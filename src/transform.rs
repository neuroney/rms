use crate::r1cs::{Constraint, LinComb, Variable, R1CS};
use crate::utils::{lincomb_to_string, var_to_string};
use ark_bn254::Fr;
use ark_ff::{One, Zero};
use std::collections::{BTreeMap, HashMap};
use std::fmt;

const DEFAULT_MAX_BLOWUP_FACTOR: usize = 512_000_000_000;
const DEFAULT_MAX_TRANSFORMED_CONSTRAINTS: usize = 1_000_000_000_000;

#[derive(Clone, Debug)]
pub struct TransformResult {
    pub r1cs: R1CS,
    pub transformed_constraints: usize,
    pub blowup_factor: f64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransformError {
    ConstraintLimitExceeded { limit: usize, produced: usize },
    MissingWitnessOrigin { witness: usize },
}

impl fmt::Display for TransformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransformError::ConstraintLimitExceeded { limit, produced } => write!(
                f,
                "Choudhuri transform aborted after producing {} constraints; configured limit is {}",
                produced, limit
            ),
            TransformError::MissingWitnessOrigin { witness } => {
                write!(f, "witness w{} has no defining constraint", witness)
            }
        }
    }
}

impl std::error::Error for TransformError {}

#[derive(Clone, Debug)]
struct ScaledWitness {
    coeff: Fr,
    witness: usize,
}

impl ScaledWitness {
    fn identity(witness: usize) -> Self {
        Self {
            coeff: Fr::one(),
            witness,
        }
    }
}

#[derive(Clone, Debug)]
struct ScaledVariable {
    coeff: Fr,
    variable: Variable,
}

pub fn choudhuri_transform(input: &R1CS) -> TransformResult {
    try_choudhuri_transform(input)
        .unwrap_or_else(|err| panic!("Choudhuri transform failed: {}", err))
}

pub fn try_choudhuri_transform(input: &R1CS) -> Result<TransformResult, TransformError> {
    let max_constraints = default_constraint_limit(input.constraints.len());
    try_choudhuri_transform_with_limit(input, max_constraints)
}

pub fn try_choudhuri_transform_with_limit(
    input: &R1CS,
    max_constraints: usize,
) -> Result<TransformResult, TransformError> {
    let original_constraints = input.constraints.len();
    let mut new_constraints: Vec<Constraint> = Vec::new();
    let mut new_origin: HashMap<usize, usize> = HashMap::new();
    let mut next_w = input.num_witnesses + 1;
    let mut product_cache: HashMap<(usize, usize), ScaledWitness> = HashMap::new();
    let mut depth_cache: HashMap<usize, usize> = HashMap::new();
    let input_lift_use_counts = count_input_lift_uses(input);
    let mut input_lift_cache: HashMap<String, usize> = HashMap::new();
    let mut witness_aliases: HashMap<usize, ScaledWitness> = HashMap::new();

    depth_cache.insert(1, 0);

    for constraint in &input.constraints {
        if constraint.is_input_input() {
            lower_input_input_constraint(
                constraint,
                &mut new_constraints,
                &mut new_origin,
                &mut next_w,
                &mut input_lift_cache,
                &input_lift_use_counts,
                &mut witness_aliases,
                &mut depth_cache,
                max_constraints,
            )?;
        } else if !constraint.is_witness_witness() {
            let out_w = extract_witness_idx(&constraint.c);
            push_constraint(
                constraint.clone(),
                out_w,
                &mut new_constraints,
                &mut new_origin,
                &mut witness_aliases,
                &mut depth_cache,
                max_constraints,
            )?;
        } else {
            let w_a = extract_witness_idx(&constraint.a);
            let w_b = extract_witness_idx(&constraint.b);
            let w_c = extract_witness_idx(&constraint.c);

            ensure_product(
                w_a,
                w_b,
                Some(w_c),
                &mut new_constraints,
                &mut new_origin,
                &mut next_w,
                &mut product_cache,
                &mut witness_aliases,
                &mut depth_cache,
                max_constraints,
            )?;
        }
    }

    let transformed_constraints = new_constraints.len();
    let blowup_factor = if original_constraints == 0 {
        1.0
    } else {
        transformed_constraints as f64 / original_constraints as f64
    };

    Ok(TransformResult {
        r1cs: R1CS {
            num_inputs: input.num_inputs,
            num_witnesses: next_w - 1,
            constraints: new_constraints,
            origin: new_origin,
        },
        transformed_constraints,
        blowup_factor,
    })
}

fn ensure_product(
    left: usize,
    right: usize,
    final_output: Option<usize>,
    new_constraints: &mut Vec<Constraint>,
    new_origin: &mut HashMap<usize, usize>,
    next_w: &mut usize,
    product_cache: &mut HashMap<(usize, usize), ScaledWitness>,
    witness_aliases: &mut HashMap<usize, ScaledWitness>,
    depth_cache: &mut HashMap<usize, usize>,
    max_constraints: usize,
) -> Result<usize, TransformError> {
    let left = resolve_scaled_witness(ScaledWitness::identity(left), witness_aliases);
    let right = resolve_scaled_witness(ScaledWitness::identity(right), witness_aliases);
    let preferred_output = if left.coeff == Fr::one() && right.coeff == Fr::one() {
        final_output
    } else {
        None
    };
    let result = ensure_scaled_product(
        left,
        right,
        preferred_output,
        new_constraints,
        new_origin,
        next_w,
        product_cache,
        witness_aliases,
        depth_cache,
        max_constraints,
    )?;

    if let Some(out) = final_output {
        if out != result.witness || result.coeff != Fr::one() {
            materialize_scaled_alias(
                out,
                &result,
                new_constraints,
                new_origin,
                witness_aliases,
                depth_cache,
                max_constraints,
            )?;
        }
        Ok(out)
    } else {
        Ok(result.witness)
    }
}

fn ensure_scaled_product(
    left: ScaledWitness,
    right: ScaledWitness,
    preferred_output: Option<usize>,
    new_constraints: &mut Vec<Constraint>,
    new_origin: &mut HashMap<usize, usize>,
    next_w: &mut usize,
    product_cache: &mut HashMap<(usize, usize), ScaledWitness>,
    witness_aliases: &mut HashMap<usize, ScaledWitness>,
    depth_cache: &mut HashMap<usize, usize>,
    max_constraints: usize,
) -> Result<ScaledWitness, TransformError> {
    let left = resolve_scaled_witness(left, witness_aliases);
    let right = resolve_scaled_witness(right, witness_aliases);
    let external_scale = left.coeff * right.coeff;

    if left.witness == 1 {
        return Ok(ScaledWitness {
            coeff: external_scale,
            witness: right.witness,
        });
    }

    if right.witness == 1 {
        return Ok(ScaledWitness {
            coeff: external_scale,
            witness: left.witness,
        });
    }

    let key = canonical_pair(left.witness, right.witness);
    if let Some(cached) = product_cache.get(&key) {
        return Ok(ScaledWitness {
            coeff: external_scale * cached.coeff,
            witness: cached.witness,
        });
    }

    let (expand_w, other_w) = choose_expand_side(key.0, key.1, depth_cache)?;
    let src = source_constraint(expand_w, new_constraints, new_origin)?.clone();

    let cached = if src.a.is_input_only() {
        let mut grouped_terms: BTreeMap<usize, Fr> = BTreeMap::new();
        for (coeff, var) in &src.b.terms {
            let dep_w = match var {
                Variable::Witness(w_j) => *w_j,
                other => panic!(
                    "RMS witness side should contain only witnesses, found {:?}",
                    other
                ),
            };
            let inner = ensure_scaled_product(
                resolve_scaled_witness(ScaledWitness::identity(dep_w), witness_aliases),
                ScaledWitness::identity(other_w),
                None,
                new_constraints,
                new_origin,
                next_w,
                product_cache,
                witness_aliases,
                depth_cache,
                max_constraints,
            )?;
            let merged_coeff = *coeff * inner.coeff;
            if merged_coeff.is_zero() {
                continue;
            }
            let entry = grouped_terms.entry(inner.witness).or_insert_with(Fr::zero);
            *entry += merged_coeff;
            if entry.is_zero() {
                grouped_terms.remove(&inner.witness);
            }
        }

        let inner_terms = grouped_terms
            .into_iter()
            .filter_map(|(witness, coeff)| {
                if coeff.is_zero() {
                    None
                } else {
                    Some((coeff, Variable::Witness(witness)))
                }
            })
            .collect::<Vec<_>>();

        let out = preferred_output.unwrap_or_else(|| allocate_helper_witness(next_w));
        push_constraint(
            Constraint {
                a: src.a,
                b: LinComb::from_terms(inner_terms),
                c: LinComb::from_var(Variable::Witness(out)),
            },
            out,
            new_constraints,
            new_origin,
            witness_aliases,
            depth_cache,
            max_constraints,
        )?;
        ScaledWitness::identity(out)
    } else {
        let left_factor = resolve_scaled_witness(
            ScaledWitness::identity(extract_witness_idx(&src.a)),
            witness_aliases,
        );
        let right_factor = resolve_scaled_witness(
            ScaledWitness::identity(extract_witness_idx(&src.b)),
            witness_aliases,
        );
        let inner = ensure_scaled_product(
            right_factor,
            ScaledWitness::identity(other_w),
            None,
            new_constraints,
            new_origin,
            next_w,
            product_cache,
            witness_aliases,
            depth_cache,
            max_constraints,
        )?;
        let outer = ensure_scaled_product(
            left_factor,
            inner,
            None,
            new_constraints,
            new_origin,
            next_w,
            product_cache,
            witness_aliases,
            depth_cache,
            max_constraints,
        )?;

        if let Some(out) = preferred_output {
            materialize_scaled_alias(
                out,
                &outer,
                new_constraints,
                new_origin,
                witness_aliases,
                depth_cache,
                max_constraints,
            )?;
            ScaledWitness::identity(out)
        } else {
            outer
        }
    };

    product_cache.insert(key, cached.clone());
    Ok(ScaledWitness {
        coeff: external_scale * cached.coeff,
        witness: cached.witness,
    })
}

fn materialize_scaled_alias(
    output: usize,
    source: &ScaledWitness,
    new_constraints: &mut Vec<Constraint>,
    new_origin: &mut HashMap<usize, usize>,
    witness_aliases: &mut HashMap<usize, ScaledWitness>,
    depth_cache: &mut HashMap<usize, usize>,
    max_constraints: usize,
) -> Result<(), TransformError> {
    if output == source.witness && source.coeff == Fr::one() {
        return Ok(());
    }

    push_constraint(
        Constraint {
            a: LinComb::from_var(Variable::Input(0)),
            b: LinComb::from_terms(vec![(source.coeff, Variable::Witness(source.witness))]),
            c: LinComb::from_var(Variable::Witness(output)),
        },
        output,
        new_constraints,
        new_origin,
        witness_aliases,
        depth_cache,
        max_constraints,
    )
}

fn lower_input_input_constraint(
    constraint: &Constraint,
    new_constraints: &mut Vec<Constraint>,
    new_origin: &mut HashMap<usize, usize>,
    next_w: &mut usize,
    input_lift_cache: &mut HashMap<String, usize>,
    input_lift_use_counts: &HashMap<String, usize>,
    witness_aliases: &mut HashMap<usize, ScaledWitness>,
    depth_cache: &mut HashMap<usize, usize>,
    max_constraints: usize,
) -> Result<(), TransformError> {
    let a_key = lincomb_to_string(&constraint.a);
    let b_key = lincomb_to_string(&constraint.b);

    let should_lift_a = prefer_left_lift(
        constraint,
        &a_key,
        &b_key,
        input_lift_cache,
        input_lift_use_counts,
    );

    let (lift_lc, lift_key, rhs_lc) = if should_lift_a {
        (&constraint.a, a_key, &constraint.b)
    } else {
        (&constraint.b, b_key, &constraint.a)
    };

    let w_tmp = if let Some(&cached) = input_lift_cache.get(&lift_key) {
        cached
    } else {
        let w_tmp = allocate_helper_witness(next_w);
        push_constraint(
            Constraint {
                a: lift_lc.clone(),
                b: LinComb::from_var(Variable::Witness(1)),
                c: LinComb::from_var(Variable::Witness(w_tmp)),
            },
            w_tmp,
            new_constraints,
            new_origin,
            witness_aliases,
            depth_cache,
            max_constraints,
        )?;
        input_lift_cache.insert(lift_key, w_tmp);
        w_tmp
    };

    let out_w = extract_witness_idx(&constraint.c);
    push_constraint(
        Constraint {
            a: rhs_lc.clone(),
            b: LinComb::from_var(Variable::Witness(w_tmp)),
            c: LinComb::from_var(Variable::Witness(out_w)),
        },
        out_w,
        new_constraints,
        new_origin,
        witness_aliases,
        depth_cache,
        max_constraints,
    )
}

fn count_input_lift_uses(r1cs: &R1CS) -> HashMap<String, usize> {
    let mut counts = HashMap::new();

    for constraint in &r1cs.constraints {
        if constraint.is_input_input() {
            *counts.entry(lincomb_to_string(&constraint.a)).or_insert(0) += 1;
            *counts.entry(lincomb_to_string(&constraint.b)).or_insert(0) += 1;
        }
    }

    counts
}

fn prefer_left_lift(
    constraint: &Constraint,
    a_key: &str,
    b_key: &str,
    input_lift_cache: &HashMap<String, usize>,
    input_lift_use_counts: &HashMap<String, usize>,
) -> bool {
    let a_cached = input_lift_cache.contains_key(a_key);
    let b_cached = input_lift_cache.contains_key(b_key);

    match (a_cached, b_cached) {
        (true, false) => return true,
        (false, true) => return false,
        _ => {}
    }

    let a_uses = input_lift_use_counts.get(a_key).copied().unwrap_or(0);
    let b_uses = input_lift_use_counts.get(b_key).copied().unwrap_or(0);

    if a_uses != b_uses {
        return a_uses >= b_uses;
    }

    if constraint.a.terms.len() != constraint.b.terms.len() {
        return constraint.a.terms.len() <= constraint.b.terms.len();
    }

    true
}

fn push_constraint(
    constraint: Constraint,
    output_witness: usize,
    new_constraints: &mut Vec<Constraint>,
    new_origin: &mut HashMap<usize, usize>,
    witness_aliases: &mut HashMap<usize, ScaledWitness>,
    depth_cache: &mut HashMap<usize, usize>,
    max_constraints: usize,
) -> Result<(), TransformError> {
    if new_constraints.len() >= max_constraints {
        return Err(TransformError::ConstraintLimitExceeded {
            limit: max_constraints,
            produced: new_constraints.len(),
        });
    }

    let idx = new_constraints.len();
    let depth = constraint_depth(&constraint, depth_cache)?;
    let scalar_alias = extract_scalar_witness_alias(&constraint, witness_aliases);
    new_origin.insert(output_witness, idx);
    new_constraints.push(constraint);
    depth_cache.insert(output_witness, depth);
    if let Some(alias) = scalar_alias {
        witness_aliases.insert(output_witness, alias);
    }
    Ok(())
}

fn constraint_depth(
    constraint: &Constraint,
    depth_cache: &HashMap<usize, usize>,
) -> Result<usize, TransformError> {
    let left = lincomb_depth(&constraint.a, depth_cache)?;
    let right = lincomb_depth(&constraint.b, depth_cache)?;
    Ok(left.max(right) + 1)
}

fn lincomb_depth(
    lincomb: &LinComb,
    depth_cache: &HashMap<usize, usize>,
) -> Result<usize, TransformError> {
    let mut max_depth = 0;

    for (_, var) in &lincomb.terms {
        if let Variable::Witness(witness) = var {
            let depth = if *witness == 1 {
                0
            } else {
                *depth_cache
                    .get(witness)
                    .ok_or(TransformError::MissingWitnessOrigin { witness: *witness })?
            };
            max_depth = max_depth.max(depth);
        }
    }

    Ok(max_depth)
}

fn choose_expand_side(
    left: usize,
    right: usize,
    depth_cache: &HashMap<usize, usize>,
) -> Result<(usize, usize), TransformError> {
    let left_depth = witness_depth(left, depth_cache)?;
    let right_depth = witness_depth(right, depth_cache)?;
    Ok(if left_depth <= right_depth {
        (left, right)
    } else {
        (right, left)
    })
}

fn witness_depth(
    witness: usize,
    depth_cache: &HashMap<usize, usize>,
) -> Result<usize, TransformError> {
    if witness == 1 {
        return Ok(0);
    }

    depth_cache
        .get(&witness)
        .copied()
        .ok_or(TransformError::MissingWitnessOrigin { witness })
}

fn source_constraint<'a>(
    witness: usize,
    constraints: &'a [Constraint],
    origin: &HashMap<usize, usize>,
) -> Result<&'a Constraint, TransformError> {
    let idx = origin
        .get(&witness)
        .copied()
        .ok_or(TransformError::MissingWitnessOrigin { witness })?;
    Ok(&constraints[idx])
}

fn canonical_pair(left: usize, right: usize) -> (usize, usize) {
    (left.min(right), left.max(right))
}

fn resolve_witness_alias(
    witness: usize,
    witness_aliases: &HashMap<usize, ScaledWitness>,
) -> ScaledWitness {
    let mut coeff = Fr::one();
    let mut current = witness;

    while let Some(alias) = witness_aliases.get(&current) {
        coeff *= alias.coeff;
        current = alias.witness;
    }

    ScaledWitness {
        coeff,
        witness: current,
    }
}

fn resolve_scaled_witness(
    scaled: ScaledWitness,
    witness_aliases: &HashMap<usize, ScaledWitness>,
) -> ScaledWitness {
    let resolved = resolve_witness_alias(scaled.witness, witness_aliases);
    ScaledWitness {
        coeff: scaled.coeff * resolved.coeff,
        witness: resolved.witness,
    }
}

fn constant_input_scale(lc: &LinComb) -> Option<Fr> {
    let mut coeff = Fr::zero();
    for (term_coeff, var) in &lc.terms {
        match var {
            Variable::Input(0) => coeff += term_coeff,
            _ => return None,
        }
    }
    Some(coeff)
}

fn extract_scalar_witness_alias(
    constraint: &Constraint,
    witness_aliases: &HashMap<usize, ScaledWitness>,
) -> Option<ScaledWitness> {
    let scale = constant_input_scale(&constraint.a)?;
    let (wit_coeff, witness) = match constraint.b.terms.as_slice() {
        [(coeff, Variable::Witness(witness))] => (*coeff, *witness),
        _ => return None,
    };
    let resolved = resolve_witness_alias(witness, witness_aliases);
    let merged_coeff = scale * wit_coeff * resolved.coeff;
    if merged_coeff.is_zero() {
        return None;
    }
    Some(ScaledWitness {
        coeff: merged_coeff,
        witness: resolved.witness,
    })
}

fn allocate_helper_witness(next_w: &mut usize) -> usize {
    let witness = *next_w;
    *next_w += 1;
    witness
}

fn default_constraint_limit(original_constraints: usize) -> usize {
    let scaled = original_constraints
        .saturating_mul(DEFAULT_MAX_BLOWUP_FACTOR)
        .max(original_constraints.saturating_add(1));
    scaled.min(DEFAULT_MAX_TRANSFORMED_CONSTRAINTS)
}

fn constraint_key(c: &Constraint) -> String {
    format!("{}|{}", lincomb_to_string(&c.a), lincomb_to_string(&c.b))
}

fn resolve_variable_alias(
    variable: &Variable,
    coeff: Fr,
    redirect: &HashMap<String, ScaledVariable>,
) -> ScaledVariable {
    let mut resolved_coeff = coeff;
    let mut resolved_var = variable.clone();

    while let Some(next) = redirect.get(&var_to_string(&resolved_var)) {
        resolved_coeff *= next.coeff;
        resolved_var = next.variable.clone();
    }

    ScaledVariable {
        coeff: resolved_coeff,
        variable: resolved_var,
    }
}

fn normalize_lincomb(lc: &LinComb, redirect: &HashMap<String, ScaledVariable>) -> LinComb {
    let mut grouped: BTreeMap<String, (Fr, Variable)> = BTreeMap::new();

    for (coeff, var) in &lc.terms {
        let resolved = resolve_variable_alias(var, *coeff, redirect);
        if resolved.coeff.is_zero() {
            continue;
        }
        let key = var_to_string(&resolved.variable);
        let entry = grouped
            .entry(key)
            .or_insert_with(|| (Fr::zero(), resolved.variable.clone()));
        entry.0 += resolved.coeff;
        if entry.0.is_zero() {
            grouped.remove(&var_to_string(&resolved.variable));
        }
    }

    LinComb {
        terms: grouped
            .into_values()
            .filter_map(|(coeff, variable)| {
                if coeff.is_zero() {
                    None
                } else {
                    Some((coeff, variable))
                }
            })
            .collect(),
    }
}

fn normalize_constraint(c: &Constraint, redirect: &HashMap<String, ScaledVariable>) -> Constraint {
    Constraint {
        a: normalize_lincomb(&c.a, redirect),
        b: normalize_lincomb(&c.b, redirect),
        c: normalize_lincomb(&c.c, redirect),
    }
}

fn extract_output_var(lc: &LinComb) -> Option<Variable> {
    match lc.terms.as_slice() {
        [(coeff, var)] if *coeff == Fr::one() => Some(var.clone()),
        _ => None,
    }
}

fn extract_scalar_alias_target(constraint: &Constraint) -> Option<ScaledVariable> {
    let scale = constant_input_scale(&constraint.a)?;
    let (wit_coeff, witness) = match constraint.b.terms.as_slice() {
        [(coeff, Variable::Witness(witness))] => (*coeff, *witness),
        _ => return None,
    };
    let merged_coeff = scale * wit_coeff;
    if merged_coeff.is_zero() {
        return None;
    }
    Some(ScaledVariable {
        coeff: merged_coeff,
        variable: Variable::Witness(witness),
    })
}

pub fn eliminate_common_subexpressions(r1cs: &R1CS) -> (R1CS, usize) {
    let mut seen: HashMap<String, Variable> = HashMap::new();
    let mut redirect: HashMap<String, ScaledVariable> = HashMap::new();
    let mut new_constraints: Vec<Constraint> = Vec::new();
    let mut new_origin: HashMap<usize, usize> = HashMap::new();

    for constraint in &r1cs.constraints {
        let normalized = normalize_constraint(constraint, &redirect);
        if let Some(target) = extract_scalar_alias_target(&normalized) {
            if let Some(out) = extract_output_var(&normalized.c) {
                redirect.insert(var_to_string(&out), target);
            }
            continue;
        }
        let key = constraint_key(&normalized);

        if let Some(existing_out) = seen.get(&key) {
            if let Some(out) = extract_output_var(&normalized.c) {
                redirect.insert(
                    var_to_string(&out),
                    ScaledVariable {
                        coeff: Fr::one(),
                        variable: existing_out.clone(),
                    },
                );
            }
        } else {
            if let Some(out) = extract_output_var(&normalized.c) {
                seen.insert(key, out.clone());
                if let Variable::Witness(i) = out {
                    new_origin.insert(i, new_constraints.len());
                }
            }
            new_constraints.push(normalized);
        }
    }

    let eliminated = r1cs.constraints.len() - new_constraints.len();
    (
        R1CS {
            num_inputs: r1cs.num_inputs,
            num_witnesses: r1cs.num_witnesses,
            constraints: new_constraints,
            origin: new_origin,
        },
        eliminated,
    )
}

fn extract_witness_idx(lc: &LinComb) -> usize {
    assert_eq!(lc.terms.len(), 1);
    match &lc.terms[0].1 {
        Variable::Witness(i) => *i,
        other => panic!("Expect Witness, obtain {:?}", other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::One;

    #[test]
    fn transform_limit_fails_fast_with_clear_error() {
        let mut r1cs = R1CS::new(2, 3);
        r1cs.add_constraint(
            Constraint {
                a: LinComb::from_var(Variable::Input(1)),
                b: LinComb::from_var(Variable::Witness(1)),
                c: LinComb::from_var(Variable::Witness(2)),
            },
            2,
        );
        r1cs.add_constraint(
            Constraint {
                a: LinComb::from_var(Variable::Witness(2)),
                b: LinComb::from_var(Variable::Witness(2)),
                c: LinComb::from_var(Variable::Witness(3)),
            },
            3,
        );

        let error = try_choudhuri_transform_with_limit(&r1cs, 1).unwrap_err();
        assert!(matches!(
            error,
            TransformError::ConstraintLimitExceeded {
                limit: 1,
                produced: 1
            }
        ));
    }

    #[test]
    fn eliminate_common_subexpressions_folds_scalar_aliases() {
        let mut r1cs = R1CS::new(2, 3);
        r1cs.add_constraint(
            Constraint {
                a: LinComb::from_var(Variable::Input(0)),
                b: LinComb::from_terms(vec![(Fr::from(5u64), Variable::Witness(1))]),
                c: LinComb::from_var(Variable::Witness(2)),
            },
            2,
        );
        r1cs.add_constraint(
            Constraint {
                a: LinComb::from_var(Variable::Input(1)),
                b: LinComb::from_var(Variable::Witness(2)),
                c: LinComb::from_var(Variable::Witness(3)),
            },
            3,
        );

        let (optimized, eliminated) = eliminate_common_subexpressions(&r1cs);
        assert_eq!(eliminated, 1);
        assert_eq!(optimized.constraints.len(), 1);
        assert_eq!(optimized.constraints[0].a.terms.len(), 1);
        assert_eq!(optimized.constraints[0].b.terms.len(), 1);
        assert_eq!(optimized.constraints[0].b.terms[0].0, Fr::from(5u64));
        assert_eq!(optimized.constraints[0].b.terms[0].1, Variable::Witness(1));
    }

    #[test]
    fn scaled_aliases_hit_product_cache() {
        let mut new_constraints = Vec::new();
        let mut new_origin = HashMap::new();
        let mut next_w = 4usize;
        let mut product_cache = HashMap::new();
        let mut witness_aliases = HashMap::new();
        let mut depth_cache = HashMap::new();
        depth_cache.insert(1, 0);

        push_constraint(
            Constraint {
                a: LinComb::from_var(Variable::Input(1)),
                b: LinComb::from_var(Variable::Witness(1)),
                c: LinComb::from_var(Variable::Witness(2)),
            },
            2,
            &mut new_constraints,
            &mut new_origin,
            &mut witness_aliases,
            &mut depth_cache,
            128,
        )
        .expect("seed RMS constraint");

        push_constraint(
            Constraint {
                a: LinComb::from_var(Variable::Input(0)),
                b: LinComb::from_terms(vec![(-Fr::one(), Variable::Witness(2))]),
                c: LinComb::from_var(Variable::Witness(3)),
            },
            3,
            &mut new_constraints,
            &mut new_origin,
            &mut witness_aliases,
            &mut depth_cache,
            128,
        )
        .expect("seed scalar alias");

        let neg_square = ensure_scaled_product(
            resolve_scaled_witness(ScaledWitness::identity(3), &witness_aliases),
            ScaledWitness::identity(2),
            None,
            &mut new_constraints,
            &mut new_origin,
            &mut next_w,
            &mut product_cache,
            &mut witness_aliases,
            &mut depth_cache,
            128,
        )
        .expect("build aliased product");
        assert_eq!(product_cache.len(), 1);

        let square = ensure_scaled_product(
            ScaledWitness::identity(2),
            ScaledWitness::identity(2),
            None,
            &mut new_constraints,
            &mut new_origin,
            &mut next_w,
            &mut product_cache,
            &mut witness_aliases,
            &mut depth_cache,
            128,
        )
        .expect("reuse cached base product");

        assert_eq!(product_cache.len(), 1);
        assert_eq!(neg_square.witness, square.witness);
        assert_eq!(neg_square.coeff, -Fr::one());
        assert_eq!(square.coeff, Fr::one());
    }
}
