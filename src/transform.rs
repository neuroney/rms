use crate::r1cs::{Constraint, LinComb, Variable, R1CS};
use crate::utils::{lincomb_to_string, var_to_string};
use std::collections::HashMap;
use std::fmt;

const DEFAULT_MAX_BLOWUP_FACTOR: usize = 512_000;
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

#[derive(Clone)]
enum PairFrame {
    Enter {
        left: usize,
        right: usize,
    },
    FinalizeRms {
        key: (usize, usize),
        other: usize,
        src_a: LinComb,
        deps: Vec<(ark_bn254::Fr, usize)>,
    },
    FinalizeWwAfterInner {
        key: (usize, usize),
        p: usize,
        q: usize,
        other: usize,
    },
    FinalizeWwAlias {
        key: (usize, usize),
        p: usize,
        inner_result: usize,
    },
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
    let mut product_cache: HashMap<(usize, usize), usize> = HashMap::new();
    let mut depth_cache: HashMap<usize, usize> = HashMap::new();
    let input_lift_use_counts = count_input_lift_uses(input);
    let mut input_lift_cache: HashMap<String, usize> = HashMap::new();

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
    product_cache: &mut HashMap<(usize, usize), usize>,
    depth_cache: &mut HashMap<usize, usize>,
    max_constraints: usize,
) -> Result<usize, TransformError> {
    let key = canonical_pair(left, right);
    let root_key = key;
    let mut stack = vec![PairFrame::Enter { left, right }];

    while let Some(frame) = stack.pop() {
        match frame {
            PairFrame::Enter { left, right } => {
                let key = canonical_pair(left, right);
                if product_cache.contains_key(&key) {
                    continue;
                }

                if left == 1 || right == 1 {
                    product_cache.insert(key, if left == 1 { right } else { left });
                    continue;
                }

                let (expand_w, other_w) = choose_expand_side(left, right, depth_cache)?;
                let src = source_constraint(expand_w, new_constraints, new_origin)?.clone();

                if src.a.is_input_only() {
                    let deps = src
                        .b
                        .terms
                        .iter()
                        .map(|(coeff, var)| match var {
                            Variable::Witness(w_j) => Ok((*coeff, *w_j)),
                            other => panic!(
                                "RMS witness side should contain only witnesses, found {:?}",
                                other
                            ),
                        })
                        .collect::<Result<Vec<_>, TransformError>>()?;

                    let mut unresolved = Vec::new();
                    for (_, dep_w) in &deps {
                        let dep_key = canonical_pair(*dep_w, other_w);
                        if !product_cache.contains_key(&dep_key) {
                            unresolved.push((*dep_w, other_w));
                        }
                    }

                    if unresolved.is_empty() {
                        let out = materialize_rms_product(
                            key,
                            other_w,
                            src.a.clone(),
                            deps,
                            preferred_output(key, root_key, final_output, product_cache),
                            new_constraints,
                            new_origin,
                            next_w,
                            product_cache,
                            depth_cache,
                            max_constraints,
                        )?;
                        product_cache.insert(key, out);
                    } else {
                        stack.push(PairFrame::FinalizeRms {
                            key,
                            other: other_w,
                            src_a: src.a.clone(),
                            deps,
                        });
                        for (dep_left, dep_right) in unresolved.into_iter().rev() {
                            stack.push(PairFrame::Enter {
                                left: dep_left,
                                right: dep_right,
                            });
                        }
                    }
                } else {
                    let w_p = extract_witness_idx(&src.a);
                    let w_q = extract_witness_idx(&src.b);
                    let inner_key = canonical_pair(w_q, other_w);

                    if product_cache.contains_key(&inner_key) {
                        let inner_result = product_cache[&inner_key];
                        let outer_key = canonical_pair(w_p, inner_result);

                        if let Some(&outer_result) = product_cache.get(&outer_key) {
                            product_cache.insert(key, outer_result);
                        } else {
                            stack.push(PairFrame::FinalizeWwAlias {
                                key,
                                p: w_p,
                                inner_result,
                            });
                            stack.push(PairFrame::Enter {
                                left: w_p,
                                right: inner_result,
                            });
                        }
                    } else {
                        stack.push(PairFrame::FinalizeWwAfterInner {
                            key,
                            p: w_p,
                            q: w_q,
                            other: other_w,
                        });
                        stack.push(PairFrame::Enter {
                            left: w_q,
                            right: other_w,
                        });
                    }
                }
            }
            PairFrame::FinalizeRms {
                key,
                other,
                src_a,
                deps,
            } => {
                if product_cache.contains_key(&key) {
                    continue;
                }

                let out = materialize_rms_product(
                    key,
                    other,
                    src_a,
                    deps,
                    preferred_output(key, root_key, final_output, product_cache),
                    new_constraints,
                    new_origin,
                    next_w,
                    product_cache,
                    depth_cache,
                    max_constraints,
                )?;
                product_cache.insert(key, out);
            }
            PairFrame::FinalizeWwAfterInner { key, p, q, other } => {
                if product_cache.contains_key(&key) {
                    continue;
                }

                let inner_key = canonical_pair(q, other);
                let inner_result = *product_cache
                    .get(&inner_key)
                    .ok_or(TransformError::MissingWitnessOrigin { witness: q })?;
                let outer_key = canonical_pair(p, inner_result);

                if let Some(&outer_result) = product_cache.get(&outer_key) {
                    product_cache.insert(key, outer_result);
                } else {
                    stack.push(PairFrame::FinalizeWwAlias {
                        key,
                        p,
                        inner_result,
                    });
                    stack.push(PairFrame::Enter {
                        left: p,
                        right: inner_result,
                    });
                }
            }
            PairFrame::FinalizeWwAlias {
                key,
                p,
                inner_result,
            } => {
                if product_cache.contains_key(&key) {
                    continue;
                }

                let outer_key = canonical_pair(p, inner_result);
                let outer_result = *product_cache
                    .get(&outer_key)
                    .ok_or(TransformError::MissingWitnessOrigin { witness: p })?;
                product_cache.insert(key, outer_result);
            }
        }
    }

    let result = *product_cache
        .get(&key)
        .ok_or(TransformError::MissingWitnessOrigin { witness: left })?;

    if let Some(out) = final_output {
        if out != result {
            push_constraint(
                Constraint {
                    a: LinComb::from_var(Variable::Input(0)),
                    b: LinComb::from_var(Variable::Witness(result)),
                    c: LinComb::from_var(Variable::Witness(out)),
                },
                out,
                new_constraints,
                new_origin,
                depth_cache,
                max_constraints,
            )?;
        }
        Ok(out)
    } else {
        Ok(result)
    }
}

fn materialize_rms_product(
    key: (usize, usize),
    other: usize,
    src_a: LinComb,
    deps: Vec<(ark_bn254::Fr, usize)>,
    preferred_output: Option<usize>,
    new_constraints: &mut Vec<Constraint>,
    new_origin: &mut HashMap<usize, usize>,
    next_w: &mut usize,
    product_cache: &HashMap<(usize, usize), usize>,
    depth_cache: &mut HashMap<usize, usize>,
    max_constraints: usize,
) -> Result<usize, TransformError> {
    let inner_terms = deps
        .into_iter()
        .map(|(coeff, dep_w)| {
            let inner_key = canonical_pair(dep_w, other);
            let inner_w = *product_cache
                .get(&inner_key)
                .ok_or(TransformError::MissingWitnessOrigin { witness: dep_w })?;
            Ok((coeff, Variable::Witness(inner_w)))
        })
        .collect::<Result<Vec<_>, TransformError>>()?;

    let out = preferred_output.unwrap_or_else(|| allocate_helper_witness(next_w));
    push_constraint(
        Constraint {
            a: src_a,
            b: LinComb::from_terms(inner_terms),
            c: LinComb::from_var(Variable::Witness(out)),
        },
        out,
        new_constraints,
        new_origin,
        depth_cache,
        max_constraints,
    )?;
    let _ = key;
    Ok(out)
}

fn preferred_output(
    key: (usize, usize),
    root_key: (usize, usize),
    final_output: Option<usize>,
    product_cache: &HashMap<(usize, usize), usize>,
) -> Option<usize> {
    if key == root_key && !product_cache.contains_key(&key) {
        final_output
    } else {
        None
    }
}

fn lower_input_input_constraint(
    constraint: &Constraint,
    new_constraints: &mut Vec<Constraint>,
    new_origin: &mut HashMap<usize, usize>,
    next_w: &mut usize,
    input_lift_cache: &mut HashMap<String, usize>,
    input_lift_use_counts: &HashMap<String, usize>,
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
    new_origin.insert(output_witness, idx);
    new_constraints.push(constraint);
    depth_cache.insert(output_witness, depth);
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

fn normalize_lincomb(lc: &LinComb, redirect: &HashMap<String, Variable>) -> LinComb {
    LinComb {
        terms: lc
            .terms
            .iter()
            .map(|(coeff, var)| {
                let key = var_to_string(var);
                let new_var = redirect.get(&key).cloned().unwrap_or_else(|| var.clone());
                (*coeff, new_var)
            })
            .collect(),
    }
}

fn normalize_constraint(c: &Constraint, redirect: &HashMap<String, Variable>) -> Constraint {
    Constraint {
        a: normalize_lincomb(&c.a, redirect),
        b: normalize_lincomb(&c.b, redirect),
        c: normalize_lincomb(&c.c, redirect),
    }
}

fn extract_single_var(lc: &LinComb) -> Option<Variable> {
    if lc.terms.len() == 1 {
        Some(lc.terms[0].1.clone())
    } else {
        None
    }
}

pub fn eliminate_common_subexpressions(r1cs: &R1CS) -> (R1CS, usize) {
    let mut seen: HashMap<String, Variable> = HashMap::new();
    let mut redirect: HashMap<String, Variable> = HashMap::new();
    let mut new_constraints: Vec<Constraint> = Vec::new();
    let mut new_origin: HashMap<usize, usize> = HashMap::new();

    for constraint in &r1cs.constraints {
        let normalized = normalize_constraint(constraint, &redirect);
        let key = constraint_key(&normalized);

        if let Some(existing_out) = seen.get(&key) {
            if let Some(out) = extract_single_var(&normalized.c) {
                redirect.insert(var_to_string(&out), existing_out.clone());
            }
        } else {
            if let Some(out) = extract_single_var(&normalized.c) {
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
}
