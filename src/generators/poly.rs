use crate::export::{write_r1cs, OutputFormat};
use crate::r1cs::{ExportConstraint, RmsLinearExport, Term};
use rand::{rngs::StdRng, seq::SliceRandom, Rng, SeedableRng};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub const DEFAULT_SPARSE_NUM_VARS: usize = 4;
pub const DEFAULT_SPARSE_NUM_TERMS: usize = 8;
pub const DEFAULT_SPARSE_MAX_TOTAL_DEGREE: usize = 4;
pub const DEFAULT_SPARSE_MAX_SUPPORT: usize = 3;
pub const DEFAULT_BASE_SEED: u64 = 42;

pub const DEFAULT_FULL_NUM_VARS: usize = 5;
pub const DEFAULT_FULL_MIN_DEGREE: usize = 6;
pub const DEFAULT_FULL_MAX_DEGREE: usize = 10;
pub const DEFAULT_FULL_NUM_VARS_ENV: &str = "RMS_POLY_FULL_NUM_VARS";
pub const DEFAULT_FULL_MIN_DEGREE_ENV: &str = "RMS_POLY_FULL_MIN_DEGREE";
pub const DEFAULT_FULL_MAX_DEGREE_ENV: &str = "RMS_POLY_FULL_MAX_DEGREE";
pub const DEFAULT_FULL_OUT_DIR_ENV: &str = "RMS_POLY_FULL_OUT_DIR";
pub const DEFAULT_FULL_SEED_ENV: &str = "RMS_POLY_FULL_SEED";

pub const SMALL_COEFF_POOL: &[i64] = &[-3, -2, -1, 1, 2, 3];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RmsMonomial {
    pub coeff: i64,
    pub exponents: Vec<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RmsMultivariatePolynomial {
    pub num_vars: usize,
    pub terms: Vec<RmsMonomial>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolyFullBatchConfig {
    pub out_dir: PathBuf,
    pub num_vars: usize,
    pub min_degree: usize,
    pub max_degree: usize,
    pub base_seed: u64,
}

impl PolyFullBatchConfig {
    pub fn from_env(default_out_dir: &Path) -> Result<Self, String> {
        Ok(Self {
            out_dir: env_path(DEFAULT_FULL_OUT_DIR_ENV, default_out_dir)?,
            num_vars: env_usize(DEFAULT_FULL_NUM_VARS_ENV, DEFAULT_FULL_NUM_VARS)?,
            min_degree: env_usize(DEFAULT_FULL_MIN_DEGREE_ENV, DEFAULT_FULL_MIN_DEGREE)?,
            max_degree: env_usize(DEFAULT_FULL_MAX_DEGREE_ENV, DEFAULT_FULL_MAX_DEGREE)?,
            base_seed: env_u64(DEFAULT_FULL_SEED_ENV, DEFAULT_BASE_SEED)?,
        })
    }
}

pub fn sample_small_coeff<R: Rng>(rng: &mut R) -> i64 {
    let idx = rng.gen_range(0..SMALL_COEFF_POOL.len());
    SMALL_COEFF_POOL[idx]
}

#[derive(Debug, Clone, Default)]
struct WitnessLinComb {
    terms: BTreeMap<usize, i64>,
}

impl WitnessLinComb {
    fn zero() -> Self {
        Self {
            terms: BTreeMap::new(),
        }
    }

    fn from_witness(index: usize, coeff: i64) -> Self {
        let mut terms = BTreeMap::new();
        if coeff != 0 {
            terms.insert(index, coeff);
        }
        Self { terms }
    }

    fn add_term(&mut self, index: usize, coeff: i64) {
        if coeff == 0 {
            return;
        }

        let entry = self.terms.entry(index).or_insert(0);
        *entry += coeff;
        if *entry == 0 {
            self.terms.remove(&index);
        }
    }

    fn add_assign(&mut self, other: Self) {
        for (index, coeff) in other.terms {
            self.add_term(index, coeff);
        }
    }

    fn is_zero(&self) -> bool {
        self.terms.is_empty()
    }

    fn to_b_wit_terms(&self) -> Vec<Term> {
        self.terms
            .iter()
            .filter_map(|(&index, &coeff)| {
                if coeff == 0 {
                    None
                } else {
                    Some(term_from_i64(index, coeff))
                }
            })
            .collect()
    }
}

struct RmsCompiler {
    num_inputs: usize,
    constraints: Vec<ExportConstraint>,
    next_witness: usize,
}

impl RmsCompiler {
    fn new(num_vars: usize) -> Self {
        Self {
            num_inputs: num_vars + 1,
            constraints: Vec::new(),
            next_witness: 2,
        }
    }

    fn push_constraint(&mut self, a_in: Vec<Term>, b_wit: Vec<Term>) -> usize {
        let out = self.next_witness;
        let index = self.constraints.len();
        self.constraints.push(ExportConstraint {
            index,
            a_in,
            b_wit,
            output_witness: out,
        });
        self.next_witness += 1;
        out
    }

    fn one_witness(&self) -> usize {
        1
    }

    fn const_lc(&self, coeff: i64) -> WitnessLinComb {
        WitnessLinComb::from_witness(self.one_witness(), coeff)
    }

    fn mul_input_by_lc(&mut self, input_idx: usize, lc: &WitnessLinComb) -> WitnessLinComb {
        if lc.is_zero() {
            return WitnessLinComb::zero();
        }

        let out = self.push_constraint(vec![term_from_i64(input_idx, 1)], lc.to_b_wit_terms());
        WitnessLinComb::from_witness(out, 1)
    }

    fn materialize_lc(&mut self, lc: &WitnessLinComb) -> usize {
        if lc.is_zero() {
            return self.push_constraint(vec![term_from_i64(0, 0)], vec![term_from_i64(1, 1)]);
        }
        if lc.terms.len() == 1 {
            let (&index, &coeff) = lc.terms.iter().next().expect("single term");
            if coeff == 1 {
                return index;
            }
        }
        self.push_constraint(vec![term_from_i64(0, 1)], lc.to_b_wit_terms())
    }

    fn into_export(self) -> RmsLinearExport {
        let num_witnesses = self.next_witness - 1;
        let execution_order = (0..self.constraints.len()).collect();
        RmsLinearExport {
            version: "rms-linear-v1".to_string(),
            num_inputs: self.num_inputs,
            num_witnesses,
            execution_order,
            constraints: self.constraints,
        }
    }
}

fn term_from_i64(index: usize, coeff: i64) -> Term {
    Term {
        index,
        coeff: coeff.to_string(),
    }
}

fn collect_coeff_slices(
    terms: &[RmsMonomial],
    var_idx: usize,
) -> BTreeMap<usize, Vec<RmsMonomial>> {
    let mut grouped: BTreeMap<usize, Vec<RmsMonomial>> = BTreeMap::new();
    for term in terms {
        let exponent = term.exponents[var_idx];
        let mut stripped = term.clone();
        stripped.exponents[var_idx] = 0;
        grouped.entry(exponent).or_default().push(stripped);
    }
    grouped
}

fn compile_horner_recursive(
    poly: &RmsMultivariatePolynomial,
    active_terms: &[RmsMonomial],
    var_idx: usize,
    compiler: &mut RmsCompiler,
) -> WitnessLinComb {
    let active_terms: Vec<RmsMonomial> = active_terms
        .iter()
        .filter(|term| term.coeff != 0)
        .cloned()
        .collect();

    if active_terms.is_empty() {
        return WitnessLinComb::zero();
    }

    if var_idx == poly.num_vars {
        let coeff_sum: i64 = active_terms.iter().map(|term| term.coeff).sum();
        return compiler.const_lc(coeff_sum);
    }

    let grouped = collect_coeff_slices(&active_terms, var_idx);
    let max_exp = *grouped.keys().max().unwrap_or(&0);
    let highest_terms = grouped.get(&max_exp).cloned().unwrap_or_default();
    let mut acc = compile_horner_recursive(poly, &highest_terms, var_idx + 1, compiler);

    for exponent in (0..max_exp).rev() {
        acc = compiler.mul_input_by_lc(var_idx + 1, &acc);
        let coeff_terms = grouped.get(&exponent).cloned().unwrap_or_default();
        if !coeff_terms.is_empty() {
            let coeff_lc = compile_horner_recursive(poly, &coeff_terms, var_idx + 1, compiler);
            let mut merged = coeff_lc;
            merged.add_assign(acc);
            acc = merged;
        }
    }

    acc
}

pub fn compile_poly_to_rms_horner(poly: &RmsMultivariatePolynomial) -> (RmsLinearExport, usize) {
    let mut compiler = RmsCompiler::new(poly.num_vars);
    let output_lc = compile_horner_recursive(poly, &poly.terms, 0, &mut compiler);
    let output_witness = compiler.materialize_lc(&output_lc);
    (compiler.into_export(), output_witness)
}

fn random_positive_partition<R: Rng>(rng: &mut R, total: usize, parts: usize) -> Vec<usize> {
    assert!(parts >= 1);
    assert!(total >= parts);

    if parts == 1 {
        return vec![total];
    }

    let mut cuts: Vec<usize> = (1..total).collect();
    cuts.shuffle(rng);
    cuts.truncate(parts - 1);
    cuts.sort_unstable();

    let mut out = Vec::with_capacity(parts);
    let mut prev = 0usize;
    for cut in cuts {
        out.push(cut - prev);
        prev = cut;
    }
    out.push(total - prev);
    out
}

pub fn sample_sparse_multivariate_poly<R: Rng>(
    num_vars: usize,
    num_terms: usize,
    max_total_degree: usize,
    max_support: usize,
    rng: &mut R,
) -> RmsMultivariatePolynomial {
    assert!(num_vars >= 1);
    assert!(num_terms >= 1);
    assert!(max_support >= 1);

    let mut merged: BTreeMap<Vec<usize>, i64> = BTreeMap::new();

    for _ in 0..num_terms {
        let coeff = sample_small_coeff(rng);
        let total_degree = rng.gen_range(0..=max_total_degree);
        let mut exponents = vec![0usize; num_vars];

        if total_degree > 0 {
            let support = rng.gen_range(1..=max_support.min(num_vars).min(total_degree));
            let mut vars: Vec<usize> = (0..num_vars).collect();
            vars.shuffle(rng);
            vars.truncate(support);
            vars.sort_unstable();

            let pieces = random_positive_partition(rng, total_degree, support);
            for (var_idx, degree) in vars.into_iter().zip(pieces.into_iter()) {
                exponents[var_idx] = degree;
            }
        }

        *merged.entry(exponents).or_insert(0) += coeff;
    }

    let terms = merged
        .into_iter()
        .filter_map(|(exponents, coeff)| {
            if coeff == 0 {
                None
            } else {
                Some(RmsMonomial { coeff, exponents })
            }
        })
        .collect();

    RmsMultivariatePolynomial { num_vars, terms }
}

fn checked_coeff_count(num_vars: usize, max_degree: usize) -> Result<usize, String> {
    let base = max_degree.checked_add(1).ok_or_else(|| {
        format!("max_degree overflowed when computing coefficient count: {max_degree}")
    })?;

    let mut total = 1usize;
    for _ in 0..num_vars {
        total = total.checked_mul(base).ok_or_else(|| {
            format!("coefficient count overflow for num_vars={num_vars}, max_degree={max_degree}")
        })?;
    }
    Ok(total)
}

fn enumerate_dense_terms<R: Rng>(
    var_idx: usize,
    max_degree: usize,
    exponents: &mut [usize],
    terms: &mut Vec<RmsMonomial>,
    rng: &mut R,
) {
    if var_idx == exponents.len() {
        terms.push(RmsMonomial {
            coeff: sample_small_coeff(rng),
            exponents: exponents.to_vec(),
        });
        return;
    }

    for exponent in 0..=max_degree {
        exponents[var_idx] = exponent;
        enumerate_dense_terms(var_idx + 1, max_degree, exponents, terms, rng);
    }
}

pub fn sample_full_multivariate_poly<R: Rng>(
    num_vars: usize,
    max_degree: usize,
    rng: &mut R,
) -> Result<RmsMultivariatePolynomial, String> {
    if num_vars == 0 {
        return Err("num_vars must be >= 1".to_string());
    }

    let coeff_count = checked_coeff_count(num_vars, max_degree)?;
    let mut terms = Vec::with_capacity(coeff_count);
    let mut exponents = vec![0usize; num_vars];
    enumerate_dense_terms(0, max_degree, &mut exponents, &mut terms, rng);

    Ok(RmsMultivariatePolynomial { num_vars, terms })
}

pub fn generate_sparse_fixture<P: AsRef<Path>>(
    out_dir: P,
    num_vars: usize,
    num_terms: usize,
    max_total_degree: usize,
    max_support: usize,
    seed: u64,
    format: OutputFormat,
) -> Result<(), String> {
    let out_dir = out_dir.as_ref();
    fs::create_dir_all(out_dir)
        .map_err(|err| format!("failed to create output dir {}: {err}", out_dir.display()))?;

    let mut rng = StdRng::seed_from_u64(seed);
    let poly = sample_sparse_multivariate_poly(
        num_vars,
        num_terms,
        max_total_degree,
        max_support,
        &mut rng,
    );
    let (r1cs, _output_witness) = compile_poly_to_rms_horner(&poly);

    let stem = format!(
        "rms_poly_n{}_t{}_d{}",
        num_vars, num_terms, max_total_degree
    );
    let path = out_dir.join(format!("{}.{}", stem, format.extension()));
    write_r1cs(&path, &r1cs, format).map_err(|err| err.to_string())?;

    println!(
        "wrote {}",
        std::fs::canonicalize(&path)
            .unwrap_or(path.clone())
            .display()
    );

    Ok(())
}

pub fn generate_default_sparse_fixture<P: AsRef<Path>>(
    out_dir: P,
    format: OutputFormat,
) -> Result<(), String> {
    generate_sparse_fixture(
        out_dir,
        DEFAULT_SPARSE_NUM_VARS,
        DEFAULT_SPARSE_NUM_TERMS,
        DEFAULT_SPARSE_MAX_TOTAL_DEGREE,
        DEFAULT_SPARSE_MAX_SUPPORT,
        DEFAULT_BASE_SEED,
        format,
    )
}

pub fn generate_full_batch_suite(
    config: &PolyFullBatchConfig,
    format: OutputFormat,
) -> Result<(), String> {
    if config.min_degree > config.max_degree {
        return Err(format!(
            "min_degree must be <= max_degree, got {} > {}",
            config.min_degree, config.max_degree
        ));
    }

    fs::create_dir_all(&config.out_dir).map_err(|err| {
        format!(
            "failed to create output dir {}: {err}",
            config.out_dir.display()
        )
    })?;

    for degree in config.min_degree..=config.max_degree {
        let coeff_count = checked_coeff_count(config.num_vars, degree)?;
        let seed = config.base_seed.wrapping_add(degree as u64);
        let mut rng = StdRng::seed_from_u64(seed);

        let poly = sample_full_multivariate_poly(config.num_vars, degree, &mut rng)?;
        let (r1cs, _output_witness) = compile_poly_to_rms_horner(&poly);

        let filename = format!(
            "rms_poly_full_k{}_m{}.{}",
            config.num_vars,
            degree,
            format.extension()
        );
        let path = config.out_dir.join(filename);
        write_r1cs(&path, &r1cs, format).map_err(|err| err.to_string())?;

        println!(
            "wrote {} (coeffs={}, constraints={}, witnesses={})",
            std::fs::canonicalize(&path)
                .unwrap_or(path.clone())
                .display(),
            coeff_count,
            r1cs.constraints.len(),
            r1cs.num_witnesses
        );
    }

    Ok(())
}

fn env_usize(name: &str, default: usize) -> Result<usize, String> {
    match std::env::var(name) {
        Ok(raw) => raw
            .parse::<usize>()
            .map_err(|err| format!("failed to parse {name}={raw:?} as usize: {err}")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(err) => Err(format!("failed to read env var {name}: {err}")),
    }
}

fn env_u64(name: &str, default: u64) -> Result<u64, String> {
    match std::env::var(name) {
        Ok(raw) => raw
            .parse::<u64>()
            .map_err(|err| format!("failed to parse {name}={raw:?} as u64: {err}")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(err) => Err(format!("failed to read env var {name}: {err}")),
    }
}

fn env_path(name: &str, default: &Path) -> Result<PathBuf, String> {
    match std::env::var(name) {
        Ok(raw) => Ok(PathBuf::from(raw)),
        Err(std::env::VarError::NotPresent) => Ok(default.to_path_buf()),
        Err(err) => Err(format!("failed to read env var {name}: {err}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparse_poly_keeps_requested_shape() {
        let mut rng = StdRng::seed_from_u64(11);
        let poly = sample_sparse_multivariate_poly(4, 8, 5, 3, &mut rng);

        assert_eq!(poly.num_vars, 4);
        assert!(!poly.terms.is_empty());
        assert!(poly.terms.iter().all(|term| term.exponents.len() == 4));
    }

    #[test]
    fn horner_compiler_materializes_output() {
        let poly = RmsMultivariatePolynomial {
            num_vars: 2,
            terms: vec![
                RmsMonomial {
                    coeff: 3,
                    exponents: vec![1, 0],
                },
                RmsMonomial {
                    coeff: -1,
                    exponents: vec![0, 1],
                },
                RmsMonomial {
                    coeff: 2,
                    exponents: vec![0, 0],
                },
            ],
        };

        let (export, output_witness) = compile_poly_to_rms_horner(&poly);
        assert_eq!(export.version, "rms-linear-v1");
        assert!(export.num_inputs >= 3);
        assert!(output_witness >= 1);
        assert!(!export.constraints.is_empty());
    }

    #[test]
    fn full_poly_rejects_zero_variables() {
        let mut rng = StdRng::seed_from_u64(13);
        let err = sample_full_multivariate_poly(0, 3, &mut rng).expect_err("expected error");
        assert!(err.contains("num_vars"));
    }
}
