use crate::export::{
    build_rms_export_v2, print_export_constraints_preview, write_export_bundle, ExportInputConfig,
};
use crate::r1cs::{ExportConstraint, RmsLinearExport, Term};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::collections::BTreeMap;

pub const DEFAULT_NUM_VARS: usize = 5;
pub const DEFAULT_MAX_DEGREE: usize = 4;
pub const DEFAULT_SEED: u64 = 42;

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

#[derive(Clone, Debug)]
pub struct DensePolyRunConfig {
    pub num_vars: usize,
    pub max_degree: usize,
    pub seed: u64,
    pub export_stem: String,
}

impl DensePolyRunConfig {
    pub fn demo() -> Self {
        Self::new(DEFAULT_NUM_VARS, DEFAULT_MAX_DEGREE, DEFAULT_SEED)
    }

    pub fn new(num_vars: usize, max_degree: usize, seed: u64) -> Self {
        Self {
            num_vars,
            max_degree,
            seed,
            export_stem: format!("data/dense_poly_n{}_d{}_rms", num_vars, max_degree),
        }
    }
}

fn sample_small_coeff<R: Rng>(rng: &mut R) -> i64 {
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
        build_rms_export_v2(
            self.num_inputs,
            num_witnesses,
            execution_order,
            self.constraints,
            &ExportInputConfig::all_private(self.num_inputs),
        )
        .expect("dense poly v2 export should be valid")
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

pub fn run() {
    run_with_args(&[]).expect("稠密多项式示例失败");
}

pub fn run_with_args(args: &[String]) -> Result<(), String> {
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        return Err(usage_text().to_string());
    }

    let config = match args {
        [] => DensePolyRunConfig::demo(),
        [num_vars, max_degree] => DensePolyRunConfig::new(
            parse_usize_arg("num_vars", num_vars)?,
            parse_usize_arg("degree", max_degree)?,
            DEFAULT_SEED,
        ),
        _ => return Err(usage_text().to_string()),
    };

    run_with_config(config)
}

fn run_with_config(config: DensePolyRunConfig) -> Result<(), String> {
    let mut rng = StdRng::seed_from_u64(config.seed);
    let poly = sample_full_multivariate_poly(config.num_vars, config.max_degree, &mut rng)
        .map_err(|err| format!("生成稠密多项式失败: {err}"))?;
    let coeff_count = poly.terms.len();
    let (export, output_witness) = compile_poly_to_rms_horner(&poly);
    let report = write_export_bundle(&config.export_stem, &export)
        .map_err(|err| format!("导出稠密多项式 RMS 电路失败: {err}"))?;

    println!("\n╔══════════════════════════════════════════════════╗");
    println!("║  稠密多项式：Horner 编译为 RMS 线性电路          ║");
    println!("╚══════════════════════════════════════════════════╝\n");
    println!("  变量数: {}", config.num_vars);
    println!("  最大次数: {}", config.max_degree);
    println!("  系数数: {}", coeff_count);
    println!("  输出 witness: w{}", output_witness);
    println!("  约束数: {}", export.constraints.len());
    println!("  witness 数: {}", export.num_witnesses);
    println!("  JSON: {}", report.json_path);
    println!("  BIN:  {}", report.bin_path);
    println!("  版本: {}", report.version);
    println!("  JSON/BIN 内容一致: {}", report.json_bin_match);
    println!("  前 8 条 RMS 约束:");
    print_export_constraints_preview(&export, 8);

    Ok(())
}

fn parse_usize_arg(name: &str, raw: &str) -> Result<usize, String> {
    raw.parse::<usize>()
        .map_err(|err| format!("{name} 必须是非负整数，收到 {raw:?}: {err}"))
}

fn usage_text() -> &'static str {
    "\
用法:
  cargo run -- dense_poly
  cargo run -- dense_poly <num_vars> <degree>
  cargo run --example dense_poly -- <num_vars> <degree>

说明:
  默认值: num_vars=5, degree=4"
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(export.version, "rms-linear-v2");
        assert!(export.num_inputs >= 3);
        assert_eq!(export.num_public_inputs, 1);
        assert_eq!(export.public_inputs[0].index, 0);
        assert_eq!(export.public_inputs[0].value, "1");
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
