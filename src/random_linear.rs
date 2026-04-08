use crate::export::{
    build_rms_export, print_export_constraints_preview, split_export_cli_args,
    write_export_bundle_with_options, ExportBundleOptions, ExportInputConfig,
};
use crate::r1cs::{ExportConstraint, RmsLinearExport, Term};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::collections::BTreeSet;

pub const DEFAULT_NUM_INPUTS: usize = 5;
pub const DEFAULT_NUM_CONSTRAINTS: usize = 64;
pub const DEFAULT_SEED: u64 = 42;

const COEFF_POOL: &[i64] = &[-3, -2, -1, 1, 2, 3];

#[derive(Clone, Debug)]
pub struct RandomLinearRunConfig {
    pub num_inputs: usize,
    pub num_constraints: usize,
    pub seed: u64,
    pub export_stem: String,
}

impl RandomLinearRunConfig {
    pub fn demo() -> Self {
        Self::new(DEFAULT_NUM_INPUTS, DEFAULT_NUM_CONSTRAINTS, DEFAULT_SEED)
    }

    pub fn new(num_inputs: usize, num_constraints: usize, seed: u64) -> Self {
        Self {
            num_inputs,
            num_constraints,
            seed,
            export_stem: format!("data/random_linear_n{}_d{}", num_inputs, num_constraints),
        }
    }
}

fn sample_coeff<R: Rng>(rng: &mut R) -> i64 {
    let idx = rng.gen_range(0..COEFF_POOL.len());
    COEFF_POOL[idx]
}

fn sample_unique_indices<R: Rng>(rng: &mut R, upper_exclusive: usize, k: usize) -> Vec<usize> {
    assert!(upper_exclusive >= 1);
    assert!(k >= 1);

    let want = k.min(upper_exclusive);
    let mut picked = BTreeSet::new();
    while picked.len() < want {
        picked.insert(rng.gen_range(0..upper_exclusive));
    }
    picked.into_iter().collect()
}

fn sample_unique_witness_indices<R: Rng>(
    rng: &mut R,
    max_existing_witness: usize,
    k: usize,
) -> Vec<usize> {
    assert!(max_existing_witness >= 1);
    assert!(k >= 1);

    let want = k.min(max_existing_witness);
    let mut picked = BTreeSet::new();
    while picked.len() < want {
        picked.insert(rng.gen_range(1..=max_existing_witness));
    }
    picked.into_iter().collect()
}

fn sample_input_linear_combo<R: Rng>(rng: &mut R, num_inputs: usize) -> Vec<Term> {
    let arity = rng.gen_range(1..=num_inputs.min(3));
    let indices = sample_unique_indices(rng, num_inputs, arity);

    indices
        .into_iter()
        .map(|index| Term {
            index,
            coeff: sample_coeff(rng).to_string(),
        })
        .collect()
}

fn sample_witness_linear_combo<R: Rng>(rng: &mut R, max_existing_witness: usize) -> Vec<Term> {
    let arity = rng.gen_range(1..=max_existing_witness.min(3));
    let indices = sample_unique_witness_indices(rng, max_existing_witness, arity);

    indices
        .into_iter()
        .map(|index| Term {
            index,
            coeff: sample_coeff(rng).to_string(),
        })
        .collect()
}

pub fn build_random_rms_linear<R: Rng>(
    num_inputs: usize,
    depth: usize,
    rng: &mut R,
) -> Result<RmsLinearExport, String> {
    if num_inputs == 0 {
        return Err("num_inputs must be >= 1".to_string());
    }
    if depth == 0 {
        return Err("num_constraints must be >= 1".to_string());
    }

    let num_witnesses = depth + 1;
    let execution_order: Vec<usize> = (0..depth).collect();
    let mut constraints = Vec::with_capacity(depth);

    for index in 0..depth {
        let max_existing_witness = index + 1;
        let output_witness = index + 2;

        constraints.push(ExportConstraint {
            index,
            a_in: sample_input_linear_combo(rng, num_inputs),
            b_wit: sample_witness_linear_combo(rng, max_existing_witness),
            output_witness,
        });
    }

    build_rms_export(
        num_inputs,
        num_witnesses,
        execution_order,
        constraints,
        &ExportInputConfig::all_private(num_inputs),
    )
    .map(|export| export.with_output_witnesses(vec![num_witnesses]))
}

pub fn run() {
    run_with_args(&[]).expect("随机 linear 示例失败");
}

pub fn run_with_args(args: &[String]) -> Result<(), String> {
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        return Err(usage_text().to_string());
    }

    let (args, export_options) = split_export_cli_args(args);
    let config = match args.as_slice() {
        [] => RandomLinearRunConfig::demo(),
        [num_inputs, num_constraints] => RandomLinearRunConfig::new(
            parse_usize_arg("num_inputs", num_inputs)?,
            parse_usize_arg("num_constraints", num_constraints)?,
            DEFAULT_SEED,
        ),
        _ => return Err(usage_text().to_string()),
    };

    run_with_config(config, export_options)
}

fn run_with_config(
    config: RandomLinearRunConfig,
    export_options: ExportBundleOptions,
) -> Result<(), String> {
    let mut rng = StdRng::seed_from_u64(config.seed);
    let export = build_random_rms_linear(config.num_inputs, config.num_constraints, &mut rng)?;
    let report = write_export_bundle_with_options(&config.export_stem, &export, export_options)
        .map_err(|err| format!("导出随机 linear RMS 电路失败: {err}"))?;

    println!("\n╔══════════════════════════════════════════════════╗");
    println!("║  随机采样 Linear：输入线性组合乘 witness         ║");
    println!("╚══════════════════════════════════════════════════╝\n");
    println!("  输入数: {}", export.num_inputs);
    println!("  约束数: {}", export.constraints.len());
    println!("  witness 数: {}", export.num_witnesses);
    println!("  BIN:  {}", report.bin_path);
    if let Some(json_path) = &report.json_path {
        println!("  JSON: {}", json_path);
    }
    println!("  版本: {}", report.version);
    if let Some(json_bin_match) = report.json_bin_match {
        println!("  JSON/BIN 内容一致: {}", json_bin_match);
    }
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
  cargo run -- random_linear [--json]
  cargo run -- random_linear <num_inputs> <num_constraints> [--json]
  cargo run --example random_linear -- <num_inputs> <num_constraints> [--json]

说明:
  默认值: num_inputs=5, num_constraints=64。
  默认只导出 .bin；追加 --json 时同时导出 .json。"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linear_generator_produces_sequential_constraints() {
        let mut rng = StdRng::seed_from_u64(7);
        let export = build_random_rms_linear(4, 6, &mut rng).expect("linear export");

        assert_eq!(export.version, "rms-linear-v2");
        assert_eq!(export.num_inputs, 4);
        assert_eq!(export.num_witnesses, 7);
        assert_eq!(export.execution_order, vec![0, 1, 2, 3, 4, 5]);
        assert_eq!(export.num_public_inputs, 1);
        assert_eq!(export.public_inputs[0].index, 0);
        assert_eq!(export.public_inputs[0].value, "1");
        assert_eq!(export.num_private_inputs, 3);
        assert_eq!(export.output_witnesses, vec![7]);

        for (index, constraint) in export.constraints.iter().enumerate() {
            assert_eq!(constraint.index, index);
            assert_eq!(constraint.output_witness, index + 2);
            assert!(!constraint.a_in.is_empty());
            assert!(!constraint.b_wit.is_empty());
            assert!(constraint.b_wit.iter().all(|term| term.index <= index + 1));
        }
    }
}
