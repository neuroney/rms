use crate::export::{
    build_rms_export_v2, print_export_constraints_preview, write_export_bundle, ExportInputConfig,
};
use crate::r1cs::{ExportConstraint, RmsLinearExport, Term};
use rand::{rngs::StdRng, Rng, SeedableRng};

pub const DEFAULT_NUM_INPUTS: usize = 5;
pub const DEFAULT_NUM_CONSTRAINTS: usize = 64;
pub const DEFAULT_SEED: u64 = 42;

#[derive(Clone, Debug)]
pub struct RandomMulRunConfig {
    pub num_inputs: usize,
    pub num_constraints: usize,
    pub seed: u64,
    pub export_stem: String,
}

impl RandomMulRunConfig {
    pub fn demo() -> Self {
        Self::new(DEFAULT_NUM_INPUTS, DEFAULT_NUM_CONSTRAINTS, DEFAULT_SEED)
    }

    pub fn new(num_inputs: usize, num_constraints: usize, seed: u64) -> Self {
        Self {
            num_inputs,
            num_constraints,
            seed,
            export_stem: format!("data/random_mul_n{}_d{}_rms", num_inputs, num_constraints),
        }
    }
}

pub fn build_random_rms<R: Rng>(
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
        let input_idx = rng.gen_range(0..num_inputs);
        let witness_in = rng.gen_range(1..=(index + 1));
        let witness_out = index + 2;

        constraints.push(ExportConstraint {
            index,
            a_in: vec![Term {
                index: input_idx,
                coeff: "1".to_string(),
            }],
            b_wit: vec![Term {
                index: witness_in,
                coeff: "1".to_string(),
            }],
            output_witness: witness_out,
        });
    }

    build_rms_export_v2(
        num_inputs,
        num_witnesses,
        execution_order,
        constraints,
        &ExportInputConfig::all_private(num_inputs),
    )
}

pub fn run() {
    run_with_args(&[]).expect("随机 mul 示例失败");
}

pub fn run_with_args(args: &[String]) -> Result<(), String> {
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        return Err(usage_text().to_string());
    }

    let config = match args {
        [] => RandomMulRunConfig::demo(),
        [num_inputs, num_constraints] => RandomMulRunConfig::new(
            parse_usize_arg("num_inputs", num_inputs)?,
            parse_usize_arg("num_constraints", num_constraints)?,
            DEFAULT_SEED,
        ),
        _ => return Err(usage_text().to_string()),
    };

    run_with_config(config)
}

fn run_with_config(config: RandomMulRunConfig) -> Result<(), String> {
    let mut rng = StdRng::seed_from_u64(config.seed);
    let export = build_random_rms(config.num_inputs, config.num_constraints, &mut rng)?;
    let report = write_export_bundle(&config.export_stem, &export)
        .map_err(|err| format!("导出随机 mul RMS 电路失败: {err}"))?;

    println!("\n╔══════════════════════════════════════════════════╗");
    println!("║  随机采样 Mul：直接满足 RMS 的乘法链             ║");
    println!("╚══════════════════════════════════════════════════╝\n");
    println!("  输入数: {}", export.num_inputs);
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
  cargo run -- random_mul
  cargo run -- random_mul <num_inputs> <num_constraints>
  cargo run --example random_mul -- <num_inputs> <num_constraints>

说明:
  默认值: num_inputs=5, num_constraints=64"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_generator_uses_existing_witnesses_only() {
        let mut rng = StdRng::seed_from_u64(9);
        let export = build_random_rms(5, 8, &mut rng).expect("mul export");

        assert_eq!(export.version, "rms-linear-v2");
        assert_eq!(export.num_witnesses, 9);
        assert_eq!(export.constraints.len(), 8);
        assert_eq!(export.num_public_inputs, 1);
        assert_eq!(export.public_inputs[0].index, 0);
        assert_eq!(export.public_inputs[0].value, "1");
        assert_eq!(export.num_private_inputs, 4);

        for (index, constraint) in export.constraints.iter().enumerate() {
            assert_eq!(constraint.index, index);
            assert_eq!(constraint.a_in.len(), 1);
            assert_eq!(constraint.b_wit.len(), 1);
            assert!(constraint.a_in[0].index < 5);
            assert!(constraint.b_wit[0].index <= index + 1);
            assert_eq!(constraint.output_witness, index + 2);
        }
    }
}
