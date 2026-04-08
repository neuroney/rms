use crate::evalr1cs::{execute_circuit, verify_assignment, Assignment};
use crate::export::{
    load_r1cs_from_bin, split_export_cli_args, terms_to_export_string,
    write_export_bundle_with_options, ExportBundleOptions, ExportInputConfig, WrittenArtifacts,
};
use crate::r1cs::{Constraint, LinComb, RmsLinearExport, Variable, R1CS};
use crate::transform::{
    choudhuri_transform, eliminate_common_subexpressions_preserving_witnesses, TransformResult,
};
use crate::utils::{coeff_to_string, format_preview_list, print_constraints};
use ark_bn254::Fr;
use ark_ff::{Field, One};
use std::str::FromStr;

const MIMC7_FIXTURE_SOURCE: &str = include_str!("../fixtures/mimc_fixed_key.circom");

pub const DEFAULT_NUM_ROUNDS: usize = 91;
pub const DEFAULT_DEMO_INPUT: u64 = 3;
pub const PRIVATE_INPUT_INDEX: usize = 1;
pub const MIMC7_EXPONENT: usize = 7;

#[derive(Clone, Debug)]
pub struct Mimc7Circuit {
    pub r1cs: R1CS,
    pub num_rounds: usize,
    pub input_index: usize,
    pub lifted_input_witness: usize,
    pub round_output_witness_indices: Vec<usize>,
}

#[derive(Clone, Debug)]
pub struct Mimc7RunConfig {
    pub num_rounds: usize,
    pub input_value: Fr,
    pub export_stem: String,
}

#[derive(Clone, Debug)]
pub struct GeneratedMimc7 {
    pub config: Mimc7RunConfig,
    pub circuit: Mimc7Circuit,
    pub input_assignment: Vec<(usize, Fr)>,
    pub expected_round_outputs: Vec<Fr>,
}

#[derive(Clone, Debug)]
pub struct TransformedMimc7 {
    pub transformed: TransformResult,
    pub optimized: R1CS,
    pub eliminated: usize,
}

#[derive(Clone, Debug)]
pub struct Mimc7EvalReport {
    pub expected_round_outputs: Vec<Fr>,
    pub original_round_outputs: Vec<Fr>,
    pub transformed_round_outputs: Vec<Fr>,
    pub original_valid: bool,
    pub transformed_valid: bool,
    pub outputs_match: bool,
}

pub type Mimc7ExportReport = WrittenArtifacts;

impl Mimc7RunConfig {
    pub fn demo() -> Self {
        Self::new(DEFAULT_NUM_ROUNDS)
    }

    pub fn new(num_rounds: usize) -> Self {
        Self::with_input(num_rounds, Fr::from(DEFAULT_DEMO_INPUT))
    }

    pub fn with_input(num_rounds: usize, input_value: Fr) -> Self {
        Self {
            num_rounds,
            input_value,
            export_stem: format!("data/mimc7_r{}", num_rounds),
        }
    }
}

pub fn available_round_constants() -> Result<Vec<Fr>, String> {
    let marker = "var c[91] = [";
    let start = MIMC7_FIXTURE_SOURCE
        .find(marker)
        .ok_or_else(|| "在 fixture 里找不到 MiMC7 round constants 定义".to_string())?
        + marker.len();
    let tail = &MIMC7_FIXTURE_SOURCE[start..];
    let end = tail
        .find("];")
        .ok_or_else(|| "MiMC7 round constants 定义缺少结束标记 `];`".to_string())?;
    let body = &tail[..end];

    let constants = body
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(parse_fr)
        .collect::<Result<Vec<_>, _>>()?;

    if constants.len() != DEFAULT_NUM_ROUNDS {
        return Err(format!(
            "MiMC7 fixture round constants 数量异常: 期望 {}，实际 {}",
            DEFAULT_NUM_ROUNDS,
            constants.len()
        ));
    }

    Ok(constants)
}

pub fn generate_mimc7_r1cs(num_rounds: usize) -> Result<Mimc7Circuit, String> {
    let round_constants = available_round_constants()?;
    validate_num_rounds(num_rounds, round_constants.len())?;

    let num_inputs = PRIVATE_INPUT_INDEX + 1;
    let mut r1cs = R1CS::new(num_inputs, 0);
    let mut next_witness = 2usize;

    let lifted_input_witness = next_witness;
    next_witness += 1;
    r1cs.add_constraint(
        Constraint {
            a: LinComb::from_var(Variable::Input(PRIVATE_INPUT_INDEX)),
            b: LinComb::from_var(Variable::Witness(1)),
            c: LinComb::from_var(Variable::Witness(lifted_input_witness)),
        },
        lifted_input_witness,
    );

    let mut current_state = lifted_input_witness;
    let mut round_output_witness_indices = Vec::with_capacity(num_rounds);

    for round_constant in round_constants.into_iter().take(num_rounds) {
        let t_witness = next_witness;
        next_witness += 1;
        r1cs.add_constraint(
            Constraint {
                a: LinComb::from_var(Variable::Input(0)),
                b: LinComb::from_terms(vec![
                    (Fr::one(), Variable::Witness(current_state)),
                    (round_constant, Variable::Witness(1)),
                ]),
                c: LinComb::from_var(Variable::Witness(t_witness)),
            },
            t_witness,
        );

        let t2_witness = next_witness;
        next_witness += 1;
        r1cs.add_constraint(
            Constraint {
                a: LinComb::from_var(Variable::Witness(t_witness)),
                b: LinComb::from_var(Variable::Witness(t_witness)),
                c: LinComb::from_var(Variable::Witness(t2_witness)),
            },
            t2_witness,
        );

        let t4_witness = next_witness;
        next_witness += 1;
        r1cs.add_constraint(
            Constraint {
                a: LinComb::from_var(Variable::Witness(t2_witness)),
                b: LinComb::from_var(Variable::Witness(t2_witness)),
                c: LinComb::from_var(Variable::Witness(t4_witness)),
            },
            t4_witness,
        );

        let t6_witness = next_witness;
        next_witness += 1;
        r1cs.add_constraint(
            Constraint {
                a: LinComb::from_var(Variable::Witness(t4_witness)),
                b: LinComb::from_var(Variable::Witness(t2_witness)),
                c: LinComb::from_var(Variable::Witness(t6_witness)),
            },
            t6_witness,
        );

        let next_state = next_witness;
        next_witness += 1;
        r1cs.add_constraint(
            Constraint {
                a: LinComb::from_var(Variable::Witness(t6_witness)),
                b: LinComb::from_var(Variable::Witness(t_witness)),
                c: LinComb::from_var(Variable::Witness(next_state)),
            },
            next_state,
        );

        round_output_witness_indices.push(next_state);
        current_state = next_state;
    }

    r1cs.num_witnesses = next_witness - 1;

    Ok(Mimc7Circuit {
        r1cs,
        num_rounds,
        input_index: PRIVATE_INPUT_INDEX,
        lifted_input_witness,
        round_output_witness_indices,
    })
}

pub fn generate_circuit(config: Mimc7RunConfig) -> Result<GeneratedMimc7, String> {
    let circuit = generate_mimc7_r1cs(config.num_rounds)?;
    let input_assignment = vec![(circuit.input_index, config.input_value)];
    let expected_round_outputs = expected_round_outputs(config.num_rounds, config.input_value)?;

    Ok(GeneratedMimc7 {
        config,
        circuit,
        input_assignment,
        expected_round_outputs,
    })
}

pub fn transform_circuit(generated: &GeneratedMimc7) -> TransformedMimc7 {
    let transformed = choudhuri_transform(&generated.circuit.r1cs);
    let (optimized, eliminated) = eliminate_common_subexpressions_preserving_witnesses(
        &transformed.r1cs,
        &generated.circuit.round_output_witness_indices,
    );

    TransformedMimc7 {
        transformed,
        optimized,
        eliminated,
    }
}

pub fn evaluate_equivalence(
    generated: &GeneratedMimc7,
    transformed: &TransformedMimc7,
) -> Mimc7EvalReport {
    let mut original_assignment = Assignment::from_field_inputs(generated.input_assignment.clone());
    let _ = execute_circuit(&generated.circuit.r1cs, &mut original_assignment).is_some();
    let original_valid = verify_assignment(&generated.circuit.r1cs, &original_assignment);
    let original_round_outputs = read_output_vector(
        &generated.circuit.round_output_witness_indices,
        &original_assignment,
    );

    let mut transformed_assignment =
        Assignment::from_field_inputs(generated.input_assignment.clone());
    let _ = execute_circuit(&transformed.optimized, &mut transformed_assignment).is_some();
    let transformed_valid = verify_assignment(&transformed.optimized, &transformed_assignment);
    let transformed_round_outputs = read_output_vector(
        &generated.circuit.round_output_witness_indices,
        &transformed_assignment,
    );

    Mimc7EvalReport {
        expected_round_outputs: generated.expected_round_outputs.clone(),
        original_round_outputs: original_round_outputs.clone(),
        transformed_round_outputs: transformed_round_outputs.clone(),
        original_valid,
        transformed_valid,
        outputs_match: original_round_outputs == generated.expected_round_outputs
            && transformed_round_outputs == generated.expected_round_outputs,
    }
}

pub fn export_circuit(
    generated: &GeneratedMimc7,
    transformed: &TransformedMimc7,
) -> Result<Mimc7ExportReport, Box<dyn std::error::Error>> {
    export_circuit_with_options(generated, transformed, ExportBundleOptions::default())
}

pub fn export_circuit_with_options(
    generated: &GeneratedMimc7,
    transformed: &TransformedMimc7,
    export_options: ExportBundleOptions,
) -> Result<Mimc7ExportReport, Box<dyn std::error::Error>> {
    let export = RmsLinearExport::from_r1cs_with_inputs(
        &transformed.optimized,
        &ExportInputConfig::all_private(generated.circuit.r1cs.num_inputs),
    )?
    .with_output_witnesses(generated.circuit.round_output_witness_indices.clone());

    write_export_bundle_with_options(&generated.config.export_stem, &export, export_options)
}

pub fn expected_round_outputs(num_rounds: usize, input_value: Fr) -> Result<Vec<Fr>, String> {
    let round_constants = available_round_constants()?;
    validate_num_rounds(num_rounds, round_constants.len())?;

    let mut current = input_value;
    let mut outputs = Vec::with_capacity(num_rounds);
    for constant in round_constants.into_iter().take(num_rounds) {
        current = (current + constant).pow([MIMC7_EXPONENT as u64]);
        outputs.push(current);
    }
    Ok(outputs)
}

pub fn run() {
    run_with_args(&[]).expect("MiMC7 示例失败");
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
        [] => Mimc7RunConfig::demo(),
        [num_rounds] => Mimc7RunConfig::new(parse_usize_arg("num_rounds", num_rounds)?),
        _ => return Err(usage_text().to_string()),
    };

    run_with_config(config, export_options)
}

fn run_with_config(
    config: Mimc7RunConfig,
    export_options: ExportBundleOptions,
) -> Result<(), String> {
    let generated = generate_circuit(config)?;
    let transformed = transform_circuit(&generated);
    let evaluation = evaluate_equivalence(&generated, &transformed);
    let export = export_circuit_with_options(&generated, &transformed, export_options)
        .map_err(|err| format!("导出 MiMC7 RMS 电路失败: {err}"))?;

    println!("\n╔══════════════════════════════════════════════════╗");
    println!("║  MiMC7：递推版 x <- (x + k_i)^7                  ║");
    println!("╚══════════════════════════════════════════════════╝\n");

    println!("【1. 生成电路】");
    println!("  轮数: {}", generated.config.num_rounds);
    println!(
        "  demo 输入 x{}: {}",
        generated.circuit.input_index,
        coeff_to_string(&generated.config.input_value)
    );
    println!(
        "  输入 lift witness: w{}",
        generated.circuit.lifted_input_witness
    );
    println!(
        "  每轮输出 witness: {}",
        format_preview_list(
            &generated.circuit.round_output_witness_indices,
            8,
            |index| { format!("w{}", index) }
        )
    );
    generated.circuit.r1cs.print_stats();

    println!("\n【2. 电路转换】");
    transformed.transformed.r1cs.print_stats();
    println!(
        "  Choudhuri 膨胀倍数: {:.2}x",
        transformed.transformed.blowup_factor
    );
    println!("  CSE 消除重复约束:  {}", transformed.eliminated);
    println!(
        "  最终膨胀倍数:      {:.2}x",
        transformed.optimized.constraints.len() as f64
            / generated.circuit.r1cs.constraints.len() as f64
    );

    println!("\n【3. Eval 一致性】");
    println!(
        "  前 3 轮期望输出: {}",
        format_preview_list(&evaluation.expected_round_outputs, 3, coeff_to_string)
    );
    println!(
        "  前 3 轮原始输出: {}",
        format_preview_list(&evaluation.original_round_outputs, 3, coeff_to_string)
    );
    println!(
        "  前 3 轮转换后输出: {}",
        format_preview_list(&evaluation.transformed_round_outputs, 3, coeff_to_string)
    );
    let final_expected = evaluation
        .expected_round_outputs
        .last()
        .ok_or_else(|| "MiMC7 至少需要 1 轮输出".to_string())?;
    let final_original = evaluation
        .original_round_outputs
        .last()
        .ok_or_else(|| "原始电路缺少最终输出".to_string())?;
    let final_transformed = evaluation
        .transformed_round_outputs
        .last()
        .ok_or_else(|| "转换后电路缺少最终输出".to_string())?;
    println!("  最后一轮期望输出: {}", coeff_to_string(final_expected));
    println!("  原始电路最后输出: {}", coeff_to_string(final_original));
    println!("  转换后最后输出:   {}", coeff_to_string(final_transformed));
    println!(
        "  输出一致: {}  [约束满足: orig={}, rms+cse={}]",
        evaluation.outputs_match, evaluation.original_valid, evaluation.transformed_valid
    );

    println!("\n【4. 电路导出】");
    println!("  BIN:  {}", export.bin_path);
    if let Some(json_path) = &export.json_path {
        println!("  JSON: {}", json_path);
    }
    println!("  版本: {}", export.version);
    println!("  约束数: {}", export.num_constraints);
    if let Some(json_bin_match) = export.json_bin_match {
        println!("  JSON/BIN 内容一致: {}", json_bin_match);
    }
    println!("  前 8 条最终 RMS 约束:");
    let exported_bin = load_r1cs_from_bin(&export.bin_path).expect("读取 BIN 导出文件失败");
    for constraint in exported_bin.constraints.iter().take(8) {
        println!(
            "    step {:>2}: ({} ) * ({} ) -> w{}",
            constraint.index,
            terms_to_export_string(&constraint.a_in, "x"),
            terms_to_export_string(&constraint.b_wit, "w"),
            constraint.output_witness
        );
    }

    println!("\n【前 8 条原始约束预览】");
    let original_preview = R1CS {
        num_inputs: generated.circuit.r1cs.num_inputs,
        num_witnesses: generated.circuit.r1cs.num_witnesses,
        constraints: generated
            .circuit
            .r1cs
            .constraints
            .iter()
            .take(8)
            .cloned()
            .collect(),
        origin: generated.circuit.r1cs.origin.clone(),
    };
    print_constraints(&original_preview);

    Ok(())
}

fn validate_num_rounds(num_rounds: usize, available_rounds: usize) -> Result<(), String> {
    if num_rounds == 0 {
        return Err("num_rounds must be >= 1".to_string());
    }
    if num_rounds > available_rounds {
        return Err(format!(
            "num_rounds={num_rounds} 超出内置 MiMC7 round constants 上限 {available_rounds}"
        ));
    }
    Ok(())
}

fn parse_usize_arg(name: &str, raw: &str) -> Result<usize, String> {
    raw.parse::<usize>()
        .map_err(|err| format!("{name} 必须是非负整数，收到 {raw:?}: {err}"))
}

fn usage_text() -> &'static str {
    "\
用法:
  cargo run -- mimc7 [--json]
  cargo run -- mimc7 <num_rounds> [--json]
  cargo run --example mimc7 -- <num_rounds> [--json]

说明:
  手写递推版 MiMC7：每轮执行 x <- (x + k_i)^7，再转换导出最终 RMS。
  默认只导出 .bin；追加 --json 时同时导出 .json。"
}

fn read_output_vector(output_witnesses: &[usize], assignment: &Assignment) -> Vec<Fr> {
    output_witnesses
        .iter()
        .map(|witness_idx| assignment.witnesses[witness_idx])
        .collect()
}

fn parse_fr(raw: &str) -> Result<Fr, String> {
    Fr::from_str(raw).map_err(|err| format!("字段元素解析失败 {raw:?}: {err:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r1cs::RmsLinearExport;

    #[test]
    fn mimc7_recursive_circuit_has_expected_shape() {
        let circuit = generate_mimc7_r1cs(2).expect("mimc7 circuit");

        assert_eq!(circuit.num_rounds, 2);
        assert_eq!(circuit.r1cs.num_inputs, 2);
        assert_eq!(circuit.lifted_input_witness, 2);
        assert_eq!(circuit.round_output_witness_indices, vec![7, 12]);
        assert_eq!(circuit.r1cs.constraints.len(), 11);
        assert_eq!(circuit.r1cs.num_witnesses, 12);
    }

    #[test]
    fn mimc7_recursive_transform_preserves_outputs() {
        let generated =
            generate_circuit(Mimc7RunConfig::with_input(3, Fr::from(2u64))).expect("generated");
        let transformed = transform_circuit(&generated);
        let evaluation = evaluate_equivalence(&generated, &transformed);

        assert!(evaluation.original_valid);
        assert!(evaluation.transformed_valid);
        assert!(evaluation.outputs_match);
        assert_eq!(
            evaluation.original_round_outputs,
            generated.expected_round_outputs
        );
        assert_eq!(
            evaluation.transformed_round_outputs,
            generated.expected_round_outputs
        );
        assert_eq!(coeff_to_string(&generated.expected_round_outputs[0]), "128");
        assert!(transformed
            .optimized
            .constraints
            .iter()
            .all(|constraint| constraint.is_rms_compatible()));
    }

    #[test]
    fn export_marks_only_x_private() {
        let generated =
            generate_circuit(Mimc7RunConfig::with_input(2, Fr::from(3u64))).expect("generated");
        let transformed = transform_circuit(&generated);
        let export = RmsLinearExport::from_r1cs_with_inputs(
            &transformed.optimized,
            &ExportInputConfig::all_private(generated.circuit.r1cs.num_inputs),
        )
        .expect("export")
        .with_output_witnesses(generated.circuit.round_output_witness_indices.clone());

        assert_eq!(export.version, "rms-linear-v2");
        assert_eq!(export.num_inputs, 2);
        assert_eq!(export.num_public_inputs, 1);
        assert_eq!(export.public_inputs[0].index, 0);
        assert_eq!(export.public_inputs[0].value, "1");
        assert_eq!(export.num_private_inputs, 1);
        assert_eq!(export.private_inputs, vec![1]);
        assert_eq!(
            export.output_witnesses,
            generated.circuit.round_output_witness_indices
        );
    }

    #[test]
    fn mimc7_rejects_out_of_range_round_count() {
        let err = generate_mimc7_r1cs(DEFAULT_NUM_ROUNDS + 1).expect_err("expected error");
        assert!(err.contains("num_rounds"));
    }
}
