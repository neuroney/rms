use crate::evalr1cs::{execute_circuit, verify_assignment, Assignment};
use crate::export::{
    export_r1cs_bundle_with_inputs, load_r1cs_from_json, terms_to_export_string, ExportInputConfig,
    WrittenArtifacts,
};
use crate::r1cs::{Constraint, LinComb, Variable, R1CS};
use crate::transform::{choudhuri_transform, eliminate_common_subexpressions, TransformResult};
use crate::utils::{fr_to_u64, print_constraints};
use ark_bn254::Fr;

#[derive(Clone, Debug)]
pub struct GreaterThanCircuit {
    pub r1cs: R1CS,
    pub num_bits: usize,
    pub alpha_input_indices: Vec<usize>,
    pub beta_input_indices: Vec<usize>,
    pub equal_bit_witness_indices: Vec<usize>,
    pub greater_bit_witness_indices: Vec<usize>,
    pub prefix_result_witness_indices: Vec<usize>,
    pub output_witness_index: usize,
}

#[derive(Clone, Debug)]
pub struct GreaterThanRunConfig {
    pub num_bits: usize,
    pub alpha: u64,
    pub beta: u64,
    pub export_stem: String,
}

#[derive(Clone, Debug)]
pub struct GeneratedGreaterThan {
    pub config: GreaterThanRunConfig,
    pub circuit: GreaterThanCircuit,
    pub input_assignment: Vec<(usize, u64)>,
    pub alpha_bits: Vec<u64>,
    pub beta_bits: Vec<u64>,
    pub expected_output: u64,
}

#[derive(Clone, Debug)]
pub struct TransformedGreaterThan {
    pub transformed: TransformResult,
    pub optimized: R1CS,
    pub eliminated: usize,
}

#[derive(Clone, Debug)]
pub struct GreaterThanEvalReport {
    pub expected_output: u64,
    pub original_output: u64,
    pub transformed_output: u64,
    pub original_valid: bool,
    pub transformed_valid: bool,
    pub outputs_match: bool,
}

pub type GreaterThanExportReport = WrittenArtifacts;

impl GreaterThanRunConfig {
    pub fn demo() -> Self {
        Self::for_bits(8)
    }

    pub fn for_bits(num_bits: usize) -> Self {
        let (alpha, beta) = demo_operands(num_bits);

        Self {
            num_bits,
            alpha,
            beta,
            export_stem: format!("data/greater_than_{}bit_rms", num_bits),
        }
    }
}

pub fn generate_greater_than_r1cs(num_bits: usize) -> GreaterThanCircuit {
    assert!(num_bits > 0, "比较位宽必须大于 0");

    let num_inputs = 1 + 2 * num_bits;
    let mut r1cs = R1CS::new(num_inputs, 0);

    let mut next_input = 1usize;
    let mut alpha_input_indices = Vec::with_capacity(num_bits);
    for _ in 0..num_bits {
        alpha_input_indices.push(next_input);
        next_input += 1;
    }

    let mut beta_input_indices = Vec::with_capacity(num_bits);
    for _ in 0..num_bits {
        beta_input_indices.push(next_input);
        next_input += 1;
    }

    let mut next_w = 2usize;
    let zero_witness = next_w;
    next_w += 1;
    r1cs.add_constraint(
        Constraint {
            a: LinComb::from_var(Variable::Input(0)),
            b: LinComb::from_terms(vec![]),
            c: LinComb::from_var(Variable::Witness(zero_witness)),
        },
        zero_witness,
    );

    let one = Fr::from(1u64);
    let minus_one = -Fr::from(1u64);

    let mut equal_bit_witness_indices = Vec::with_capacity(num_bits);
    let mut greater_bit_witness_indices = Vec::with_capacity(num_bits);
    let mut prefix_result_witness_indices = Vec::with_capacity(num_bits);

    let mut prefix_prev = zero_witness;

    for bit in 0..num_bits {
        let alpha_idx = alpha_input_indices[bit];
        let beta_idx = beta_input_indices[bit];

        let alpha_beta_witness = next_w;
        next_w += 1;
        r1cs.add_constraint(
            Constraint {
                a: LinComb::from_var(Variable::Input(alpha_idx)),
                b: LinComb::from_var(Variable::Input(beta_idx)),
                c: LinComb::from_var(Variable::Witness(alpha_beta_witness)),
            },
            alpha_beta_witness,
        );

        let both_zero_witness = next_w;
        next_w += 1;
        r1cs.add_constraint(
            Constraint {
                a: LinComb::from_terms(vec![
                    (one, Variable::Input(0)),
                    (minus_one, Variable::Input(alpha_idx)),
                ]),
                b: LinComb::from_terms(vec![
                    (one, Variable::Input(0)),
                    (minus_one, Variable::Input(beta_idx)),
                ]),
                c: LinComb::from_var(Variable::Witness(both_zero_witness)),
            },
            both_zero_witness,
        );

        let equal_bit_witness = next_w;
        next_w += 1;
        r1cs.add_constraint(
            Constraint {
                a: LinComb::from_var(Variable::Input(0)),
                b: LinComb::from_terms(vec![
                    (one, Variable::Witness(alpha_beta_witness)),
                    (one, Variable::Witness(both_zero_witness)),
                ]),
                c: LinComb::from_var(Variable::Witness(equal_bit_witness)),
            },
            equal_bit_witness,
        );

        let greater_bit_witness = next_w;
        next_w += 1;
        r1cs.add_constraint(
            Constraint {
                a: LinComb::from_var(Variable::Input(alpha_idx)),
                b: LinComb::from_terms(vec![
                    (one, Variable::Input(0)),
                    (minus_one, Variable::Input(beta_idx)),
                ]),
                c: LinComb::from_var(Variable::Witness(greater_bit_witness)),
            },
            greater_bit_witness,
        );

        let equal_and_prev_witness = next_w;
        next_w += 1;
        r1cs.add_constraint(
            Constraint {
                a: LinComb::from_var(Variable::Witness(equal_bit_witness)),
                b: LinComb::from_var(Variable::Witness(prefix_prev)),
                c: LinComb::from_var(Variable::Witness(equal_and_prev_witness)),
            },
            equal_and_prev_witness,
        );

        let prefix_result_witness = next_w;
        next_w += 1;
        r1cs.add_constraint(
            Constraint {
                a: LinComb::from_var(Variable::Input(0)),
                b: LinComb::from_terms(vec![
                    (one, Variable::Witness(greater_bit_witness)),
                    (one, Variable::Witness(equal_and_prev_witness)),
                ]),
                c: LinComb::from_var(Variable::Witness(prefix_result_witness)),
            },
            prefix_result_witness,
        );

        equal_bit_witness_indices.push(equal_bit_witness);
        greater_bit_witness_indices.push(greater_bit_witness);
        prefix_result_witness_indices.push(prefix_result_witness);
        prefix_prev = prefix_result_witness;
    }

    r1cs.num_witnesses = next_w - 1;

    GreaterThanCircuit {
        r1cs,
        num_bits,
        alpha_input_indices,
        beta_input_indices,
        equal_bit_witness_indices,
        greater_bit_witness_indices,
        prefix_result_witness_indices,
        output_witness_index: prefix_prev,
    }
}

pub fn generate_circuit(config: GreaterThanRunConfig) -> GeneratedGreaterThan {
    validate_config(&config);

    let circuit = generate_greater_than_r1cs(config.num_bits);
    let alpha_bits = decompose_bits(config.alpha, config.num_bits);
    let beta_bits = decompose_bits(config.beta, config.num_bits);
    let input_assignment = build_bit_inputs(
        &circuit.alpha_input_indices,
        &circuit.beta_input_indices,
        &alpha_bits,
        &beta_bits,
    );
    let expected_output = u64::from(config.alpha > config.beta);

    GeneratedGreaterThan {
        config,
        circuit,
        input_assignment,
        alpha_bits,
        beta_bits,
        expected_output,
    }
}

pub fn transform_circuit(generated: &GeneratedGreaterThan) -> TransformedGreaterThan {
    let transformed = choudhuri_transform(&generated.circuit.r1cs);
    let (optimized, eliminated) = eliminate_common_subexpressions(&transformed.r1cs);

    TransformedGreaterThan {
        transformed,
        optimized,
        eliminated,
    }
}

pub fn evaluate_equivalence(
    generated: &GeneratedGreaterThan,
    transformed: &TransformedGreaterThan,
) -> GreaterThanEvalReport {
    let mut original_assignment = Assignment::new(generated.input_assignment.clone());
    let _ = execute_circuit(&generated.circuit.r1cs, &mut original_assignment).is_some();
    let original_valid = verify_assignment(&generated.circuit.r1cs, &original_assignment);
    let original_output = read_output(generated.circuit.output_witness_index, &original_assignment);

    let mut transformed_assignment = Assignment::new(generated.input_assignment.clone());
    let _ = execute_circuit(&transformed.optimized, &mut transformed_assignment).is_some();
    let transformed_valid = verify_assignment(&transformed.optimized, &transformed_assignment);
    let transformed_output = read_output(
        generated.circuit.output_witness_index,
        &transformed_assignment,
    );

    GreaterThanEvalReport {
        expected_output: generated.expected_output,
        original_output,
        transformed_output,
        original_valid,
        transformed_valid,
        outputs_match: original_output == generated.expected_output
            && transformed_output == generated.expected_output,
    }
}

pub fn export_circuit(
    generated: &GeneratedGreaterThan,
    transformed: &TransformedGreaterThan,
) -> Result<GreaterThanExportReport, Box<dyn std::error::Error>> {
    export_r1cs_bundle_with_inputs(
        &transformed.optimized,
        &generated.config.export_stem,
        &ExportInputConfig::all_private(generated.circuit.r1cs.num_inputs),
    )
}

pub fn run() {
    run_with_args(&[]).expect("greater-than 示例失败");
}

pub fn run_with_args(args: &[String]) -> Result<(), String> {
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        return Err(usage_text().to_string());
    }

    let config = match args {
        [] => GreaterThanRunConfig::demo(),
        [num_bits] => GreaterThanRunConfig::for_bits(parse_positive_usize_arg("bit", num_bits)?),
        _ => return Err(usage_text().to_string()),
    };

    run_with_config(config)
}

fn run_with_config(config: GreaterThanRunConfig) -> Result<(), String> {
    let generated = generate_circuit(config);
    let transformed = transform_circuit(&generated);
    let evaluation = evaluate_equivalence(&generated, &transformed);
    let export = export_circuit(&generated, &transformed)
        .map_err(|err| format!("导出 greater-than RMS 电路失败: {err}"))?;

    println!("\n╔══════════════════════════════════════════════════╗");
    println!("║  Greater-Than 示例：按位递推比较                 ║");
    println!("╚══════════════════════════════════════════════════╝\n");

    println!("【1. 生成电路】");
    println!("  位宽: {}", generated.config.num_bits);
    println!(
        "  alpha = {} (bits: {})",
        generated.config.alpha,
        format_bits(&generated.alpha_bits)
    );
    println!(
        "  beta  = {} (bits: {})",
        generated.config.beta,
        format_bits(&generated.beta_bits)
    );
    println!("  输入索引（按 MSB -> LSB 展示）:");
    print_bit_indices("alpha", "x", &generated.circuit.alpha_input_indices);
    print_bit_indices("beta ", "x", &generated.circuit.beta_input_indices);
    println!("  递推 witness（bit 编号按 MSB -> LSB 展示）:");
    print_comparison_witnesses(&generated.circuit);
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
    println!("  期望输出:       {}", evaluation.expected_output);
    println!("  原始电路输出:   {}", evaluation.original_output);
    println!("  转换后电路输出: {}", evaluation.transformed_output);
    println!(
        "  输出一致: {}  [约束满足: orig={}, rms+cse={}]",
        evaluation.outputs_match, evaluation.original_valid, evaluation.transformed_valid
    );

    println!("\n【4. 电路导出】");
    println!("  JSON: {}", export.json_path);
    println!("  BIN:  {}", export.bin_path);
    println!("  版本: {}", export.version);
    println!("  约束数: {}", export.num_constraints);
    println!("  JSON/BIN 内容一致: {}", export.json_bin_match);
    println!("  前 8 条最终 RMS 约束:");
    let exported_json = load_r1cs_from_json(&export.json_path).expect("读取 JSON 导出文件失败");
    for constraint in exported_json.constraints.iter().take(8) {
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

fn validate_config(config: &GreaterThanRunConfig) {
    assert!(config.num_bits > 0, "比较位宽必须大于 0");
    assert!(
        config.num_bits <= u64::BITS as usize,
        "当前 demo 仅支持不超过 64 bit 的整数输入"
    );

    if config.num_bits < u64::BITS as usize {
        let upper_bound = 1u64 << config.num_bits;
        assert!(
            config.alpha < upper_bound,
            "alpha 超出 {} bit 范围",
            config.num_bits
        );
        assert!(
            config.beta < upper_bound,
            "beta 超出 {} bit 范围",
            config.num_bits
        );
    }
}

fn demo_operands(num_bits: usize) -> (u64, u64) {
    assert!(num_bits > 0, "比较位宽必须大于 0");
    assert!(
        num_bits <= u64::BITS as usize,
        "当前 demo 仅支持不超过 64 bit 的整数输入"
    );

    let max_value = if num_bits == u64::BITS as usize {
        u64::MAX
    } else {
        (1u64 << num_bits) - 1
    };

    if max_value == 1 {
        return (1, 0);
    }

    let alpha = max_value.saturating_sub(max_value / 5).max(1);
    let mut beta = max_value / 2;
    if beta >= alpha {
        beta = alpha.saturating_sub(1);
    }

    (alpha, beta)
}

fn decompose_bits(value: u64, num_bits: usize) -> Vec<u64> {
    (0..num_bits).map(|bit| (value >> bit) & 1).collect()
}

fn build_bit_inputs(
    alpha_indices: &[usize],
    beta_indices: &[usize],
    alpha_bits: &[u64],
    beta_bits: &[u64],
) -> Vec<(usize, u64)> {
    let mut inputs = Vec::with_capacity(alpha_indices.len() + beta_indices.len());

    for (input_idx, bit) in alpha_indices.iter().zip(alpha_bits.iter()) {
        inputs.push((*input_idx, *bit));
    }
    for (input_idx, bit) in beta_indices.iter().zip(beta_bits.iter()) {
        inputs.push((*input_idx, *bit));
    }

    inputs
}

fn read_output(output_witness: usize, assignment: &Assignment) -> u64 {
    fr_to_u64(&assignment.witnesses[&output_witness]).expect("比较输出超出 u64")
}

fn format_bits(bits: &[u64]) -> String {
    bits.iter()
        .rev()
        .map(|bit| bit.to_string())
        .collect::<Vec<_>>()
        .join("")
}

fn print_bit_indices(name: &str, prefix: &str, indices: &[usize]) {
    let formatted = indices
        .iter()
        .enumerate()
        .rev()
        .map(|(bit, index)| format!("b{}={}{}", bit, prefix, index))
        .collect::<Vec<_>>()
        .join(", ");
    println!("    {}: [{}]", name, formatted);
}

fn print_comparison_witnesses(circuit: &GreaterThanCircuit) {
    for bit in (0..circuit.num_bits).rev() {
        println!(
            "    bit {}: eq=w{}, gt=w{}, c=w{}",
            bit,
            circuit.equal_bit_witness_indices[bit],
            circuit.greater_bit_witness_indices[bit],
            circuit.prefix_result_witness_indices[bit]
        );
    }
}

fn parse_positive_usize_arg(name: &str, raw: &str) -> Result<usize, String> {
    let value = raw
        .parse::<usize>()
        .map_err(|err| format!("{name} 必须是非负整数，收到 {raw:?}: {err}"))?;
    if value == 0 {
        return Err(format!("{name} 必须大于 0"));
    }
    Ok(value)
}

fn usage_text() -> &'static str {
    "\
用法:
  cargo run -- greater_than
  cargo run -- greater_than <bit>
  cargo run --example greater_than -- <bit>

说明:
  默认值: bit=8。
  alpha 和 beta 会根据位宽自动生成一组稳定的演示输入。"
}

#[cfg(test)]
mod circuit_tests {
    use super::*;

    fn build_greater_than_assignment(
        circuit: &GreaterThanCircuit,
        alpha: u64,
        beta: u64,
    ) -> Assignment {
        assert!(
            circuit.num_bits <= u64::BITS as usize,
            "测试输入目前仅支持不超过 64 bit"
        );
        if circuit.num_bits < u64::BITS as usize {
            let upper_bound = 1u64 << circuit.num_bits;
            assert!(
                alpha < upper_bound,
                "alpha 超出 {} bit 范围",
                circuit.num_bits
            );
            assert!(
                beta < upper_bound,
                "beta 超出 {} bit 范围",
                circuit.num_bits
            );
        }

        let mut inputs = Vec::with_capacity(circuit.num_bits * 2);
        for (bit, input_idx) in circuit.alpha_input_indices.iter().enumerate() {
            inputs.push((*input_idx, (alpha >> bit) & 1));
        }
        for (bit, input_idx) in circuit.beta_input_indices.iter().enumerate() {
            inputs.push((*input_idx, (beta >> bit) & 1));
        }

        Assignment::new(inputs)
    }

    fn read_greater_than_output(circuit: &GreaterThanCircuit, assignment: &Assignment) -> u64 {
        fr_to_u64(&assignment.witnesses[&circuit.output_witness_index]).expect("比较输出超出 u64")
    }

    #[test]
    fn greater_than_4_bit_transforms_to_rms_and_preserves_output() {
        let circuit = generate_greater_than_r1cs(4);
        let transformed = choudhuri_transform(&circuit.r1cs);
        let (optimized, _eliminated) = eliminate_common_subexpressions(&transformed.r1cs);

        assert!(optimized
            .constraints
            .iter()
            .all(|constraint| constraint.is_rms_compatible()));

        for (alpha, beta, expected) in [
            (0u64, 0u64, 0u64),
            (1, 0, 1),
            (0, 1, 0),
            (6, 6, 0),
            (9, 6, 1),
            (6, 9, 0),
            (15, 14, 1),
            (8, 12, 0),
        ] {
            let mut original_assignment = build_greater_than_assignment(&circuit, alpha, beta);
            assert!(execute_circuit(&circuit.r1cs, &mut original_assignment).is_some());
            assert!(verify_assignment(&circuit.r1cs, &original_assignment));
            assert_eq!(
                read_greater_than_output(&circuit, &original_assignment),
                expected
            );

            let mut optimized_assignment = build_greater_than_assignment(&circuit, alpha, beta);
            assert!(execute_circuit(&optimized, &mut optimized_assignment).is_some());
            assert!(verify_assignment(&optimized, &optimized_assignment));
            assert_eq!(
                read_greater_than_output(&circuit, &optimized_assignment),
                expected
            );
        }
    }
}

#[cfg(test)]
mod pipeline_tests {
    use super::*;

    #[test]
    fn greater_than_demo_pipeline_keeps_output_after_transform() {
        let generated = generate_circuit(GreaterThanRunConfig::demo());
        let transformed = transform_circuit(&generated);
        let evaluation = evaluate_equivalence(&generated, &transformed);

        assert!(evaluation.original_valid);
        assert!(evaluation.transformed_valid);
        assert!(evaluation.outputs_match);
        assert_eq!(evaluation.original_output, evaluation.expected_output);
        assert_eq!(evaluation.transformed_output, evaluation.expected_output);
    }
}
