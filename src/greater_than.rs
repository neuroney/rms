use crate::evalr1cs::{execute_circuit, verify_assignment, Assignment};
use crate::export::{
    export_r1cs_bundle_with_inputs, load_r1cs_from_json, terms_to_export_string, ExportInputConfig,
    WrittenArtifacts,
};
use crate::r1cs::{Constraint, LinComb, Variable, R1CS};
use crate::transform::{choudhuri_transform, eliminate_common_subexpressions, TransformResult};
use crate::utils::{fr_to_u64, print_constraints};
use ark_bn254::Fr;

const ZERO_PUBLIC_INPUT_INDEX: usize = 1;
const FIRST_EXTERNAL_INPUT_INDEX: usize = 2;

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
    /// Operand bits in LSB-first order.
    pub alpha_bits: Vec<u64>,
    /// Operand bits in LSB-first order.
    pub beta_bits: Vec<u64>,
    pub export_stem: String,
}

#[derive(Clone, Debug)]
pub struct GeneratedGreaterThan {
    pub config: GreaterThanRunConfig,
    pub circuit: GreaterThanCircuit,
    pub input_assignment: Vec<(usize, u64)>,
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
        let (alpha_bits, beta_bits) = demo_operands(num_bits);

        Self {
            alpha_bits,
            beta_bits,
            export_stem: format!("data/greater_than_{}bit", num_bits),
        }
    }

    pub fn num_bits(&self) -> usize {
        self.alpha_bits.len()
    }
}

pub fn generate_greater_than_r1cs(num_bits: usize) -> GreaterThanCircuit {
    assert!(num_bits > 0, "比较位宽必须大于 0");

    let num_inputs = FIRST_EXTERNAL_INPUT_INDEX + 2 * num_bits;
    let mut r1cs = R1CS::new(num_inputs, 0);

    let mut next_input = FIRST_EXTERNAL_INPUT_INDEX;
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
            a: LinComb::from_var(Variable::Input(ZERO_PUBLIC_INPUT_INDEX)),
            b: LinComb::from_var(Variable::Witness(1)),
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

    let num_bits = config.num_bits();
    let circuit = generate_greater_than_r1cs(num_bits);
    let input_assignment = build_bit_inputs(
        &circuit.alpha_input_indices,
        &circuit.beta_input_indices,
        &config.alpha_bits,
        &config.beta_bits,
    );
    let expected_output = u64::from(bits_greater_than(&config.alpha_bits, &config.beta_bits));

    GeneratedGreaterThan {
        config,
        circuit,
        input_assignment,
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
        &greater_than_export_input_config(generated.circuit.r1cs.num_inputs),
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
    println!("  位宽: {}", generated.config.num_bits());
    println!("  alpha = {}", format_operand(&generated.config.alpha_bits));
    println!("  beta  = {}", format_operand(&generated.config.beta_bits));
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
    let num_bits = config.num_bits();
    assert!(num_bits > 0, "比较位宽必须大于 0");
    assert_eq!(
        num_bits,
        config.beta_bits.len(),
        "alpha_bits 和 beta_bits 的长度必须一致"
    );

    validate_binary_operand("alpha_bits", &config.alpha_bits);
    validate_binary_operand("beta_bits", &config.beta_bits);
}

fn validate_binary_operand(name: &str, bits: &[u64]) {
    if let Some((bit_idx, value)) = bits.iter().enumerate().find(|(_, bit)| **bit > 1) {
        panic!("{name}[{bit_idx}] = {value} 不是有效 bit（必须是 0 或 1）");
    }
}

fn demo_operands(num_bits: usize) -> (Vec<u64>, Vec<u64>) {
    assert!(num_bits > 0, "比较位宽必须大于 0");

    if num_bits == 1 {
        return (vec![1], vec![0]);
    }

    let deciding_bit = num_bits - 1 - (num_bits / 3).max(1);
    let mut alpha_bits = vec![0; num_bits];
    let mut beta_bits = vec![0; num_bits];

    for bit in (deciding_bit + 1)..num_bits {
        let shared = ((bit + num_bits) % 2) as u64;
        alpha_bits[bit] = shared;
        beta_bits[bit] = shared;
    }

    alpha_bits[deciding_bit] = 1;
    beta_bits[deciding_bit] = 0;

    for bit in 0..deciding_bit {
        alpha_bits[bit] = ((bit * 3 + 1) % 2) as u64;
        beta_bits[bit] = ((bit * 5 + 2) % 2) as u64;
    }

    (alpha_bits, beta_bits)
}

fn bits_greater_than(alpha_bits: &[u64], beta_bits: &[u64]) -> bool {
    assert_eq!(
        alpha_bits.len(),
        beta_bits.len(),
        "alpha_bits 和 beta_bits 的长度必须一致"
    );

    alpha_bits
        .iter()
        .rev()
        .zip(beta_bits.iter().rev())
        .find_map(|(alpha, beta)| (alpha != beta).then_some(alpha > beta))
        .unwrap_or(false)
}

fn build_bit_inputs(
    alpha_indices: &[usize],
    beta_indices: &[usize],
    alpha_bits: &[u64],
    beta_bits: &[u64],
) -> Vec<(usize, u64)> {
    assert_eq!(
        alpha_indices.len(),
        alpha_bits.len(),
        "alpha 输入索引数量必须与 alpha_bits 长度一致"
    );
    assert_eq!(
        beta_indices.len(),
        beta_bits.len(),
        "beta 输入索引数量必须与 beta_bits 长度一致"
    );

    let mut inputs = Vec::with_capacity(alpha_indices.len() + beta_indices.len() + 1);
    inputs.push((ZERO_PUBLIC_INPUT_INDEX, 0));

    for (input_idx, bit) in alpha_indices.iter().zip(alpha_bits.iter()) {
        inputs.push((*input_idx, *bit));
    }
    for (input_idx, bit) in beta_indices.iter().zip(beta_bits.iter()) {
        inputs.push((*input_idx, *bit));
    }

    inputs
}

fn greater_than_export_input_config(num_inputs: usize) -> ExportInputConfig {
    ExportInputConfig::from_public_values(
        num_inputs,
        vec![(ZERO_PUBLIC_INPUT_INDEX, Fr::from(0u64))],
    )
    .expect("greater-than fixed zero public input should be valid")
}

fn read_output(output_witness: usize, assignment: &Assignment) -> u64 {
    fr_to_u64(&assignment.witnesses[&output_witness]).expect("比较输出超出 u64")
}

fn format_operand(bits: &[u64]) -> String {
    let binary = format_bits(bits);
    match bits_to_u64(bits) {
        Some(value) => format!("{value} (bits: {binary})"),
        None => format!("{} ({} bits)", abbreviate_binary(&binary), bits.len()),
    }
}

fn bits_to_u64(bits: &[u64]) -> Option<u64> {
    if bits.len() > u64::BITS as usize {
        return None;
    }

    let mut value = 0u64;
    for (bit_idx, bit) in bits.iter().enumerate() {
        if *bit == 1 {
            value |= 1u64 << bit_idx;
        }
    }
    Some(value)
}

fn abbreviate_binary(binary: &str) -> String {
    const EDGE_BITS: usize = 24;

    if binary.len() <= EDGE_BITS * 2 {
        return format!("0b{binary}");
    }

    format!(
        "0b{}...{}",
        &binary[..EDGE_BITS],
        &binary[binary.len() - EDGE_BITS..]
    )
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
  alpha 和 beta 会根据位宽自动生成一组稳定的按位演示输入，支持任意位宽。"
}

#[cfg(test)]
mod circuit_tests {
    use super::*;

    fn build_greater_than_assignment(
        circuit: &GreaterThanCircuit,
        alpha_bits: &[u64],
        beta_bits: &[u64],
    ) -> Assignment {
        assert_eq!(circuit.num_bits, alpha_bits.len(), "alpha_bits 长度不匹配");
        assert_eq!(circuit.num_bits, beta_bits.len(), "beta_bits 长度不匹配");

        Assignment::new(build_bit_inputs(
            &circuit.alpha_input_indices,
            &circuit.beta_input_indices,
            alpha_bits,
            beta_bits,
        ))
    }

    fn read_greater_than_output(circuit: &GreaterThanCircuit, assignment: &Assignment) -> u64 {
        fr_to_u64(&assignment.witnesses[&circuit.output_witness_index]).expect("比较输出超出 u64")
    }

    fn bits_from_msb_string(bits: &str) -> Vec<u64> {
        bits.chars()
            .rev()
            .map(|ch| match ch {
                '0' => 0,
                '1' => 1,
                other => panic!("非法 bit 字符: {other}"),
            })
            .collect()
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
        assert!(optimized
            .constraints
            .iter()
            .all(|constraint| !constraint.a.terms.is_empty()));

        for (alpha_bits, beta_bits, expected) in [
            (
                bits_from_msb_string("0000"),
                bits_from_msb_string("0000"),
                0u64,
            ),
            (
                bits_from_msb_string("0001"),
                bits_from_msb_string("0000"),
                1u64,
            ),
            (
                bits_from_msb_string("0000"),
                bits_from_msb_string("0001"),
                0u64,
            ),
            (
                bits_from_msb_string("0110"),
                bits_from_msb_string("0110"),
                0u64,
            ),
            (
                bits_from_msb_string("1001"),
                bits_from_msb_string("0110"),
                1u64,
            ),
            (
                bits_from_msb_string("0110"),
                bits_from_msb_string("1001"),
                0u64,
            ),
            (
                bits_from_msb_string("1111"),
                bits_from_msb_string("1110"),
                1u64,
            ),
            (
                bits_from_msb_string("1000"),
                bits_from_msb_string("1100"),
                0u64,
            ),
        ] {
            let mut original_assignment =
                build_greater_than_assignment(&circuit, &alpha_bits, &beta_bits);
            assert!(execute_circuit(&circuit.r1cs, &mut original_assignment).is_some());
            assert!(verify_assignment(&circuit.r1cs, &original_assignment));
            assert_eq!(
                read_greater_than_output(&circuit, &original_assignment),
                expected
            );

            let mut optimized_assignment =
                build_greater_than_assignment(&circuit, &alpha_bits, &beta_bits);
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

    #[test]
    fn greater_than_130_bit_pipeline_keeps_output_after_transform() {
        let generated = generate_circuit(GreaterThanRunConfig::for_bits(130));
        let transformed = transform_circuit(&generated);
        let evaluation = evaluate_equivalence(&generated, &transformed);

        assert_eq!(generated.config.num_bits(), 130);
        assert!(evaluation.original_valid);
        assert!(evaluation.transformed_valid);
        assert!(evaluation.outputs_match);
        assert_eq!(evaluation.expected_output, 1);
        assert_eq!(evaluation.original_output, evaluation.expected_output);
        assert_eq!(evaluation.transformed_output, evaluation.expected_output);
    }
}
