use crate::evalr1cs::{execute_circuit, verify_assignment, Assignment};
use crate::export::{
    export_r1cs_to_bin, export_r1cs_to_json, load_r1cs_from_bin, load_r1cs_from_json,
    terms_to_export_string,
};
use crate::r1cs::{generate_greater_than_r1cs, GreaterThanCircuit, R1CS};
use crate::transform::{choudhuri_transform, eliminate_common_subexpressions, TransformResult};
use crate::utils::{fr_to_u64, print_constraints};
use std::error::Error;

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

#[derive(Clone, Debug)]
pub struct GreaterThanExportReport {
    pub json_path: String,
    pub bin_path: String,
    pub version: String,
    pub num_constraints: usize,
    pub json_bin_match: bool,
}

impl GreaterThanRunConfig {
    pub fn demo() -> Self {
        Self {
            num_bits: 8,
            alpha: 173,
            beta: 141,
            export_stem: "target/greater_than_8bit_rms".to_string(),
        }
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
) -> Result<GreaterThanExportReport, Box<dyn Error>> {
    let json_path = format!("{}.json", generated.config.export_stem);
    let bin_path = format!("{}.bin", generated.config.export_stem);

    export_r1cs_to_json(&transformed.optimized, &json_path)?;
    export_r1cs_to_bin(&transformed.optimized, &bin_path)?;

    let exported_json = load_r1cs_from_json(&json_path)?;
    let exported_bin = load_r1cs_from_bin(&bin_path)?;
    let version = exported_json.version.clone();
    let num_constraints = exported_json.constraints.len();
    let json_bin_match = exported_json == exported_bin;

    Ok(GreaterThanExportReport {
        json_path,
        bin_path,
        version,
        num_constraints,
        json_bin_match,
    })
}

pub fn run() {
    let generated = generate_circuit(GreaterThanRunConfig::demo());
    let transformed = transform_circuit(&generated);
    let evaluation = evaluate_equivalence(&generated, &transformed);
    let export = export_circuit(&generated, &transformed).expect("导出 greater-than RMS 电路失败");

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

#[cfg(test)]
mod tests {
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
