use crate::evalr1cs::{execute_circuit, verify_assignment, Assignment};
use crate::export::{
    load_r1cs_from_bin, split_export_cli_args, terms_to_export_string,
    write_export_bundle_with_options, ExportBundleOptions, ExportInputConfig, WrittenArtifacts,
};
use crate::r1cs::{Constraint, LinComb, RmsLinearExport, Variable, R1CS};
use crate::transform::{choudhuri_transform, eliminate_common_subexpressions, TransformResult};
use crate::utils::{fr_to_u64, print_constraints, print_preview_matrix};

#[derive(Clone, Debug)]
pub struct TwoMatCircuit {
    pub r1cs: R1CS,
    pub dim: usize,
    pub left_input_indices: Vec<Vec<usize>>,
    pub right_input_indices: Vec<Vec<usize>>,
    pub output_witness_indices: Vec<Vec<usize>>,
}

#[derive(Clone, Debug)]
pub struct TwoMatRunConfig {
    pub dim: usize,
    pub left_values: Vec<Vec<u64>>,
    pub right_values: Vec<Vec<u64>>,
    pub export_stem: String,
}

#[derive(Clone, Debug)]
pub struct GeneratedTwoMat {
    pub config: TwoMatRunConfig,
    pub circuit: TwoMatCircuit,
    pub input_assignment: Vec<(usize, u64)>,
    pub expected_output: Vec<Vec<u64>>,
}

#[derive(Clone, Debug)]
pub struct TransformedTwoMat {
    pub transformed: TransformResult,
    pub optimized: R1CS,
    pub eliminated: usize,
}

#[derive(Clone, Debug)]
pub struct TwoMatEvalReport {
    pub expected_output: Vec<Vec<u64>>,
    pub original_output: Vec<Vec<u64>>,
    pub transformed_output: Vec<Vec<u64>>,
    pub original_valid: bool,
    pub transformed_valid: bool,
    pub outputs_match: bool,
}

pub type TwoMatExportReport = WrittenArtifacts;

impl TwoMatRunConfig {
    pub fn demo() -> Self {
        Self::square(4)
    }

    pub fn square(dim: usize) -> Self {
        let left_values = build_demo_matrix(dim, dim, 1);
        let right_values = build_demo_matrix(dim, dim, (dim * dim) as u64 + 1);

        Self {
            dim,
            left_values,
            right_values,
            export_stem: format!("data/two_mat_{}x{}", dim, dim),
        }
    }
}

pub fn generate_two_mat_r1cs(dim: usize) -> TwoMatCircuit {
    assert!(dim > 0, "矩阵维度必须大于 0");

    let num_inputs = 1 + 2 * dim * dim;
    let mut r1cs = R1CS::new(num_inputs, 0);

    let mut next_input = 1usize;
    let mut left_input_indices = vec![vec![0; dim]; dim];
    for row in &mut left_input_indices {
        for input_idx in row.iter_mut() {
            *input_idx = next_input;
            next_input += 1;
        }
    }

    let mut right_input_indices = vec![vec![0; dim]; dim];
    for row in &mut right_input_indices {
        for input_idx in row.iter_mut() {
            *input_idx = next_input;
            next_input += 1;
        }
    }

    let mut next_witness = 2usize;

    let mut output_witness_indices = vec![vec![0; dim]; dim];
    for i in 0..dim {
        for j in 0..dim {
            let mut product_witnesses = Vec::with_capacity(dim);

            for k in 0..dim {
                let product_witness = next_witness;
                next_witness += 1;
                r1cs.add_constraint(
                    Constraint {
                        a: LinComb::from_var(Variable::Input(left_input_indices[i][k])),
                        b: LinComb::from_var(Variable::Input(right_input_indices[k][j])),
                        c: LinComb::from_var(Variable::Witness(product_witness)),
                    },
                    product_witness,
                );
                product_witnesses.push(product_witness);
            }

            let output_witness = if product_witnesses.len() == 1 {
                product_witnesses[0]
            } else {
                let output_witness = next_witness;
                next_witness += 1;
                r1cs.add_constraint(
                    Constraint {
                        a: LinComb::from_var(Variable::Input(0)),
                        b: LinComb::from_terms(
                            product_witnesses
                                .iter()
                                .map(|witness| (ark_ff::One::one(), Variable::Witness(*witness)))
                                .collect(),
                        ),
                        c: LinComb::from_var(Variable::Witness(output_witness)),
                    },
                    output_witness,
                );
                output_witness
            };
            output_witness_indices[i][j] = output_witness;
        }
    }

    r1cs.num_witnesses = next_witness - 1;

    TwoMatCircuit {
        r1cs,
        dim,
        left_input_indices,
        right_input_indices,
        output_witness_indices,
    }
}

pub fn generate_circuit(config: TwoMatRunConfig) -> GeneratedTwoMat {
    validate_matrix_shape(&config.left_values, config.dim, config.dim, "左矩阵 M1");
    validate_matrix_shape(&config.right_values, config.dim, config.dim, "右矩阵 M2");

    let circuit = generate_two_mat_r1cs(config.dim);
    let input_assignment = build_matrix_inputs(
        &circuit.left_input_indices,
        &circuit.right_input_indices,
        &config.left_values,
        &config.right_values,
    );
    let expected_output = multiply_matrices(&config.left_values, &config.right_values);

    GeneratedTwoMat {
        config,
        circuit,
        input_assignment,
        expected_output,
    }
}

pub fn transform_circuit(generated: &GeneratedTwoMat) -> TransformedTwoMat {
    let transformed = choudhuri_transform(&generated.circuit.r1cs);
    let (optimized, eliminated) = eliminate_common_subexpressions(&transformed.r1cs);

    TransformedTwoMat {
        transformed,
        optimized,
        eliminated,
    }
}

pub fn evaluate_equivalence(
    generated: &GeneratedTwoMat,
    transformed: &TransformedTwoMat,
) -> TwoMatEvalReport {
    let mut original_assignment = Assignment::new(generated.input_assignment.clone());
    let _ = execute_circuit(&generated.circuit.r1cs, &mut original_assignment).is_some();
    let original_valid = verify_assignment(&generated.circuit.r1cs, &original_assignment);
    let original_output = read_output_matrix(
        &generated.circuit.output_witness_indices,
        &original_assignment,
    );

    let mut transformed_assignment = Assignment::new(generated.input_assignment.clone());
    let _ = execute_circuit(&transformed.optimized, &mut transformed_assignment).is_some();
    let transformed_valid = verify_assignment(&transformed.optimized, &transformed_assignment);
    let transformed_output = read_output_matrix(
        &generated.circuit.output_witness_indices,
        &transformed_assignment,
    );

    TwoMatEvalReport {
        expected_output: generated.expected_output.clone(),
        outputs_match: original_output == generated.expected_output
            && transformed_output == generated.expected_output,
        original_output,
        transformed_output,
        original_valid,
        transformed_valid,
    }
}

pub fn export_circuit(
    generated: &GeneratedTwoMat,
    transformed: &TransformedTwoMat,
) -> Result<TwoMatExportReport, Box<dyn std::error::Error>> {
    export_circuit_with_options(generated, transformed, ExportBundleOptions::default())
}

pub fn export_circuit_with_options(
    generated: &GeneratedTwoMat,
    transformed: &TransformedTwoMat,
    export_options: ExportBundleOptions,
) -> Result<TwoMatExportReport, Box<dyn std::error::Error>> {
    let export = RmsLinearExport::from_r1cs_with_inputs(
        &transformed.optimized,
        &ExportInputConfig::all_private(generated.circuit.r1cs.num_inputs),
    )?
    .with_output_witnesses(
        generated
            .circuit
            .output_witness_indices
            .iter()
            .flatten()
            .copied()
            .collect(),
    );

    write_export_bundle_with_options(&generated.config.export_stem, &export, export_options)
}

pub fn run() {
    run_with_args(&[]).expect("TwoMat 示例失败");
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
        [] => TwoMatRunConfig::demo(),
        [dim] => TwoMatRunConfig::square(parse_positive_usize_arg("dim", dim)?),
        _ => return Err(usage_text().to_string()),
    };

    run_with_config(config, export_options)
}

fn run_with_config(
    config: TwoMatRunConfig,
    export_options: ExportBundleOptions,
) -> Result<(), String> {
    let generated = generate_circuit(config);
    let transformed = transform_circuit(&generated);
    let evaluation = evaluate_equivalence(&generated, &transformed);
    let export = export_circuit_with_options(&generated, &transformed, export_options)
        .map_err(|err| format!("导出 TwoMat RMS 电路失败: {err}"))?;

    println!("\n╔══════════════════════════════════════════════════╗");
    println!("║  TwoMat：两个私有矩阵相乘                        ║");
    println!("╚══════════════════════════════════════════════════╝\n");

    println!("【1. 生成电路】");
    println!(
        "  维度: {} x {} 乘 {} x {}",
        generated.config.dim, generated.config.dim, generated.config.dim, generated.config.dim
    );
    println!("  私有输入索引:");
    print_index_matrix("M1", "x", &generated.circuit.left_input_indices);
    print_index_matrix("M2", "x", &generated.circuit.right_input_indices);
    println!("  输出 witness:");
    print_index_matrix("P", "w", &generated.circuit.output_witness_indices);
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
    println!("  私有输入样例:");
    print_value_matrix("M1", &generated.config.left_values);
    print_value_matrix("M2", &generated.config.right_values);
    println!("  期望输出:");
    print_value_matrix("Expected", &evaluation.expected_output);
    println!("  原始电路输出:");
    print_value_matrix("R1CS", &evaluation.original_output);
    println!("  转换后电路输出:");
    print_value_matrix("RMS+CSE", &evaluation.transformed_output);
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
    println!("  前 5 条最终 RMS 约束:");
    let exported_bin = load_r1cs_from_bin(&export.bin_path).expect("读取 BIN 导出文件失败");
    for constraint in exported_bin.constraints.iter().take(5) {
        println!(
            "    step {:>2}: ({} ) * ({} ) -> w{}",
            constraint.index,
            terms_to_export_string(&constraint.a_in, "x"),
            terms_to_export_string(&constraint.b_wit, "w"),
            constraint.output_witness
        );
    }

    println!("\n【前 5 条原始约束预览】");
    let original_preview = R1CS {
        num_inputs: generated.circuit.r1cs.num_inputs,
        num_witnesses: generated.circuit.r1cs.num_witnesses,
        constraints: generated
            .circuit
            .r1cs
            .constraints
            .iter()
            .take(5)
            .cloned()
            .collect(),
        origin: generated.circuit.r1cs.origin.clone(),
    };
    print_constraints(&original_preview);

    Ok(())
}

fn print_index_matrix(name: &str, prefix: &str, matrix: &[Vec<usize>]) {
    print_preview_matrix(name, matrix, |index| format!("{}{}", prefix, index));
}

fn print_value_matrix(name: &str, matrix: &[Vec<u64>]) {
    print_preview_matrix(name, matrix, |value| format!("{:>4}", value));
}

fn build_matrix_inputs(
    left_indices: &[Vec<usize>],
    right_indices: &[Vec<usize>],
    left_values: &[Vec<u64>],
    right_values: &[Vec<u64>],
) -> Vec<(usize, u64)> {
    let mut inputs = Vec::new();

    for (index_row, value_row) in left_indices.iter().zip(left_values.iter()) {
        for (input_idx, value) in index_row.iter().zip(value_row.iter()) {
            inputs.push((*input_idx, *value));
        }
    }

    for (index_row, value_row) in right_indices.iter().zip(right_values.iter()) {
        for (input_idx, value) in index_row.iter().zip(value_row.iter()) {
            inputs.push((*input_idx, *value));
        }
    }

    inputs
}

fn build_demo_matrix(rows: usize, cols: usize, start: u64) -> Vec<Vec<u64>> {
    let mut next = start;
    let mut matrix = vec![vec![0; cols]; rows];

    for row in &mut matrix {
        for value in row {
            *value = next;
            next = next.wrapping_add(1);
        }
    }

    matrix
}

fn validate_matrix_shape(matrix: &[Vec<u64>], rows: usize, cols: usize, name: &str) {
    assert_eq!(matrix.len(), rows, "{} 行数不匹配", name);
    assert!(
        matrix.iter().all(|row| row.len() == cols),
        "{} 列数不匹配",
        name
    );
}

fn read_output_matrix(output_witnesses: &[Vec<usize>], assignment: &Assignment) -> Vec<Vec<u64>> {
    output_witnesses
        .iter()
        .map(|row| {
            row.iter()
                .map(|witness_idx| {
                    fr_to_u64(&assignment.witnesses[witness_idx]).expect("矩阵输出超出 u64")
                })
                .collect()
        })
        .collect()
}

fn multiply_matrices(left: &[Vec<u64>], right: &[Vec<u64>]) -> Vec<Vec<u64>> {
    let rows = left.len();
    let shared = left.first().map(|row| row.len()).unwrap_or(0);
    let cols = right.first().map(|row| row.len()).unwrap_or(0);

    assert!(rows > 0 && shared > 0 && cols > 0, "矩阵不能为空");
    assert_eq!(right.len(), shared, "矩阵维度不匹配");

    let mut result = vec![vec![0u64; cols]; rows];
    for i in 0..rows {
        for j in 0..cols {
            let mut acc = 0u64;
            for k in 0..shared {
                acc = acc.wrapping_add(left[i][k].wrapping_mul(right[k][j]));
            }
            result[i][j] = acc;
        }
    }
    result
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
  cargo run -- twomat [--json]
  cargo run -- twomat <dim> [--json]

说明:
  默认值: 4x4 乘 4x4。
  两个操作数 M1、M2 都是私有 n x n 矩阵输入。
  默认只导出 .bin；追加 --json 时同时导出 .json。"
}

#[cfg(test)]
mod circuit_tests {
    use super::*;
    use crate::r1cs::RmsLinearExport;

    #[test]
    fn two_mat_2x2_transforms_to_rms_and_preserves_output() {
        let circuit = generate_two_mat_r1cs(2);
        let transformed = choudhuri_transform(&circuit.r1cs);
        let (optimized, _) = eliminate_common_subexpressions(&transformed.r1cs);

        assert!(optimized
            .constraints
            .iter()
            .all(|constraint| constraint.is_rms_compatible()));

        let left = vec![vec![1, 2], vec![3, 4]];
        let right = vec![vec![5, 6], vec![7, 8]];
        let generated = generate_circuit(TwoMatRunConfig {
            dim: 2,
            left_values: left,
            right_values: right,
            export_stem: "data/two_mat_test".to_string(),
        });
        let transformed = transform_circuit(&generated);
        let evaluation = evaluate_equivalence(&generated, &transformed);

        assert!(evaluation.original_valid);
        assert!(evaluation.transformed_valid);
        assert!(evaluation.outputs_match);
        assert_eq!(evaluation.expected_output, vec![vec![19, 22], vec![43, 50]]);
    }

    #[test]
    fn export_marks_both_matrices_private() {
        let generated = generate_circuit(TwoMatRunConfig::square(3));
        let transformed = transform_circuit(&generated);
        let export = RmsLinearExport::from_r1cs_with_inputs(
            &transformed.optimized,
            &ExportInputConfig::all_private(generated.circuit.r1cs.num_inputs),
        )
        .expect("导出带输入元数据的 RMS 失败")
        .with_output_witnesses(
            generated
                .circuit
                .output_witness_indices
                .iter()
                .flatten()
                .copied()
                .collect(),
        );

        assert_eq!(export.num_public_inputs, 1);
        assert_eq!(export.public_inputs[0].index, 0);
        assert_eq!(export.public_inputs[0].value, "1");
        assert_eq!(export.num_private_inputs, 18);
        assert_eq!(
            export.private_inputs,
            (1usize..=18usize).collect::<Vec<_>>()
        );
        assert_eq!(
            export.output_witnesses,
            generated
                .circuit
                .output_witness_indices
                .iter()
                .flatten()
                .copied()
                .collect::<Vec<_>>()
        );
    }
}

#[cfg(test)]
mod pipeline_tests {
    use super::*;

    #[test]
    fn two_mat_demo_pipeline_keeps_output_after_transform() {
        let generated = generate_circuit(TwoMatRunConfig::demo());
        let transformed = transform_circuit(&generated);
        let evaluation = evaluate_equivalence(&generated, &transformed);

        assert!(evaluation.original_valid);
        assert!(evaluation.transformed_valid);
        assert!(evaluation.outputs_match);
        assert_eq!(evaluation.original_output, evaluation.expected_output);
        assert_eq!(evaluation.transformed_output, evaluation.expected_output);
    }
}
