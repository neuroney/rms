use crate::evalr1cs::{execute_circuit, verify_assignment, Assignment};
use crate::export::{
    export_r1cs_bundle_with_inputs, load_r1cs_from_json, terms_to_export_string, ExportInputConfig,
    WrittenArtifacts,
};
use crate::r1cs::{Constraint, LinComb, Variable, R1CS};
use crate::transform::{choudhuri_transform, eliminate_common_subexpressions, TransformResult};
use crate::utils::{fr_to_u64, print_constraints};

#[derive(Clone, Debug)]
pub struct MatrixMulCircuit {
    pub r1cs: R1CS,
    pub left_input_indices: Vec<Vec<usize>>,
    pub right_input_indices: Vec<Vec<usize>>,
    pub output_witness_indices: Vec<Vec<usize>>,
}

#[derive(Clone, Debug)]
pub struct MatrixMulRunConfig {
    pub rows: usize,
    pub shared: usize,
    pub cols: usize,
    pub left_values: Vec<Vec<u64>>,
    pub right_values: Vec<Vec<u64>>,
    pub export_stem: String,
}

#[derive(Clone, Debug)]
pub struct GeneratedMatrixMul {
    pub config: MatrixMulRunConfig,
    pub circuit: MatrixMulCircuit,
    pub input_assignment: Vec<(usize, u64)>,
    pub expected_output: Vec<Vec<u64>>,
}

#[derive(Clone, Debug)]
pub struct TransformedMatrixMul {
    pub transformed: TransformResult,
    pub optimized: R1CS,
    pub eliminated: usize,
}

#[derive(Clone, Debug)]
pub struct MatrixMulEvalReport {
    pub expected_output: Vec<Vec<u64>>,
    pub original_output: Vec<Vec<u64>>,
    pub transformed_output: Vec<Vec<u64>>,
    pub original_valid: bool,
    pub transformed_valid: bool,
    pub outputs_match: bool,
}

pub type MatrixMulExportReport = WrittenArtifacts;

impl MatrixMulRunConfig {
    pub fn demo() -> Self {
        Self::square(4)
    }

    pub fn square(dim: usize) -> Self {
        Self::rectangular(dim, dim, dim)
    }

    pub fn rectangular(rows: usize, shared: usize, cols: usize) -> Self {
        let left_values = build_demo_matrix(rows, shared, 1);
        let right_values = build_demo_matrix(shared, cols, (rows * shared) as u64 + 1);

        Self {
            rows,
            shared,
            cols,
            left_values,
            right_values,
            export_stem: format!("data/matrix_mul_{}x{}x{}", rows, shared, cols),
        }
    }
}

pub fn generate_matrix_mul_r1cs(rows: usize, shared: usize, cols: usize) -> MatrixMulCircuit {
    assert!(rows > 0, "左矩阵行数必须大于 0");
    assert!(shared > 0, "矩阵内积维度必须大于 0");
    assert!(cols > 0, "右矩阵列数必须大于 0");

    let num_inputs = 1 + rows * shared + shared * cols;
    let mut r1cs = R1CS::new(num_inputs, 0);

    let mut next_input = 1usize;
    let mut left_input_indices = vec![vec![0; shared]; rows];
    for row in &mut left_input_indices {
        for input_idx in row.iter_mut() {
            *input_idx = next_input;
            next_input += 1;
        }
    }

    let mut right_input_indices = vec![vec![0; cols]; shared];
    for row in &mut right_input_indices {
        for input_idx in row.iter_mut() {
            *input_idx = next_input;
            next_input += 1;
        }
    }

    let mut next_w = 2usize;
    let mut output_witness_indices = vec![vec![0; cols]; rows];

    for i in 0..rows {
        for j in 0..cols {
            let mut product_witnesses = Vec::with_capacity(shared);

            for k in 0..shared {
                let out_w = next_w;
                next_w += 1;
                r1cs.add_constraint(
                    Constraint {
                        a: LinComb::from_var(Variable::Input(left_input_indices[i][k])),
                        b: LinComb::from_var(Variable::Input(right_input_indices[k][j])),
                        c: LinComb::from_var(Variable::Witness(out_w)),
                    },
                    out_w,
                );
                product_witnesses.push(out_w);
            }

            let output_witness = if product_witnesses.len() == 1 {
                product_witnesses[0]
            } else {
                let out_w = next_w;
                next_w += 1;
                r1cs.add_constraint(
                    Constraint {
                        a: LinComb::from_var(Variable::Input(0)),
                        b: LinComb::from_terms(
                            product_witnesses
                                .iter()
                                .map(|witness| (ark_ff::One::one(), Variable::Witness(*witness)))
                                .collect(),
                        ),
                        c: LinComb::from_var(Variable::Witness(out_w)),
                    },
                    out_w,
                );
                out_w
            };

            output_witness_indices[i][j] = output_witness;
        }
    }

    r1cs.num_witnesses = next_w - 1;

    MatrixMulCircuit {
        r1cs,
        left_input_indices,
        right_input_indices,
        output_witness_indices,
    }
}

pub fn generate_circuit(config: MatrixMulRunConfig) -> GeneratedMatrixMul {
    validate_matrix_shape(&config.left_values, config.rows, config.shared, "左矩阵");
    validate_matrix_shape(&config.right_values, config.shared, config.cols, "右矩阵");

    let circuit = generate_matrix_mul_r1cs(config.rows, config.shared, config.cols);
    let input_assignment = build_matrix_inputs(
        &circuit.left_input_indices,
        &circuit.right_input_indices,
        &config.left_values,
        &config.right_values,
    );
    let expected_output = multiply_matrices(&config.left_values, &config.right_values);

    GeneratedMatrixMul {
        config,
        circuit,
        input_assignment,
        expected_output,
    }
}

pub fn transform_circuit(generated: &GeneratedMatrixMul) -> TransformedMatrixMul {
    let transformed = choudhuri_transform(&generated.circuit.r1cs);
    let (optimized, eliminated) = eliminate_common_subexpressions(&transformed.r1cs);

    TransformedMatrixMul {
        transformed,
        optimized,
        eliminated,
    }
}

pub fn evaluate_equivalence(
    generated: &GeneratedMatrixMul,
    transformed: &TransformedMatrixMul,
) -> MatrixMulEvalReport {
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

    MatrixMulEvalReport {
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
    generated: &GeneratedMatrixMul,
    transformed: &TransformedMatrixMul,
) -> Result<MatrixMulExportReport, Box<dyn std::error::Error>> {
    export_r1cs_bundle_with_inputs(
        &transformed.optimized,
        &generated.config.export_stem,
        &ExportInputConfig::all_private(generated.circuit.r1cs.num_inputs),
    )
}

pub fn run() {
    run_with_args(&[]).expect("矩阵乘法示例失败");
}

pub fn run_with_args(args: &[String]) -> Result<(), String> {
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        return Err(usage_text().to_string());
    }

    let config = match args {
        [] => MatrixMulRunConfig::demo(),
        [dim] => MatrixMulRunConfig::square(parse_positive_usize_arg("dim", dim)?),
        [rows, shared, cols] => MatrixMulRunConfig::rectangular(
            parse_positive_usize_arg("rows", rows)?,
            parse_positive_usize_arg("shared", shared)?,
            parse_positive_usize_arg("cols", cols)?,
        ),
        _ => return Err(usage_text().to_string()),
    };

    run_with_config(config)
}

fn run_with_config(config: MatrixMulRunConfig) -> Result<(), String> {
    let generated = generate_circuit(config);
    let transformed = transform_circuit(&generated);
    let evaluation = evaluate_equivalence(&generated, &transformed);
    let export = export_circuit(&generated, &transformed)
        .map_err(|err| format!("导出矩阵乘法 RMS 电路失败: {err}"))?;

    println!("\n╔══════════════════════════════════════════════════╗");
    println!("║  矩阵乘法示例：四阶段审计流程                    ║");
    println!("╚══════════════════════════════════════════════════╝\n");

    println!("【1. 生成电路】");
    println!(
        "  维度: {} x {} 乘 {} x {}",
        generated.config.rows,
        generated.config.shared,
        generated.config.shared,
        generated.config.cols
    );
    println!("  输入索引:");
    print_index_matrix("A", "x", &generated.circuit.left_input_indices);
    print_index_matrix("B", "x", &generated.circuit.right_input_indices);
    println!("  输出 witness:");
    print_index_matrix("C", "w", &generated.circuit.output_witness_indices);
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
    println!("  样例输入:");
    print_value_matrix("A", &generated.config.left_values);
    print_value_matrix("B", &generated.config.right_values);
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
    println!("  JSON: {}", export.json_path);
    println!("  BIN:  {}", export.bin_path);
    println!("  版本: {}", export.version);
    println!("  约束数: {}", export.num_constraints);
    println!("  JSON/BIN 内容一致: {}", export.json_bin_match);
    println!("  前 5 条最终 RMS 约束:");
    let exported_json = load_r1cs_from_json(&export.json_path).expect("读取 JSON 导出文件失败");
    for constraint in exported_json.constraints.iter().take(5) {
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
    println!("    {} =", name);
    for row in matrix {
        let formatted = row
            .iter()
            .map(|index| format!("{}{}", prefix, index))
            .collect::<Vec<_>>()
            .join(", ");
        println!("      [{}]", formatted);
    }
}

fn print_value_matrix(name: &str, matrix: &[Vec<u64>]) {
    println!("    {} =", name);
    for row in matrix {
        let formatted = row
            .iter()
            .map(|value| format!("{:>4}", value))
            .collect::<Vec<_>>()
            .join(", ");
        println!("      [{}]", formatted);
    }
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
  cargo run -- matrix_mul
  cargo run -- matrix_mul <dim>
  cargo run -- matrix_mul <rows> <shared> <cols>
  cargo run --example matrix_mul -- <dim>

说明:
  默认值: 4x4 乘 4x4。
  传 1 个参数时生成方阵；传 3 个参数时生成 rows x shared 与 shared x cols。"
}

#[cfg(test)]
mod circuit_tests {
    use super::*;

    fn build_matrix_assignment(
        circuit: &MatrixMulCircuit,
        left: [[u64; 2]; 2],
        right: [[u64; 2]; 2],
    ) -> Assignment {
        let mut inputs = Vec::new();

        for (i, row) in left.iter().enumerate() {
            for (k, value) in row.iter().enumerate() {
                inputs.push((circuit.left_input_indices[i][k], *value));
            }
        }

        for (k, row) in right.iter().enumerate() {
            for (j, value) in row.iter().enumerate() {
                inputs.push((circuit.right_input_indices[k][j], *value));
            }
        }

        Assignment::new(inputs)
    }

    fn read_matrix_outputs(circuit: &MatrixMulCircuit, assignment: &Assignment) -> Vec<Vec<u64>> {
        circuit
            .output_witness_indices
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

    #[test]
    fn matrix_mul_2x2_transforms_to_rms_and_preserves_output() {
        let circuit = generate_matrix_mul_r1cs(2, 2, 2);
        let transformed = choudhuri_transform(&circuit.r1cs);
        let (optimized, eliminated) = eliminate_common_subexpressions(&transformed.r1cs);

        assert!(optimized
            .constraints
            .iter()
            .all(|constraint| constraint.is_rms_compatible()));
        assert_eq!(transformed.r1cs.constraints.len(), 16);
        assert_eq!(eliminated, 0);
        assert_eq!(optimized.constraints.len(), 16);

        let left = [[1, 2], [3, 4]];
        let right = [[5, 6], [7, 8]];

        let mut original_assignment = build_matrix_assignment(&circuit, left, right);
        assert!(execute_circuit(&circuit.r1cs, &mut original_assignment).is_some());
        assert!(verify_assignment(&circuit.r1cs, &original_assignment));
        let original_outputs = read_matrix_outputs(&circuit, &original_assignment);
        assert_eq!(original_outputs, vec![vec![19, 22], vec![43, 50]]);

        let mut optimized_assignment = build_matrix_assignment(&circuit, left, right);
        assert!(execute_circuit(&optimized, &mut optimized_assignment).is_some());
        assert!(verify_assignment(&optimized, &optimized_assignment));
        let optimized_outputs = read_matrix_outputs(&circuit, &optimized_assignment);
        assert_eq!(optimized_outputs, original_outputs);
    }
}

#[cfg(test)]
mod pipeline_tests {
    use super::*;

    #[test]
    fn matrix_demo_pipeline_keeps_output_after_transform() {
        let generated = generate_circuit(MatrixMulRunConfig::demo());
        let transformed = transform_circuit(&generated);
        let evaluation = evaluate_equivalence(&generated, &transformed);

        assert!(evaluation.original_valid);
        assert!(evaluation.transformed_valid);
        assert!(evaluation.outputs_match);
        assert_eq!(evaluation.original_output, evaluation.expected_output);
        assert_eq!(evaluation.transformed_output, evaluation.expected_output);
    }
}
