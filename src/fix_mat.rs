//! Fixed public matrix times private vector demo circuit and export flow.

use crate::evalr1cs::{execute_circuit, verify_assignment, Assignment};
use crate::export::{
    load_r1cs_from_bin, split_export_cli_args, terms_to_export_string,
    write_export_bundle_with_options, ExportBundleOptions, ExportInputConfig, WrittenArtifacts,
};
use crate::r1cs::{Constraint, LinComb, RmsLinearExport, Variable, R1CS};
use crate::transform::{choudhuri_transform, eliminate_common_subexpressions, TransformResult};
use crate::utils::{
    format_preview_list, fr_to_u64, print_constraints, print_preview_matrix,
    PREVIEW_MAX_VECTOR_ITEMS,
};
use ark_bn254::Fr;

const ZERO_PUBLIC_INPUT_INDEX: usize = 1;
const FIRST_VECTOR_INPUT_INDEX: usize = ZERO_PUBLIC_INPUT_INDEX + 1;

#[derive(Clone, Debug)]
pub struct FixMatCircuit {
    pub r1cs: R1CS,
    pub dim: usize,
    pub vector_input_indices: Vec<usize>,
    pub vector_witness_indices: Vec<usize>,
    pub output_witness_indices: Vec<usize>,
}

#[derive(Clone, Debug)]
pub struct FixMatRunConfig {
    pub dim: usize,
    pub matrix_values: Vec<Vec<u64>>,
    pub vector_values: Vec<u64>,
    pub export_stem: String,
}

#[derive(Clone, Debug)]
pub struct GeneratedFixMat {
    pub config: FixMatRunConfig,
    pub circuit: FixMatCircuit,
    pub input_assignment: Vec<(usize, u64)>,
    pub expected_output: Vec<u64>,
}

#[derive(Clone, Debug)]
pub struct TransformedFixMat {
    pub transformed: TransformResult,
    pub optimized: R1CS,
    pub eliminated: usize,
}

#[derive(Clone, Debug)]
pub struct FixMatEvalReport {
    pub expected_output: Vec<u64>,
    pub original_output: Vec<u64>,
    pub transformed_output: Vec<u64>,
    pub original_valid: bool,
    pub transformed_valid: bool,
    pub outputs_match: bool,
}

pub type FixMatExportReport = WrittenArtifacts;

impl FixMatRunConfig {
    pub fn demo() -> Self {
        Self::square(4)
    }

    pub fn square(dim: usize) -> Self {
        let matrix_values = build_demo_matrix(dim, dim, 1);
        let vector_values = build_demo_vector(dim, (dim * dim) as u64 + 1);

        Self {
            dim,
            matrix_values,
            vector_values,
            export_stem: format!("data/fix_mat_{}x{}", dim, dim),
        }
    }
}

pub fn generate_fix_mat_r1cs(matrix_values: &[Vec<u64>]) -> FixMatCircuit {
    let dim = matrix_values.len();
    assert!(dim > 0, "Matrix dimension must be greater than 0");
    validate_matrix_shape(matrix_values, dim, dim, "fixed matrix M");

    let num_inputs = FIRST_VECTOR_INPUT_INDEX + dim;
    let mut r1cs = R1CS::new(num_inputs, 0);

    let vector_input_indices =
        (FIRST_VECTOR_INPUT_INDEX..FIRST_VECTOR_INPUT_INDEX + dim).collect::<Vec<_>>();

    let mut next_witness = 2usize;
    let zero_witness = next_witness;
    next_witness += 1;
    r1cs.add_constraint(
        Constraint {
            a: LinComb::from_var(Variable::Input(ZERO_PUBLIC_INPUT_INDEX)),
            b: LinComb::from_var(Variable::Witness(1)),
            c: LinComb::from_var(Variable::Witness(zero_witness)),
        },
        zero_witness,
    );

    let mut vector_witness_indices = Vec::with_capacity(dim);
    for &input_idx in &vector_input_indices {
        let witness_idx = next_witness;
        next_witness += 1;
        r1cs.add_constraint(
            Constraint {
                a: LinComb::from_var(Variable::Input(input_idx)),
                b: LinComb::from_var(Variable::Witness(1)),
                c: LinComb::from_var(Variable::Witness(witness_idx)),
            },
            witness_idx,
        );
        vector_witness_indices.push(witness_idx);
    }

    let mut output_witness_indices = Vec::with_capacity(dim);
    for (row_idx, row) in matrix_values.iter().enumerate() {
        let output_witness = next_witness;
        next_witness += 1;
        let mut terms = row
            .iter()
            .enumerate()
            .filter(|(_, coeff)| **coeff != 0)
            .map(|(col_idx, coeff)| {
                (
                    Fr::from(*coeff),
                    Variable::Witness(vector_witness_indices[col_idx]),
                )
            })
            .collect::<Vec<_>>();
        terms.push((
            Fr::from((row_idx + 1) as u64),
            Variable::Witness(zero_witness),
        ));
        r1cs.add_constraint(
            Constraint {
                a: LinComb::from_var(Variable::Input(0)),
                b: LinComb::from_terms(terms),
                c: LinComb::from_var(Variable::Witness(output_witness)),
            },
            output_witness,
        );
        output_witness_indices.push(output_witness);
    }

    r1cs.num_witnesses = next_witness - 1;

    FixMatCircuit {
        r1cs,
        dim,
        vector_input_indices,
        vector_witness_indices,
        output_witness_indices,
    }
}

pub fn generate_circuit(config: FixMatRunConfig) -> GeneratedFixMat {
    validate_matrix_shape(
        &config.matrix_values,
        config.dim,
        config.dim,
        "fixed matrix M",
    );
    validate_vector_shape(&config.vector_values, config.dim, "private vector A");

    let circuit = generate_fix_mat_r1cs(&config.matrix_values);
    let input_assignment =
        build_vector_inputs(&circuit.vector_input_indices, &config.vector_values);
    let expected_output = multiply_matrix_vector(&config.matrix_values, &config.vector_values);

    GeneratedFixMat {
        config,
        circuit,
        input_assignment,
        expected_output,
    }
}

pub fn transform_circuit(generated: &GeneratedFixMat) -> TransformedFixMat {
    let transformed = choudhuri_transform(&generated.circuit.r1cs);
    let (optimized, eliminated) = eliminate_common_subexpressions(&transformed.r1cs);

    TransformedFixMat {
        transformed,
        optimized,
        eliminated,
    }
}

pub fn evaluate_equivalence(
    generated: &GeneratedFixMat,
    transformed: &TransformedFixMat,
) -> FixMatEvalReport {
    let mut original_assignment = Assignment::new(generated.input_assignment.clone());
    let _ = execute_circuit(&generated.circuit.r1cs, &mut original_assignment).is_some();
    let original_valid = verify_assignment(&generated.circuit.r1cs, &original_assignment);
    let original_output = read_output_vector(
        &generated.circuit.output_witness_indices,
        &original_assignment,
    );

    let mut transformed_assignment = Assignment::new(generated.input_assignment.clone());
    let _ = execute_circuit(&transformed.optimized, &mut transformed_assignment).is_some();
    let transformed_valid = verify_assignment(&transformed.optimized, &transformed_assignment);
    let transformed_output = read_output_vector(
        &generated.circuit.output_witness_indices,
        &transformed_assignment,
    );

    FixMatEvalReport {
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
    generated: &GeneratedFixMat,
    transformed: &TransformedFixMat,
) -> Result<FixMatExportReport, Box<dyn std::error::Error>> {
    export_circuit_with_options(generated, transformed, ExportBundleOptions::default())
}

pub fn export_circuit_with_options(
    generated: &GeneratedFixMat,
    transformed: &TransformedFixMat,
    export_options: ExportBundleOptions,
) -> Result<FixMatExportReport, Box<dyn std::error::Error>> {
    let export = RmsLinearExport::from_r1cs_with_inputs(
        &transformed.optimized,
        &fix_mat_export_input_config(generated.circuit.r1cs.num_inputs),
    )?
    .with_output_witnesses(generated.circuit.output_witness_indices.clone());

    write_export_bundle_with_options(&generated.config.export_stem, &export, export_options)
}

pub fn run() {
    run_with_args(&[]).expect("FixMat example failed");
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
        [] => FixMatRunConfig::demo(),
        [dim] => FixMatRunConfig::square(parse_positive_usize_arg("dim", dim)?),
        _ => return Err(usage_text().to_string()),
    };

    run_with_config(config, export_options)
}

fn run_with_config(
    config: FixMatRunConfig,
    export_options: ExportBundleOptions,
) -> Result<(), String> {
    let generated = generate_circuit(config);
    let transformed = transform_circuit(&generated);
    let evaluation = evaluate_equivalence(&generated, &transformed);
    let export = export_circuit_with_options(&generated, &transformed, export_options)
        .map_err(|err| format!("Failed to export FixMat RMS circuit: {err}"))?;

    println!("\n╔══════════════════════════════════════════════════╗");
    println!("║  FixMat: public fixed matrix times private vector ║");
    println!("╚══════════════════════════════════════════════════╝\n");

    println!("[1. Circuit generation]");
    println!(
        "  Dimensions: {} x {} times {}-dimensional vector",
        generated.config.dim, generated.config.dim, generated.config.dim
    );
    println!("  Private input indices:");
    print_index_vector("A", "x", &generated.circuit.vector_input_indices);
    println!("  Internal witness copies:");
    print_index_vector("A'", "w", &generated.circuit.vector_witness_indices);
    println!("  Output witnesses:");
    print_index_vector("M*A", "w", &generated.circuit.output_witness_indices);
    generated.circuit.r1cs.print_stats();

    println!("\n[2. Circuit transformation]");
    transformed.transformed.r1cs.print_stats();
    println!(
        "  Choudhuri blowup factor: {:.2}x",
        transformed.transformed.blowup_factor
    );
    println!(
        "  CSE eliminated duplicate constraints: {}",
        transformed.eliminated
    );
    println!(
        "  Final blowup factor: {:.2}x",
        transformed.optimized.constraints.len() as f64
            / generated.circuit.r1cs.constraints.len() as f64
    );

    println!("\n[3. Eval consistency]");
    println!("  Public fixed matrix M:");
    print_value_matrix("M", &generated.config.matrix_values);
    println!("  Private input vector A:");
    print_value_vector("A", &generated.config.vector_values);
    println!("  Expected output:");
    print_value_vector("Expected", &evaluation.expected_output);
    println!("  Original circuit output:");
    print_value_vector("R1CS", &evaluation.original_output);
    println!("  Transformed circuit output:");
    print_value_vector("RMS+CSE", &evaluation.transformed_output);
    println!(
        "  Outputs match: {}  [constraints satisfied: orig={}, rms+cse={}]",
        evaluation.outputs_match, evaluation.original_valid, evaluation.transformed_valid
    );

    println!("\n[4. Circuit export]");
    println!("  BIN:  {}", export.bin_path);
    if let Some(json_path) = &export.json_path {
        println!("  JSON: {}", json_path);
    }
    println!("  Version: {}", export.version);
    println!("  Constraints: {}", export.num_constraints);
    if let Some(json_bin_match) = export.json_bin_match {
        println!("  JSON/BIN contents match: {}", json_bin_match);
    }
    println!("  First 5 final RMS constraints:");
    let exported_bin =
        load_r1cs_from_bin(&export.bin_path).expect("Failed to read BIN export file");
    for constraint in exported_bin.constraints.iter().take(5) {
        println!(
            "    step {:>2}: ({} ) * ({} ) -> w{}",
            constraint.index,
            terms_to_export_string(&constraint.a_in, "x"),
            terms_to_export_string(&constraint.b_wit, "w"),
            constraint.output_witness
        );
    }

    println!("\n[Preview of the first 5 original constraints]");
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

fn print_index_vector(name: &str, prefix: &str, values: &[usize]) {
    let formatted = format_preview_list(values, PREVIEW_MAX_VECTOR_ITEMS, |index| {
        format!("{}{}", prefix, index)
    });
    println!("    {} = {}", name, formatted);
}

fn print_value_vector(name: &str, values: &[u64]) {
    let formatted = format_preview_list(values, PREVIEW_MAX_VECTOR_ITEMS, |value| {
        format!("{:>4}", value)
    });
    println!("    {} = {}", name, formatted);
}

fn print_value_matrix(name: &str, matrix: &[Vec<u64>]) {
    print_preview_matrix(name, matrix, |value| format!("{:>4}", value));
}

fn build_vector_inputs(indices: &[usize], values: &[u64]) -> Vec<(usize, u64)> {
    let mut inputs = Vec::with_capacity(indices.len() + 1);
    inputs.push((ZERO_PUBLIC_INPUT_INDEX, 0));
    inputs.extend(
        indices
            .iter()
            .zip(values.iter())
            .map(|(&index, &value)| (index, value)),
    );
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

fn build_demo_vector(dim: usize, start: u64) -> Vec<u64> {
    (0..dim).map(|offset| start + offset as u64).collect()
}

fn validate_matrix_shape(matrix: &[Vec<u64>], rows: usize, cols: usize, name: &str) {
    assert_eq!(matrix.len(), rows, "{} row count mismatch", name);
    assert!(
        matrix.iter().all(|row| row.len() == cols),
        "{} column count mismatch",
        name
    );
}

fn validate_vector_shape(vector: &[u64], dim: usize, name: &str) {
    assert_eq!(vector.len(), dim, "{} length mismatch", name);
}

fn read_output_vector(output_witnesses: &[usize], assignment: &Assignment) -> Vec<u64> {
    output_witnesses
        .iter()
        .map(|witness_idx| {
            fr_to_u64(&assignment.witnesses[witness_idx]).expect("Vector output exceeds u64")
        })
        .collect()
}

fn multiply_matrix_vector(matrix: &[Vec<u64>], vector: &[u64]) -> Vec<u64> {
    let dim = matrix.len();
    assert!(dim > 0, "Matrix cannot be empty");
    assert_eq!(
        vector.len(),
        dim,
        "Matrix and vector dimensions do not match"
    );
    validate_matrix_shape(matrix, dim, dim, "fixed matrix M");

    let mut result = vec![0u64; dim];
    for i in 0..dim {
        let mut acc = 0u64;
        for (coeff, value) in matrix[i].iter().zip(vector.iter()) {
            acc = acc.wrapping_add(coeff.wrapping_mul(*value));
        }
        result[i] = acc;
    }
    result
}

fn parse_positive_usize_arg(name: &str, raw: &str) -> Result<usize, String> {
    let value = raw
        .parse::<usize>()
        .map_err(|err| format!("{name} must be a non-negative integer, got {raw:?}: {err}"))?;
    if value == 0 {
        return Err(format!("{name} must be greater than 0"));
    }
    Ok(value)
}

fn fix_mat_export_input_config(num_inputs: usize) -> ExportInputConfig {
    ExportInputConfig::from_public_values(
        num_inputs,
        vec![(ZERO_PUBLIC_INPUT_INDEX, Fr::from(0u64))],
    )
    .expect("fix-mat fixed zero public input should be valid")
}

fn usage_text() -> &'static str {
    "\
Usage:
  cargo run -- fixmat [--json]
  cargo run -- fixmat <dim> [--json]

Notes:
    Default: 4x4 fixed matrix times a 4-dimensional private vector.
    The public fixed matrix M is written into the constraints at setup time; the private input only contains vector A.
    By default only `.bin` is exported; `.bin` contains a zstd-compressed `rms-linear-v3` payload. Append `--json` to also emit `.json`."
}

#[cfg(test)]
mod circuit_tests {
    use super::*;
    use crate::r1cs::RmsLinearExport;

    #[test]
    fn fix_mat_2x2_transforms_to_rms_and_preserves_output() {
        let matrix = vec![vec![1, 2], vec![3, 4]];
        let vector = vec![5, 6];
        let generated = generate_circuit(FixMatRunConfig {
            dim: 2,
            matrix_values: matrix,
            vector_values: vector,
            export_stem: "data/fix_mat_test".to_string(),
        });
        let transformed = transform_circuit(&generated);
        let evaluation = evaluate_equivalence(&generated, &transformed);

        assert!(generated
            .circuit
            .r1cs
            .constraints
            .iter()
            .all(|constraint| constraint.is_rms_compatible()));
        assert!(transformed
            .optimized
            .constraints
            .iter()
            .all(|constraint| constraint.is_rms_compatible()));
        assert!(evaluation.original_valid);
        assert!(evaluation.transformed_valid);
        assert!(evaluation.outputs_match);
        assert_eq!(evaluation.expected_output, vec![17, 39]);
    }

    #[test]
    fn export_marks_only_vector_private() {
        let generated = generate_circuit(FixMatRunConfig::square(4));
        let export = RmsLinearExport::from_r1cs_with_inputs(
            &generated.circuit.r1cs,
            &fix_mat_export_input_config(generated.circuit.r1cs.num_inputs),
        )
        .expect("Failed to export RMS with input metadata")
        .with_output_witnesses(generated.circuit.output_witness_indices.clone());

        assert_eq!(export.num_public_inputs, 2);
        assert_eq!(export.public_inputs[0].index, 0);
        assert_eq!(export.public_inputs[0].value, "1");
        assert_eq!(export.public_inputs[1].index, 1);
        assert_eq!(export.public_inputs[1].value, "0");
        assert_eq!(export.num_private_inputs, 4);
        assert_eq!(export.private_inputs, vec![2, 3, 4, 5]);
        assert_eq!(
            export.output_witnesses,
            generated.circuit.output_witness_indices
        );
    }
}

#[cfg(test)]
mod pipeline_tests {
    use super::*;

    #[test]
    fn fix_mat_demo_pipeline_keeps_output_after_transform() {
        let generated = generate_circuit(FixMatRunConfig::demo());
        let transformed = transform_circuit(&generated);
        let evaluation = evaluate_equivalence(&generated, &transformed);

        assert!(evaluation.original_valid);
        assert!(evaluation.transformed_valid);
        assert!(evaluation.outputs_match);
        assert_eq!(evaluation.original_output, evaluation.expected_output);
        assert_eq!(evaluation.transformed_output, evaluation.expected_output);
    }
}
