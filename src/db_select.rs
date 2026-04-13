//! Public/private database selection demo circuit generation and export pipeline.

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
use ark_ff::One;

pub const DEFAULT_INDEX_BITS: usize = 3;
pub const DEFAULT_NUM_RECORDS: usize = 1usize << DEFAULT_INDEX_BITS;
pub const ZERO_PUBLIC_INPUT_INDEX: usize = 1;
pub const FIRST_INDEX_BIT_INPUT_INDEX: usize = ZERO_PUBLIC_INPUT_INDEX + 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatabaseVisibility {
    Public,
    Private,
}

impl DatabaseVisibility {
    fn label(self) -> &'static str {
        match self {
            Self::Public => "PIR",
            Self::Private => "PrivDB",
        }
    }

    fn export_stem(self, num_records: usize) -> String {
        match self {
            Self::Public => format!("data/pir_db_n{}", num_records),
            Self::Private => format!("data/priv_db_n{}", num_records),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DbSelectCircuit {
    pub r1cs: R1CS,
    pub num_records: usize,
    pub num_index_bits: usize,
    pub index_bit_input_indices: Vec<usize>,
    pub database_input_indices: Vec<usize>,
    pub zero_witness_index: usize,
    pub selector_witness_indices: Vec<usize>,
    pub contribution_witness_indices: Vec<usize>,
    pub output_witness_index: usize,
}

#[derive(Clone, Debug)]
pub struct DbSelectRunConfig {
    pub visibility: DatabaseVisibility,
    pub num_records: usize,
    pub index_value: usize,
    pub index_bits: Vec<u64>,
    pub database_values: Vec<Fr>,
    pub export_stem: String,
}

#[derive(Clone, Debug)]
pub struct GeneratedDbSelect {
    pub config: DbSelectRunConfig,
    pub circuit: DbSelectCircuit,
    pub input_assignment: Vec<(usize, Fr)>,
    pub expected_output: Fr,
}

#[derive(Clone, Debug)]
pub struct TransformedDbSelect {
    pub transformed: TransformResult,
    pub optimized: R1CS,
    pub eliminated: usize,
}

#[derive(Clone, Debug)]
pub struct DbSelectEvalReport {
    pub expected_output: Fr,
    pub original_output: Fr,
    pub transformed_output: Fr,
    pub original_valid: bool,
    pub transformed_valid: bool,
    pub outputs_match: bool,
}

pub type DbSelectExportReport = WrittenArtifacts;

impl DbSelectRunConfig {
    pub fn demo(visibility: DatabaseVisibility) -> Self {
        Self::for_exponent(visibility, DEFAULT_INDEX_BITS)
    }

    pub fn for_records(visibility: DatabaseVisibility, num_records: usize) -> Self {
        assert!(
            num_records >= 2 && num_records.is_power_of_two(),
            "Number of records must be a power of two and at least 2"
        );

        let index_value = num_records / 2 + 1;
        let index_bits = index_to_bits_lsb(index_value, num_index_bits(num_records));
        let database_values = demo_database_values(num_records);

        Self {
            visibility,
            num_records,
            index_value,
            index_bits,
            database_values,
            export_stem: visibility.export_stem(num_records),
        }
    }

    pub fn for_exponent(visibility: DatabaseVisibility, exponent: usize) -> Self {
        let num_records = records_from_exponent(exponent)
            .expect("Record-count exponent must safely convert to 2^x");
        Self::for_records(visibility, num_records)
    }
}

pub fn generate_db_select_r1cs(num_records: usize) -> Result<DbSelectCircuit, String> {
    validate_num_records(num_records)?;

    let num_index_bits = num_index_bits(num_records);
    let index_bit_input_indices = (FIRST_INDEX_BIT_INPUT_INDEX
        ..FIRST_INDEX_BIT_INPUT_INDEX + num_index_bits)
        .collect::<Vec<_>>();
    let first_database_input_index = FIRST_INDEX_BIT_INPUT_INDEX + num_index_bits;
    let database_input_indices =
        (first_database_input_index..first_database_input_index + num_records).collect::<Vec<_>>();

    let num_inputs = first_database_input_index + num_records;
    let mut r1cs = R1CS::new(num_inputs, 0);
    let mut next_witness = 2usize;

    let zero_witness_index = next_witness;
    next_witness += 1;
    r1cs.add_constraint(
        Constraint {
            a: LinComb::from_var(Variable::Input(ZERO_PUBLIC_INPUT_INDEX)),
            b: LinComb::from_var(Variable::Witness(1)),
            c: LinComb::from_var(Variable::Witness(zero_witness_index)),
        },
        zero_witness_index,
    );

    let mut selector_witness_indices = Vec::with_capacity(num_records);
    let mut contribution_witness_indices = Vec::with_capacity(num_records);

    for (record_index, &database_input_index) in database_input_indices.iter().enumerate() {
        let record_bits = index_to_bits_lsb(record_index, num_index_bits);
        let selector_witness = build_selector_chain(
            &mut r1cs,
            &mut next_witness,
            &index_bit_input_indices,
            &record_bits,
        );
        selector_witness_indices.push(selector_witness);

        let contribution_witness = next_witness;
        next_witness += 1;
        r1cs.add_constraint(
            Constraint {
                a: LinComb::from_var(Variable::Input(database_input_index)),
                b: LinComb::from_var(Variable::Witness(selector_witness)),
                c: LinComb::from_var(Variable::Witness(contribution_witness)),
            },
            contribution_witness,
        );
        contribution_witness_indices.push(contribution_witness);
    }

    let output_witness_index = next_witness;
    next_witness += 1;
    r1cs.add_constraint(
        Constraint {
            a: LinComb::from_var(Variable::Input(0)),
            b: witness_sum_lincomb(&contribution_witness_indices),
            c: LinComb::from_var(Variable::Witness(output_witness_index)),
        },
        output_witness_index,
    );

    r1cs.num_witnesses = next_witness - 1;

    Ok(DbSelectCircuit {
        r1cs,
        num_records,
        num_index_bits,
        index_bit_input_indices,
        database_input_indices,
        zero_witness_index,
        selector_witness_indices,
        contribution_witness_indices,
        output_witness_index,
    })
}

pub fn generate_circuit(config: DbSelectRunConfig) -> Result<GeneratedDbSelect, String> {
    validate_config(&config)?;

    let circuit = generate_db_select_r1cs(config.num_records)?;
    let input_assignment = build_input_assignment(
        &circuit.index_bit_input_indices,
        &config.index_bits,
        &circuit.database_input_indices,
        &config.database_values,
    );
    let expected_output = config.database_values[config.index_value];

    Ok(GeneratedDbSelect {
        config,
        circuit,
        input_assignment,
        expected_output,
    })
}

pub fn transform_circuit(generated: &GeneratedDbSelect) -> TransformedDbSelect {
    let transformed = choudhuri_transform(&generated.circuit.r1cs);
    let (optimized, eliminated) = eliminate_common_subexpressions_preserving_witnesses(
        &transformed.r1cs,
        &[generated.circuit.output_witness_index],
    );

    TransformedDbSelect {
        transformed,
        optimized,
        eliminated,
    }
}

pub fn evaluate_equivalence(
    generated: &GeneratedDbSelect,
    transformed: &TransformedDbSelect,
) -> DbSelectEvalReport {
    let mut original_assignment = Assignment::from_field_inputs(generated.input_assignment.clone());
    let _ = execute_circuit(&generated.circuit.r1cs, &mut original_assignment).is_some();
    let original_valid = verify_assignment(&generated.circuit.r1cs, &original_assignment);
    let original_output = original_assignment.witnesses[&generated.circuit.output_witness_index];

    let mut transformed_assignment =
        Assignment::from_field_inputs(generated.input_assignment.clone());
    let _ = execute_circuit(&transformed.optimized, &mut transformed_assignment).is_some();
    let transformed_valid = verify_assignment(&transformed.optimized, &transformed_assignment);
    let transformed_output =
        transformed_assignment.witnesses[&generated.circuit.output_witness_index];

    DbSelectEvalReport {
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
    generated: &GeneratedDbSelect,
    transformed: &TransformedDbSelect,
) -> Result<DbSelectExportReport, Box<dyn std::error::Error>> {
    export_circuit_with_options(generated, transformed, ExportBundleOptions::default())
}

pub fn export_circuit_with_options(
    generated: &GeneratedDbSelect,
    transformed: &TransformedDbSelect,
    export_options: ExportBundleOptions,
) -> Result<DbSelectExportReport, Box<dyn std::error::Error>> {
    let input_config = export_input_config(generated)?;
    let export = RmsLinearExport::from_r1cs_with_inputs(&transformed.optimized, &input_config)?
        .with_output_witnesses(vec![generated.circuit.output_witness_index]);

    write_export_bundle_with_options(&generated.config.export_stem, &export, export_options)
}

pub fn run_pir() {
    run_pir_with_args(&[]).expect("PIR example failed");
}

pub fn run_private() {
    run_priv_with_args(&[]).expect("PrivDB example failed");
}

pub fn run_pir_with_args(args: &[String]) -> Result<(), String> {
    run_with_args(DatabaseVisibility::Public, args)
}

pub fn run_priv_with_args(args: &[String]) -> Result<(), String> {
    run_with_args(DatabaseVisibility::Private, args)
}

fn run_with_args(visibility: DatabaseVisibility, args: &[String]) -> Result<(), String> {
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        return Err(usage_text(visibility).to_string());
    }

    let (args, export_options) = split_export_cli_args(args);
    let config = match args.as_slice() {
        [] => DbSelectRunConfig::demo(visibility),
        [exponent] => DbSelectRunConfig::for_exponent(visibility, parse_usize_arg("x", exponent)?),
        _ => return Err(usage_text(visibility).to_string()),
    };

    run_with_config(config, export_options)
}

fn run_with_config(
    config: DbSelectRunConfig,
    export_options: ExportBundleOptions,
) -> Result<(), String> {
    let generated = generate_circuit(config)?;
    let transformed = transform_circuit(&generated);
    let evaluation = evaluate_equivalence(&generated, &transformed);
    let export =
        export_circuit_with_options(&generated, &transformed, export_options).map_err(|err| {
            format!(
                "Failed to export {} RMS circuit: {err}",
                generated.config.visibility.label()
            )
        })?;

    println!("\n╔══════════════════════════════════════════════════╗");
    println!(
        "║  {:<46}║",
        format!(
            "{}: database selection by address selector",
            generated.config.visibility.label()
        )
    );
    println!("╚══════════════════════════════════════════════════╝\n");

    println!("[1. Circuit generation]");
    println!("  Mode: {}", generated.config.visibility.label());
    println!("  Record count n: {}", generated.config.num_records);
    println!("  Address bit width: {}", generated.circuit.num_index_bits);
    println!(
        "  Selected index i: {} (bits: {})",
        generated.config.index_value,
        format_bits_msb(&generated.config.index_bits)
    );
    println!(
        "  Database preview: {}",
        format_preview_list(&generated.config.database_values, 8, coeff_to_string)
    );
    println!(
        "  selector witness: {}",
        format_preview_list(&generated.circuit.selector_witness_indices, 8, |index| {
            format!("w{}", index)
        })
    );
    println!(
        "  contribution witness: {}",
        format_preview_list(
            &generated.circuit.contribution_witness_indices,
            8,
            |index| { format!("w{}", index) }
        )
    );
    println!(
        "  Output witness: w{}",
        generated.circuit.output_witness_index
    );
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
    println!(
        "  Expected output: {}",
        coeff_to_string(&evaluation.expected_output)
    );
    println!(
        "  Original circuit output: {}",
        coeff_to_string(&evaluation.original_output)
    );
    println!(
        "  Transformed circuit output: {}",
        coeff_to_string(&evaluation.transformed_output)
    );
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
    println!("  First 8 final RMS constraints:");
    let exported_bin =
        load_r1cs_from_bin(&export.bin_path).expect("Failed to read BIN export file");
    for constraint in exported_bin.constraints.iter().take(8) {
        println!(
            "    step {:>2}: ({} ) * ({} ) -> w{}",
            constraint.index,
            terms_to_export_string(&constraint.a_in, "x"),
            terms_to_export_string(&constraint.b_wit, "w"),
            constraint.output_witness
        );
    }

    println!("\n[Preview of the first 8 original constraints]");
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

fn validate_num_records(num_records: usize) -> Result<(), String> {
    if num_records < 2 {
        return Err("num_records must be >= 2".to_string());
    }
    if !num_records.is_power_of_two() {
        return Err(format!("num_records={num_records} must be a power of two"));
    }
    Ok(())
}

fn validate_config(config: &DbSelectRunConfig) -> Result<(), String> {
    validate_num_records(config.num_records)?;

    let num_bits = num_index_bits(config.num_records);
    if config.index_value >= config.num_records {
        return Err(format!(
            "index_value={} exceeds address range [0, {})",
            config.index_value, config.num_records
        ));
    }
    if config.index_bits.len() != num_bits {
        return Err(format!(
            "index_bits length should be {}, got {}",
            num_bits,
            config.index_bits.len()
        ));
    }
    if config.database_values.len() != config.num_records {
        return Err(format!(
            "database_values length should be {}, got {}",
            config.num_records,
            config.database_values.len()
        ));
    }
    if let Some((bit_idx, value)) = config
        .index_bits
        .iter()
        .enumerate()
        .find(|(_, value)| **value > 1)
    {
        return Err(format!(
            "index_bits[{bit_idx}] = {value} is not a valid bit (must be 0 or 1)"
        ));
    }

    let decoded = bits_to_index_lsb(&config.index_bits);
    if decoded != config.index_value {
        return Err(format!(
            "index_bits decode to address {}, which does not match index_value={}",
            decoded, config.index_value
        ));
    }

    Ok(())
}

fn export_input_config(
    generated: &GeneratedDbSelect,
) -> Result<ExportInputConfig, Box<dyn std::error::Error>> {
    match generated.config.visibility {
        DatabaseVisibility::Public => {
            let mut public_inputs = vec![(ZERO_PUBLIC_INPUT_INDEX, Fr::from(0u64))];
            public_inputs.extend(
                generated
                    .circuit
                    .database_input_indices
                    .iter()
                    .zip(generated.config.database_values.iter())
                    .map(|(&input_idx, &value)| (input_idx, value)),
            );
            Ok(ExportInputConfig::from_public_values(
                generated.circuit.r1cs.num_inputs,
                public_inputs,
            )?)
        }
        DatabaseVisibility::Private => Ok(ExportInputConfig::from_public_values(
            generated.circuit.r1cs.num_inputs,
            vec![(ZERO_PUBLIC_INPUT_INDEX, Fr::from(0u64))],
        )?),
    }
}

fn build_input_assignment(
    index_bit_input_indices: &[usize],
    index_bits: &[u64],
    database_input_indices: &[usize],
    database_values: &[Fr],
) -> Vec<(usize, Fr)> {
    let mut assignment =
        Vec::with_capacity(1 + index_bit_input_indices.len() + database_input_indices.len());
    assignment.push((ZERO_PUBLIC_INPUT_INDEX, Fr::from(0u64)));

    for (&input_idx, &bit) in index_bit_input_indices.iter().zip(index_bits.iter()) {
        assignment.push((input_idx, Fr::from(bit)));
    }

    for (&input_idx, &value) in database_input_indices.iter().zip(database_values.iter()) {
        assignment.push((input_idx, value));
    }

    assignment
}

fn build_selector_chain(
    r1cs: &mut R1CS,
    next_witness: &mut usize,
    index_bit_input_indices: &[usize],
    record_bits: &[u64],
) -> usize {
    assert_eq!(
        index_bit_input_indices.len(),
        record_bits.len(),
        "selector bit width mismatch"
    );

    if index_bit_input_indices.len() == 1 {
        let selector_witness = *next_witness;
        *next_witness += 1;
        r1cs.add_constraint(
            Constraint {
                a: selector_literal_lincomb(index_bit_input_indices[0], record_bits[0]),
                b: LinComb::from_var(Variable::Witness(1)),
                c: LinComb::from_var(Variable::Witness(selector_witness)),
            },
            selector_witness,
        );
        return selector_witness;
    }

    let first_witness = *next_witness;
    *next_witness += 1;
    r1cs.add_constraint(
        Constraint {
            a: selector_literal_lincomb(index_bit_input_indices[0], record_bits[0]),
            b: selector_literal_lincomb(index_bit_input_indices[1], record_bits[1]),
            c: LinComb::from_var(Variable::Witness(first_witness)),
        },
        first_witness,
    );

    let mut acc = first_witness;
    for (&bit_input_index, &record_bit) in index_bit_input_indices
        .iter()
        .zip(record_bits.iter())
        .skip(2)
    {
        let out = *next_witness;
        *next_witness += 1;
        r1cs.add_constraint(
            Constraint {
                a: selector_literal_lincomb(bit_input_index, record_bit),
                b: LinComb::from_var(Variable::Witness(acc)),
                c: LinComb::from_var(Variable::Witness(out)),
            },
            out,
        );
        acc = out;
    }

    acc
}

fn selector_literal_lincomb(bit_input_index: usize, record_bit: u64) -> LinComb {
    match record_bit {
        0 => bit_complement_lincomb(bit_input_index),
        1 => LinComb::from_var(Variable::Input(bit_input_index)),
        _ => panic!("record bit must be 0 or 1"),
    }
}

fn bit_complement_lincomb(bit_input_index: usize) -> LinComb {
    LinComb::from_terms(vec![
        (Fr::one(), Variable::Input(0)),
        (-Fr::one(), Variable::Input(bit_input_index)),
    ])
}

fn witness_sum_lincomb(witness_indices: &[usize]) -> LinComb {
    LinComb::from_terms(
        witness_indices
            .iter()
            .map(|&witness_idx| (Fr::one(), Variable::Witness(witness_idx)))
            .collect(),
    )
}

fn demo_database_values(num_records: usize) -> Vec<Fr> {
    (0..num_records)
        .map(|record_idx| Fr::from((record_idx as u64 + 1) * 17))
        .collect()
}

fn num_index_bits(num_records: usize) -> usize {
    num_records.trailing_zeros() as usize
}

fn index_to_bits_lsb(index_value: usize, num_bits: usize) -> Vec<u64> {
    (0..num_bits)
        .map(|bit_idx| ((index_value >> bit_idx) & 1) as u64)
        .collect()
}

fn bits_to_index_lsb(bits: &[u64]) -> usize {
    bits.iter().enumerate().fold(0usize, |acc, (bit_idx, bit)| {
        acc | ((*bit as usize) << bit_idx)
    })
}

fn format_bits_msb(bits: &[u64]) -> String {
    bits.iter()
        .rev()
        .map(|bit| bit.to_string())
        .collect::<Vec<_>>()
        .join("")
}

fn parse_usize_arg(name: &str, raw: &str) -> Result<usize, String> {
    raw.parse::<usize>()
        .map_err(|err| format!("{name} must be a non-negative integer, got {raw:?}: {err}"))
}

fn records_from_exponent(exponent: usize) -> Result<usize, String> {
    let shift = u32::try_from(exponent)
        .map_err(|_| format!("x={exponent} is too large to convert to a shift amount"))?;
    1usize
        .checked_shl(shift)
        .ok_or_else(|| format!("x={exponent} is too large, num_records = 2^x overflows usize"))
}

fn usage_text(visibility: DatabaseVisibility) -> &'static str {
    match visibility {
        DatabaseVisibility::Public => {
            "\
Usage:
  cargo run -- pir [--json]
  cargo run -- pir <x> [--json]

Notes:
    PIR: private address selection over a public database; internal addresses are encoded as 0..n-1, with n = 2^x.
    By default only `.bin` is exported; `.bin` contains a zstd-compressed `rms-linear-v3` payload. Append `--json` to also emit `.json`."
        }
        DatabaseVisibility::Private => {
            "\
Usage:
  cargo run -- privdb [--json]
  cargo run -- privdb <x> [--json]

Notes:
    PrivDB: private address selection over a private database; internal addresses are encoded as 0..n-1, with n = 2^x.
    By default only `.bin` is exported; `.bin` contains a zstd-compressed `rms-linear-v3` payload. Append `--json` to also emit `.json`."
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r1cs::RmsLinearExport;

    #[test]
    fn db_select_shape_matches_formula_for_eight_records() {
        let circuit = generate_db_select_r1cs(8).expect("db select circuit");

        assert_eq!(circuit.num_index_bits, 3);
        assert_eq!(circuit.r1cs.num_inputs, 13);
        assert_eq!(circuit.zero_witness_index, 2);
        assert_eq!(circuit.selector_witness_indices.len(), 8);
        assert_eq!(circuit.contribution_witness_indices.len(), 8);
        assert_eq!(circuit.output_witness_index, 27);
        assert_eq!(circuit.r1cs.constraints.len(), 26);
        assert_eq!(circuit.r1cs.num_witnesses, 27);
    }

    #[test]
    fn pir_transform_preserves_selected_record() {
        let generated = generate_circuit(DbSelectRunConfig::for_records(
            DatabaseVisibility::Public,
            8,
        ))
        .expect("generated");
        let transformed = transform_circuit(&generated);
        let evaluation = evaluate_equivalence(&generated, &transformed);

        assert!(evaluation.original_valid);
        assert!(evaluation.transformed_valid);
        assert!(evaluation.outputs_match);
        assert_eq!(
            evaluation.expected_output,
            generated.config.database_values[5]
        );
        assert!(transformed
            .optimized
            .constraints
            .iter()
            .all(|constraint| constraint.is_rms_compatible()));
    }

    #[test]
    fn privdb_transform_preserves_selected_record() {
        let generated = generate_circuit(DbSelectRunConfig::for_records(
            DatabaseVisibility::Private,
            8,
        ))
        .expect("generated");
        let transformed = transform_circuit(&generated);
        let evaluation = evaluate_equivalence(&generated, &transformed);

        assert!(evaluation.original_valid);
        assert!(evaluation.transformed_valid);
        assert!(evaluation.outputs_match);
        assert_eq!(
            evaluation.expected_output,
            generated.config.database_values[5]
        );
    }

    #[test]
    fn pir_export_marks_database_public() {
        let generated = generate_circuit(DbSelectRunConfig::for_records(
            DatabaseVisibility::Public,
            8,
        ))
        .expect("generated");
        let transformed = transform_circuit(&generated);
        let export = RmsLinearExport::from_r1cs_with_inputs(
            &transformed.optimized,
            &export_input_config(&generated).expect("export config"),
        )
        .expect("export")
        .with_output_witnesses(vec![generated.circuit.output_witness_index]);

        assert_eq!(export.num_public_inputs, 10);
        assert_eq!(export.num_private_inputs, 3);
        assert_eq!(export.private_inputs, vec![2, 3, 4]);
        assert_eq!(
            export.output_witnesses,
            vec![generated.circuit.output_witness_index]
        );
    }

    #[test]
    fn privdb_export_marks_database_private() {
        let generated = generate_circuit(DbSelectRunConfig::for_records(
            DatabaseVisibility::Private,
            8,
        ))
        .expect("generated");
        let transformed = transform_circuit(&generated);
        let export = RmsLinearExport::from_r1cs_with_inputs(
            &transformed.optimized,
            &export_input_config(&generated).expect("export config"),
        )
        .expect("export")
        .with_output_witnesses(vec![generated.circuit.output_witness_index]);

        assert_eq!(export.num_public_inputs, 2);
        assert_eq!(export.num_private_inputs, 11);
        assert_eq!(export.private_inputs, (2..13).collect::<Vec<_>>());
        assert_eq!(
            export.output_witnesses,
            vec![generated.circuit.output_witness_index]
        );
    }
}
