//! Public Circom workflow orchestration: import, transform, evaluate, and export.

pub use crate::circom_reader::{
    default_sym_path_for_r1cs, import_circom_constraints_json, import_circom_file,
    import_circom_r1cs, load_circom_sym, optimize_circom_r1cs, CircomImportFormat, CircomSymEntry,
    CircomSymbolTable, ImportedCircomCircuit, ImportedCircomLayout,
};
use crate::evalr1cs::{execute_circuit, verify_assignment, Assignment};
use crate::export::{
    load_r1cs_from_bin, split_export_cli_args, terms_to_export_string,
    write_export_bundle_with_options, ExportBundleOptions, ExportInputConfig, WrittenArtifacts,
};
use crate::r1cs::{RmsLinearExport, R1CS};
use crate::transform::{eliminate_common_subexpressions, try_choudhuri_transform, TransformResult};
use crate::utils::{coeff_to_string, print_constraints};
use ark_bn254::Fr;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::thread;

#[derive(Clone, Debug)]
pub struct CircomRunArtifacts {
    pub user_path: PathBuf,
    pub import_path: PathBuf,
    pub source_path: Option<PathBuf>,
    pub format: CircomImportFormat,
    pub compiled_from_source: bool,
    pub sym_path: Option<PathBuf>,
    pub wasm_path: Option<PathBuf>,
    pub input_json_path: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct GeneratedCircom {
    pub artifacts: CircomRunArtifacts,
    pub imported: ImportedCircomCircuit,
    pub symbols: Option<CircomSymbolTable>,
}

#[derive(Clone, Debug)]
pub struct TransformedCircom {
    pub transformed: TransformResult,
    pub optimized: R1CS,
    pub eliminated: usize,
}

#[derive(Clone, Debug)]
pub struct SignalValue {
    pub signal_id: usize,
    pub name: Option<String>,
    pub value: Fr,
}

#[derive(Clone, Debug)]
pub struct CircomEvalReport {
    pub attempted: bool,
    pub skipped_reason: Option<String>,
    pub original_valid: bool,
    pub transformed_valid: bool,
    pub outputs_match: bool,
    pub input_values: Vec<SignalValue>,
    pub expected_outputs: Vec<SignalValue>,
    pub original_outputs: Vec<SignalValue>,
    pub transformed_outputs: Vec<SignalValue>,
    pub witness_source: Option<String>,
}

pub type CircomExportReport = WrittenArtifacts;

#[derive(Clone, Debug)]
struct ExternalCommand {
    program: PathBuf,
    prefix_args: Vec<String>,
}

pub fn generate_circuit(path: &str) -> GeneratedCircom {
    let artifacts = resolve_artifacts(Path::new(path)).expect("Failed to resolve Circom artifacts");
    let import_path = artifacts.import_path.clone();
    let (imported, format) = run_on_large_stack("circom-import", move || {
        import_circom_file(&import_path).expect("Failed to import Circom file")
    });
    let symbols = artifacts
        .sym_path
        .as_ref()
        .and_then(|sym_path| load_circom_sym(sym_path).ok());

    GeneratedCircom {
        artifacts: CircomRunArtifacts {
            format,
            ..artifacts
        },
        imported,
        symbols,
    }
}

pub fn transform_circuit(generated: &GeneratedCircom) -> Result<TransformedCircom, String> {
    let normalized = generated.imported.normalized_r1cs.clone();
    let result = run_on_large_stack("circom-transform", move || {
        try_choudhuri_transform(&normalized).map(|transformed| {
            let (optimized, eliminated) = eliminate_common_subexpressions(&transformed.r1cs);
            (transformed, optimized, eliminated)
        })
    });
    let (transformed, optimized, eliminated) = result.map_err(|err| err.to_string())?;

    Ok(TransformedCircom {
        transformed,
        optimized,
        eliminated,
    })
}

pub fn evaluate_equivalence(
    generated: &GeneratedCircom,
    transformed: &TransformedCircom,
) -> CircomEvalReport {
    let witness_values = match load_reference_witness(generated) {
        Ok(Some(report)) => report,
        Ok(None) => {
            return CircomEvalReport {
                attempted: false,
                skipped_reason: Some(format!(
                    "{}, skipping real witness comparison",
                    reference_witness_unavailable_reason(generated)
                )),
                original_valid: false,
                transformed_valid: false,
                outputs_match: false,
                input_values: vec![],
                expected_outputs: vec![],
                original_outputs: vec![],
                transformed_outputs: vec![],
                witness_source: None,
            };
        }
        Err(err) => {
            return CircomEvalReport {
                attempted: false,
                skipped_reason: Some(format!("Failed to generate/read witness: {}", err)),
                original_valid: false,
                transformed_valid: false,
                outputs_match: false,
                input_values: vec![],
                expected_outputs: vec![],
                original_outputs: vec![],
                transformed_outputs: vec![],
                witness_source: None,
            };
        }
    };

    let field_inputs = generated
        .imported
        .input_signal_ids
        .iter()
        .map(|signal_id| {
            let input_idx = generated.imported.input_signal_to_index[signal_id];
            let value = *witness_values
                .values
                .get(*signal_id)
                .ok_or_else(|| format!("witness is missing signal {}", signal_id))?;
            Ok((input_idx, value))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>();

    let field_inputs = match field_inputs {
        Ok(inputs) => inputs,
        Err(err) => {
            return CircomEvalReport {
                attempted: false,
                skipped_reason: Some(format!("Failed to extract inputs from witness: {}", err)),
                original_valid: false,
                transformed_valid: false,
                outputs_match: false,
                input_values: vec![],
                expected_outputs: vec![],
                original_outputs: vec![],
                transformed_outputs: vec![],
                witness_source: Some(witness_values.source),
            };
        }
    };

    let mut original_assignment = Assignment::from_field_inputs(field_inputs.clone());
    let _ = execute_circuit(
        &generated.imported.normalized_r1cs,
        &mut original_assignment,
    )
    .is_some();
    let original_valid =
        verify_assignment(&generated.imported.normalized_r1cs, &original_assignment);

    let mut transformed_assignment = Assignment::from_field_inputs(field_inputs);
    let _ = execute_circuit(&transformed.optimized, &mut transformed_assignment).is_some();
    let transformed_valid = verify_assignment(&transformed.optimized, &transformed_assignment);

    let input_values = generated
        .imported
        .input_signal_ids
        .iter()
        .filter_map(|signal_id| {
            witness_values
                .values
                .get(*signal_id)
                .copied()
                .map(|value| SignalValue {
                    signal_id: *signal_id,
                    name: signal_name(generated.symbols.as_ref(), *signal_id),
                    value,
                })
        })
        .collect::<Vec<_>>();

    let expected_outputs = generated
        .imported
        .layout
        .public_output_signal_ids
        .iter()
        .filter_map(|signal_id| {
            witness_values
                .values
                .get(*signal_id)
                .copied()
                .map(|value| SignalValue {
                    signal_id: *signal_id,
                    name: signal_name(generated.symbols.as_ref(), *signal_id),
                    value,
                })
        })
        .collect::<Vec<_>>();

    let original_outputs = read_output_values(
        generated,
        &original_assignment,
        &generated.imported.layout.public_output_signal_ids,
    );
    let transformed_outputs = read_output_values(
        generated,
        &transformed_assignment,
        &generated.imported.layout.public_output_signal_ids,
    );

    let outputs_match = original_outputs
        .iter()
        .zip(expected_outputs.iter())
        .all(|(computed, expected)| computed.value == expected.value)
        && transformed_outputs
            .iter()
            .zip(expected_outputs.iter())
            .all(|(computed, expected)| computed.value == expected.value);

    CircomEvalReport {
        attempted: true,
        skipped_reason: None,
        original_valid,
        transformed_valid,
        outputs_match,
        input_values,
        expected_outputs,
        original_outputs,
        transformed_outputs,
        witness_source: Some(witness_values.source),
    }
}

pub fn export_circuit(
    generated: &GeneratedCircom,
    transformed: &TransformedCircom,
) -> Result<CircomExportReport, Box<dyn Error>> {
    export_circuit_with_options(generated, transformed, ExportBundleOptions::default())
}

pub fn export_circuit_with_options(
    generated: &GeneratedCircom,
    transformed: &TransformedCircom,
    export_options: ExportBundleOptions,
) -> Result<CircomExportReport, Box<dyn Error>> {
    let stem = generated
        .artifacts
        .import_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or("Circom path does not have a usable file name")?;

    let input_config = build_export_input_config(generated)?;
    let export = RmsLinearExport::from_r1cs_with_inputs(&transformed.optimized, &input_config)?
        .with_output_witnesses(export_output_witnesses(generated));

    write_export_bundle_with_options(&format!("data/{}", stem), &export, export_options)
}

fn build_export_input_config(
    generated: &GeneratedCircom,
) -> Result<ExportInputConfig, Box<dyn Error>> {
    let num_inputs = generated.imported.normalized_r1cs.num_inputs;
    if generated.imported.layout.public_input_signal_ids.is_empty() {
        return Ok(ExportInputConfig::all_private(num_inputs));
    }

    let witness_values = load_reference_witness(generated)?.ok_or_else(|| {
        format!(
            "rms-linear-v3 export requires concrete public input values; {}, unable to generate reference witness",
            reference_witness_unavailable_reason(generated)
        )
    })?;

    let public_inputs = generated
        .imported
        .layout
        .public_input_signal_ids
        .iter()
        .map(|signal_id| {
            let input_idx = generated.imported.input_signal_to_index[signal_id];
            let value = *witness_values
                .values
                .get(*signal_id)
                .ok_or_else(|| format!("witness is missing public input signal {}", signal_id))?;
            Ok((input_idx, value))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;

    Ok(ExportInputConfig::from_public_values(
        num_inputs,
        public_inputs,
    )?)
}

fn export_output_witnesses(generated: &GeneratedCircom) -> Vec<usize> {
    generated
        .imported
        .layout
        .public_output_signal_ids
        .iter()
        .filter_map(|signal_id| {
            generated
                .imported
                .witness_signal_to_index
                .get(signal_id)
                .copied()
        })
        .collect()
}

pub fn run(path: &str) {
    run_with_export_options(path, ExportBundleOptions::default());
}

fn run_with_export_options(path: &str, export_options: ExportBundleOptions) {
    let generated = generate_circuit(path);
    let transformed = transform_circuit(&generated);

    println!("\n╔══════════════════════════════════════════════════╗");
    println!("║  Circom -> RMS                                  ║");
    println!("╚══════════════════════════════════════════════════╝\n");

    println!("[1. Read real artifacts]");
    print_generation_summary(&generated);

    let transformed = match transformed {
        Ok(transformed) => transformed,
        Err(err) => {
            println!("\n[2. Circuit transformation]");
            println!("  Transformation failed: {}", err);
            return;
        }
    };
    let evaluation = evaluate_equivalence(&generated, &transformed);

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
            / generated.imported.normalized_r1cs.constraints.len() as f64
    );

    println!("\n[3. Eval consistency]");
    if evaluation.attempted {
        if let Some(source) = &evaluation.witness_source {
            println!("  Witness source: {}", source);
        }
        println!("  Input values:");
        for value in evaluation.input_values.iter().take(8) {
            println!("    {}", format_signal_value(value));
        }
        println!("  Original witness outputs:");
        for value in &evaluation.expected_outputs {
            println!("    {}", format_signal_value(value));
        }
        println!("  Imported original circuit outputs:");
        for value in &evaluation.original_outputs {
            println!("    {}", format_signal_value(value));
        }
        println!("  Transformed RMS outputs:");
        for value in &evaluation.transformed_outputs {
            println!("    {}", format_signal_value(value));
        }
        println!(
            "  Outputs match: {}  [constraints satisfied: orig={}, rms+cse={}]",
            evaluation.outputs_match, evaluation.original_valid, evaluation.transformed_valid
        );
    } else {
        println!(
            "  Skipping eval: {}",
            evaluation
                .skipped_reason
                .as_deref()
                .unwrap_or("unknown reason")
        );
    }

    println!("\n[4. Circuit export]");
    let export = match export_circuit_with_options(&generated, &transformed, export_options) {
        Ok(export) => export,
        Err(err) => {
            println!("  Export failed: {}", err);
            return;
        }
    };
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

    println!("\n[Preview of the first 5 normalized constraints]");
    let preview = R1CS {
        num_inputs: generated.imported.normalized_r1cs.num_inputs,
        num_witnesses: generated.imported.normalized_r1cs.num_witnesses,
        constraints: generated
            .imported
            .normalized_r1cs
            .constraints
            .iter()
            .take(5)
            .cloned()
            .collect(),
        origin: generated.imported.normalized_r1cs.origin.clone(),
    };
    print_constraints(&preview);
}

pub fn run_with_args(args: &[String]) -> Result<(), String> {
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        return Err(usage_text().to_string());
    }

    let (args, export_options) = split_export_cli_args(args);
    match args.as_slice() {
        [path] => {
            run_with_export_options(path, export_options);
            Ok(())
        }
        _ => Err(usage_text().to_string()),
    }
}

fn usage_text() -> &'static str {
    "\
Usage:
  cargo run -- circom <constraints.json|circuit.r1cs|circuit.circom> [--json]
  cargo run --example circom_json -- <constraints.json|circuit.r1cs|circuit.circom> [--json]

Notes:
    By default only `.bin` is exported; `.bin` contains a zstd-compressed `rms-linear-v3` payload. Append `--json` to also emit `.json`."
}

fn print_generation_summary(generated: &GeneratedCircom) {
    println!("  User input: {}", generated.artifacts.user_path.display());
    println!(
        "  Imported path: {}",
        generated.artifacts.import_path.display()
    );
    println!("  Format: {}", generated.artifacts.format.display_name());
    if let Some(source_path) = &generated.artifacts.source_path {
        println!("  Source: {}", source_path.display());
    }
    println!(
        "  Compiled from source: {}",
        generated.artifacts.compiled_from_source
    );
    println!(
        "  Original Circom constraint count: {}",
        generated.imported.original_constraints
    );
    println!(
        "  Public outputs / public inputs / private inputs: {} / {} / {}",
        generated.imported.layout.public_output_signal_ids.len(),
        generated.imported.layout.public_input_signal_ids.len(),
        generated.imported.layout.private_input_signal_ids.len()
    );
    if let Some(sym_path) = &generated.artifacts.sym_path {
        println!("  .sym: {}", sym_path.display());
    } else {
        println!("  .sym: not found");
    }
    if let Some(wasm_path) = &generated.artifacts.wasm_path {
        println!("  .wasm: {}", wasm_path.display());
    }
    if let Some(input_json_path) = &generated.artifacts.input_json_path {
        println!("  input.json: {}", input_json_path.display());
    }
    if let Some(symbols) = &generated.symbols {
        println!("  Symbol table entries: {}", symbols.entries.len());
    }
    println!("  External input signals:");
    for signal_id in &generated.imported.input_signal_ids {
        println!(
            "    signal {} -> x{}{}",
            signal_id,
            generated.imported.input_signal_to_index[signal_id],
            signal_name_suffix(generated.symbols.as_ref(), *signal_id)
        );
    }
    if !generated
        .imported
        .layout
        .public_output_signal_ids
        .is_empty()
    {
        println!("  Public output signals:");
        for signal_id in &generated.imported.layout.public_output_signal_ids {
            println!(
                "    signal {}{}",
                signal_id,
                signal_name_suffix(generated.symbols.as_ref(), *signal_id)
            );
        }
    }
    generated.imported.normalized_r1cs.print_stats();
}

fn resolve_artifacts(user_path: &Path) -> Result<CircomRunArtifacts, Box<dyn Error>> {
    let user_path = user_path.to_path_buf();
    let extension = user_path
        .extension()
        .and_then(|ext| ext.to_str())
        .ok_or("Circom path is missing an extension")?;

    match extension {
        "json" | "r1cs" => build_artifacts_from_compiled_path(user_path, false),
        "circom" => resolve_from_source(user_path),
        _ => Err(format!(
            "Unsupported Circom input format: {}. Supported formats are .circom / .r1cs / .json",
            user_path.display()
        )
        .into()),
    }
}

fn resolve_from_source(source_path: PathBuf) -> Result<CircomRunArtifacts, Box<dyn Error>> {
    let sibling_r1cs = source_path.with_extension("r1cs");
    if sibling_r1cs.exists() {
        let mut artifacts = build_artifacts_from_compiled_path(sibling_r1cs, false)?;
        artifacts.user_path = source_path.clone();
        artifacts.source_path = Some(source_path);
        if artifacts.input_json_path.is_none() {
            artifacts.input_json_path =
                discover_source_input_json(artifacts.source_path.as_ref().unwrap());
        }
        return Ok(artifacts);
    }

    let circom = find_circom_command()?;

    let stem = source_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or("Source path does not have a usable file name")?;
    let build_dir = PathBuf::from(format!("target/circom_build/{}", stem));
    fs::create_dir_all(&build_dir)?;

    let status = Command::new(&circom.program)
        .args(&circom.prefix_args)
        .arg(source_path.as_os_str())
        .args(["--r1cs", "--sym", "--wasm", "--O0", "--inspect", "-o"])
        .arg(build_dir.as_os_str())
        .arg("-l")
        .arg("node_modules")
        .status()?;
    if !status.success() {
        return Err(format!("circom compilation failed: {}", source_path.display()).into());
    }

    let compiled_r1cs = build_dir.join(format!("{}.r1cs", stem));
    let mut artifacts = build_artifacts_from_compiled_path(compiled_r1cs, true)?;
    artifacts.user_path = source_path.clone();
    artifacts.source_path = Some(source_path);
    if artifacts.input_json_path.is_none() {
        artifacts.input_json_path =
            discover_source_input_json(artifacts.source_path.as_ref().unwrap());
    }
    Ok(artifacts)
}

fn build_artifacts_from_compiled_path(
    import_path: PathBuf,
    compiled_from_source: bool,
) -> Result<CircomRunArtifacts, Box<dyn Error>> {
    let format = match import_path.extension().and_then(|ext| ext.to_str()) {
        Some("json") => CircomImportFormat::ConstraintsJson,
        Some("r1cs") => CircomImportFormat::BinaryR1cs,
        _ => {
            return Err(format!(
                "Could not recognize import file format: {}",
                import_path.display()
            )
            .into())
        }
    };

    let stem = import_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or("Import path does not have a usable file name")?;
    let parent = import_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    let sym_path = (format == CircomImportFormat::BinaryR1cs)
        .then(|| default_sym_path_for_r1cs(&import_path))
        .filter(|path| path.exists());
    let wasm_path = parent
        .join(format!("{}_js/{}.wasm", stem, stem))
        .exists()
        .then(|| parent.join(format!("{}_js/{}.wasm", stem, stem)));
    let input_json_path = parent
        .join("input.json")
        .exists()
        .then(|| parent.join("input.json"));
    let source_path = import_path
        .with_extension("circom")
        .exists()
        .then(|| import_path.with_extension("circom"));

    Ok(CircomRunArtifacts {
        user_path: import_path.clone(),
        import_path,
        source_path,
        format,
        compiled_from_source,
        sym_path,
        wasm_path,
        input_json_path,
    })
}

fn read_output_values(
    generated: &GeneratedCircom,
    assignment: &Assignment,
    output_signal_ids: &[usize],
) -> Vec<SignalValue> {
    output_signal_ids
        .iter()
        .filter_map(|signal_id| {
            let witness_idx = generated.imported.witness_signal_to_index.get(signal_id)?;
            let value = assignment.witnesses.get(witness_idx).copied()?;
            Some(SignalValue {
                signal_id: *signal_id,
                name: signal_name(generated.symbols.as_ref(), *signal_id),
                value,
            })
        })
        .collect()
}

fn load_reference_witness(
    generated: &GeneratedCircom,
) -> Result<Option<WitnessVector>, Box<dyn Error>> {
    if generated.artifacts.format != CircomImportFormat::BinaryR1cs {
        return Ok(None);
    }

    let wasm_path = match &generated.artifacts.wasm_path {
        Some(path) => path,
        None => return Ok(None),
    };
    let input_json_path = match &generated.artifacts.input_json_path {
        Some(path) => path,
        None => return Ok(None),
    };

    let snarkjs = find_snarkjs_command()?;
    let stem = generated
        .artifacts
        .import_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or("Circom path does not have a usable file name")?;
    let wtns_path = PathBuf::from(format!("target/{}_reference.wtns", stem));
    let wtns_json_path = PathBuf::from(format!("target/{}_reference_wtns.json", stem));

    run_snarkjs(
        &snarkjs,
        &[
            "wtns",
            "calculate",
            &wasm_path.to_string_lossy(),
            &input_json_path.to_string_lossy(),
            &wtns_path.to_string_lossy(),
        ],
    )?;
    run_snarkjs(
        &snarkjs,
        &[
            "wej",
            &wtns_path.to_string_lossy(),
            &wtns_json_path.to_string_lossy(),
        ],
    )?;

    let values = parse_witness_json(&wtns_json_path)?;
    Ok(Some(WitnessVector {
        values,
        source: format!("{} + {}", wasm_path.display(), input_json_path.display()),
    }))
}

fn parse_witness_json(path: &Path) -> Result<Vec<Fr>, Box<dyn Error>> {
    let raw = fs::read_to_string(path)?;
    let strings: Vec<String> = serde_json::from_str(&raw)?;
    strings
        .into_iter()
        .map(|value| {
            Fr::from_str(&value)
                .map_err(|_| format!("Failed to parse witness value: {}", value).into())
        })
        .collect()
}

fn find_snarkjs_command() -> Result<ExternalCommand, Box<dyn Error>> {
    let local_bin = PathBuf::from("node_modules/.bin/snarkjs");
    if local_bin.exists() {
        return Ok(ExternalCommand {
            program: local_bin,
            prefix_args: vec![],
        });
    }
    if command_exists("snarkjs") {
        return Ok(ExternalCommand {
            program: PathBuf::from("snarkjs"),
            prefix_args: vec![],
        });
    }
    if command_exists("npx") {
        return Ok(ExternalCommand {
            program: PathBuf::from("npx"),
            prefix_args: vec!["snarkjs".to_string()],
        });
    }

    Err(
        "snarkjs was not found; expected one of node_modules/.bin/snarkjs / snarkjs / npx snarkjs"
            .into(),
    )
}

fn find_circom_command() -> Result<ExternalCommand, Box<dyn Error>> {
    let local_bin = PathBuf::from("node_modules/.bin/circom2");
    if local_bin.exists() {
        return Ok(ExternalCommand {
            program: local_bin,
            prefix_args: vec![],
        });
    }
    if command_exists("circom") {
        return Ok(ExternalCommand {
            program: PathBuf::from("circom"),
            prefix_args: vec![],
        });
    }
    if command_exists("circom2") {
        return Ok(ExternalCommand {
            program: PathBuf::from("circom2"),
            prefix_args: vec![],
        });
    }

    Err("circom compiler was not found; expected one of node_modules/.bin/circom2 / circom / circom2".into())
}

fn run_snarkjs(command: &ExternalCommand, args: &[&str]) -> Result<(), Box<dyn Error>> {
    let status = Command::new(&command.program)
        .args(&command.prefix_args)
        .args(args)
        .status()?;
    if !status.success() {
        return Err(format!(
            "snarkjs command failed: {} {}",
            command.program.display(),
            args.join(" ")
        )
        .into());
    }
    Ok(())
}

fn command_exists(program: &str) -> bool {
    Command::new(program)
        .arg("--help")
        .output()
        .map(|output| output.status.success() || output.status.code().is_some())
        .unwrap_or(false)
}

fn discover_source_input_json(source_path: &Path) -> Option<PathBuf> {
    let stem = source_path.file_stem()?.to_str()?;
    let parent = source_path.parent()?;
    let stem_specific = parent.join(format!("{}.input.json", stem));
    if stem_specific.exists() {
        return Some(stem_specific);
    }

    let generic = parent.join("input.json");
    generic.exists().then_some(generic)
}

fn reference_witness_unavailable_reason(generated: &GeneratedCircom) -> String {
    if generated.artifacts.format != CircomImportFormat::BinaryR1cs {
        return "The import format is not binary .r1cs, so snarkjs cannot generate a reference witness".to_string();
    }

    let mut missing = Vec::new();
    if generated.artifacts.wasm_path.is_none() {
        missing.push(".wasm");
    }
    if generated.artifacts.input_json_path.is_none() {
        missing.push("input.json");
    }

    if missing.is_empty() {
        "Missing available reference witness dependencies".to_string()
    } else {
        format!("Missing available {}", missing.join(" + "))
    }
}

fn signal_name(symbols: Option<&CircomSymbolTable>, signal_id: usize) -> Option<String> {
    symbols
        .and_then(|table| table.witness_names.get(&signal_id).cloned())
        .or_else(|| symbols.and_then(|table| table.signal_names.get(&signal_id).cloned()))
}

fn signal_name_suffix(symbols: Option<&CircomSymbolTable>, signal_id: usize) -> String {
    signal_name(symbols, signal_id)
        .map(|name| format!(" ({})", name))
        .unwrap_or_default()
}

fn format_signal_value(value: &SignalValue) -> String {
    match &value.name {
        Some(name) => format!(
            "signal {} ({}) = {}",
            value.signal_id,
            name,
            coeff_to_string(&value.value)
        ),
        None => format!(
            "signal {} = {}",
            value.signal_id,
            coeff_to_string(&value.value)
        ),
    }
}

#[derive(Clone, Debug)]
struct WitnessVector {
    values: Vec<Fr>,
    source: String,
}

fn run_on_large_stack<T, F>(name: &str, job: F) -> T
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    thread::Builder::new()
        .name(name.to_string())
        .stack_size(256 * 1024 * 1024)
        .spawn(job)
        .expect("Failed to create large-stack thread")
        .join()
        .expect("Large-stack thread execution failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_sym_file() {
        let path = std::env::temp_dir().join(format!("rms_sym_test_{}.sym", std::process::id()));
        fs::write(&path, "1,1,0,main.out\n2,2,0,main.a\n3,-1,0,main.dead\n")
            .expect("Failed to write .sym fixture");

        let symbols = load_circom_sym(&path).expect("Failed to parse .sym");
        assert_eq!(symbols.entries.len(), 3);
        assert_eq!(
            symbols.witness_names.get(&1).map(String::as_str),
            Some("main.out")
        );
        assert_eq!(
            symbols.witness_names.get(&2).map(String::as_str),
            Some("main.a")
        );
        assert!(symbols.witness_names.get(&3).is_none());
        assert_eq!(
            symbols.signal_names.get(&3).map(String::as_str),
            Some("main.dead")
        );
    }
}
