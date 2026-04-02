pub use crate::circom_reader::{
    default_sym_path_for_r1cs, import_circom_constraints_json, import_circom_file,
    import_circom_r1cs, load_circom_sym, optimize_circom_r1cs, CircomImportFormat, CircomSymEntry,
    CircomSymbolTable, ImportedCircomCircuit, ImportedCircomLayout,
};
use crate::evalr1cs::{execute_circuit, verify_assignment, Assignment};
use crate::export::{
    export_r1cs_bundle_with_inputs, load_r1cs_from_json, terms_to_export_string, ExportInputConfig,
    WrittenArtifacts,
};
use crate::r1cs::R1CS;
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
    let artifacts = resolve_artifacts(Path::new(path)).expect("解析 Circom 工件失败");
    let import_path = artifacts.import_path.clone();
    let (imported, format) = run_on_large_stack("circom-import", move || {
        import_circom_file(&import_path).expect("导入 Circom 文件失败")
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
                    "{}，跳过真实 witness 对拍",
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
                skipped_reason: Some(format!("生成/读取 witness 失败: {}", err)),
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
                .ok_or_else(|| format!("witness 中缺少 signal {}", signal_id))?;
            Ok((input_idx, value))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>();

    let field_inputs = match field_inputs {
        Ok(inputs) => inputs,
        Err(err) => {
            return CircomEvalReport {
                attempted: false,
                skipped_reason: Some(format!("从 witness 提取输入失败: {}", err)),
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
    let stem = generated
        .artifacts
        .import_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or("Circom 路径没有可用文件名")?;

    let input_config = build_export_input_config(generated)?;
    export_r1cs_bundle_with_inputs(
        &transformed.optimized,
        &format!("data/{}_rms", stem),
        &input_config,
    )
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
            "rms-linear-v2 导出需要 public input 的具体值；{}，无法生成 reference witness",
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
                .ok_or_else(|| format!("witness 中缺少 public input signal {}", signal_id))?;
            Ok((input_idx, value))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;

    Ok(ExportInputConfig::from_public_values(
        num_inputs,
        public_inputs,
    )?)
}

pub fn run(path: &str) {
    let generated = generate_circuit(path);
    let transformed = transform_circuit(&generated);

    println!("\n╔══════════════════════════════════════════════════╗");
    println!("║  Circom -> RMS                                  ║");
    println!("╚══════════════════════════════════════════════════╝\n");

    println!("【1. 读取真实工件】");
    print_generation_summary(&generated);

    let transformed = match transformed {
        Ok(transformed) => transformed,
        Err(err) => {
            println!("\n【2. 电路转换】");
            println!("  转换失败: {}", err);
            return;
        }
    };
    let evaluation = evaluate_equivalence(&generated, &transformed);

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
            / generated.imported.normalized_r1cs.constraints.len() as f64
    );

    println!("\n【3. Eval 一致性】");
    if evaluation.attempted {
        if let Some(source) = &evaluation.witness_source {
            println!("  witness 来源: {}", source);
        }
        println!("  输入值:");
        for value in evaluation.input_values.iter().take(8) {
            println!("    {}", format_signal_value(value));
        }
        println!("  原始 witness 输出:");
        for value in &evaluation.expected_outputs {
            println!("    {}", format_signal_value(value));
        }
        println!("  导入后原始电路输出:");
        for value in &evaluation.original_outputs {
            println!("    {}", format_signal_value(value));
        }
        println!("  转换后 RMS 输出:");
        for value in &evaluation.transformed_outputs {
            println!("    {}", format_signal_value(value));
        }
        println!(
            "  输出一致: {}  [约束满足: orig={}, rms+cse={}]",
            evaluation.outputs_match, evaluation.original_valid, evaluation.transformed_valid
        );
    } else {
        println!(
            "  跳过 eval: {}",
            evaluation.skipped_reason.as_deref().unwrap_or("未知原因")
        );
    }

    println!("\n【4. 电路导出】");
    let export = match export_circuit(&generated, &transformed) {
        Ok(export) => export,
        Err(err) => {
            println!("  导出失败: {}", err);
            return;
        }
    };
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

    println!("\n【前 5 条规范化约束预览】");
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

    match args {
        [path] => {
            run(path);
            Ok(())
        }
        _ => Err(usage_text().to_string()),
    }
}

fn usage_text() -> &'static str {
    "\
用法:
  cargo run -- circom <constraints.json|circuit.r1cs|circuit.circom>
  cargo run --example circom_json -- <constraints.json|circuit.r1cs|circuit.circom>"
}

fn print_generation_summary(generated: &GeneratedCircom) {
    println!("  用户输入: {}", generated.artifacts.user_path.display());
    println!("  实际导入: {}", generated.artifacts.import_path.display());
    println!("  格式: {}", generated.artifacts.format.display_name());
    if let Some(source_path) = &generated.artifacts.source_path {
        println!("  源码: {}", source_path.display());
    }
    println!(
        "  来自源码编译: {}",
        generated.artifacts.compiled_from_source
    );
    println!(
        "  原始 Circom 约束数: {}",
        generated.imported.original_constraints
    );
    println!(
        "  公开输出 / 公开输入 / 私有输入: {} / {} / {}",
        generated.imported.layout.public_output_signal_ids.len(),
        generated.imported.layout.public_input_signal_ids.len(),
        generated.imported.layout.private_input_signal_ids.len()
    );
    if let Some(sym_path) = &generated.artifacts.sym_path {
        println!("  .sym: {}", sym_path.display());
    } else {
        println!("  .sym: 未找到");
    }
    if let Some(wasm_path) = &generated.artifacts.wasm_path {
        println!("  .wasm: {}", wasm_path.display());
    }
    if let Some(input_json_path) = &generated.artifacts.input_json_path {
        println!("  input.json: {}", input_json_path.display());
    }
    if let Some(symbols) = &generated.symbols {
        println!("  符号表条目数: {}", symbols.entries.len());
    }
    println!("  外部输入 signal:");
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
        println!("  公开输出 signal:");
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
        .ok_or("Circom 路径缺少扩展名")?;

    match extension {
        "json" | "r1cs" => build_artifacts_from_compiled_path(user_path, false),
        "circom" => resolve_from_source(user_path),
        _ => Err(format!(
            "不支持的 Circom 输入格式: {}。目前支持 .circom / .r1cs / .json",
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
        .ok_or("源码路径没有可用文件名")?;
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
        return Err(format!("circom 编译失败: {}", source_path.display()).into());
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
        _ => return Err(format!("无法识别导入文件格式: {}", import_path.display()).into()),
    };

    let stem = import_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or("导入路径没有可用文件名")?;
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
        .ok_or("Circom 路径没有可用文件名")?;
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
            Fr::from_str(&value).map_err(|_| format!("无法解析 witness 值: {}", value).into())
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

    Err("未找到 snarkjs，可用路径应为 node_modules/.bin/snarkjs / snarkjs / npx snarkjs".into())
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

    Err("未找到 circom 编译器，可用路径应为 node_modules/.bin/circom2 / circom / circom2".into())
}

fn run_snarkjs(command: &ExternalCommand, args: &[&str]) -> Result<(), Box<dyn Error>> {
    let status = Command::new(&command.program)
        .args(&command.prefix_args)
        .args(args)
        .status()?;
    if !status.success() {
        return Err(format!(
            "snarkjs 命令失败: {} {}",
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
        return "导入格式不是 binary .r1cs，无法使用 snarkjs 生成 reference witness".to_string();
    }

    let mut missing = Vec::new();
    if generated.artifacts.wasm_path.is_none() {
        missing.push(".wasm");
    }
    if generated.artifacts.input_json_path.is_none() {
        missing.push("input.json");
    }

    if missing.is_empty() {
        "缺少可用 reference witness 依赖".to_string()
    } else {
        format!("缺少可用的 {}", missing.join(" + "))
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
        .expect("创建大栈线程失败")
        .join()
        .expect("大栈线程执行失败")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_sym_file() {
        let path = std::env::temp_dir().join(format!("rms_sym_test_{}.sym", std::process::id()));
        fs::write(&path, "1,1,0,main.out\n2,2,0,main.a\n3,-1,0,main.dead\n")
            .expect("写入 .sym fixture 失败");

        let symbols = load_circom_sym(&path).expect("解析 .sym 失败");
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
