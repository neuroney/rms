//! RMS export serialization helpers for JSON/BIN output and input metadata.

use crate::r1cs::{
    ExportConstraint, LinComb, PublicInputValue, RmsLinearExport, Term, Variable, R1CS,
};
use ark_bn254::Fr;
use ark_ff::{One, PrimeField};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Json,
    Bin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportBundleOptions {
    pub emit_json: bool,
}

#[derive(Clone, Debug)]
pub struct WrittenArtifacts {
    pub json_path: Option<String>,
    pub bin_path: String,
    pub version: String,
    pub num_constraints: usize,
    pub json_bin_match: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct ExportInputConfig {
    public_inputs: Vec<(usize, Fr)>,
}

impl OutputFormat {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "json" => Ok(Self::Json),
            "bin" => Ok(Self::Bin),
            other => Err(format!(
                "unsupported output format '{other}', expected 'json' or 'bin'"
            )),
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            OutputFormat::Json => "json",
            OutputFormat::Bin => "bin",
        }
    }
}

impl Default for ExportBundleOptions {
    fn default() -> Self {
        Self::bin_only()
    }
}

impl ExportBundleOptions {
    pub const fn bin_only() -> Self {
        Self { emit_json: false }
    }

    pub const fn with_json() -> Self {
        Self { emit_json: true }
    }
}

pub fn split_export_cli_args(args: &[String]) -> (Vec<String>, ExportBundleOptions) {
    let mut filtered = Vec::with_capacity(args.len());
    let mut options = ExportBundleOptions::default();

    for arg in args {
        match arg.as_str() {
            "--json" => options.emit_json = true,
            _ => filtered.push(arg.clone()),
        }
    }

    (filtered, options)
}

impl ExportInputConfig {
    pub fn all_private(num_inputs: usize) -> Self {
        let mut public_inputs = Vec::new();
        if num_inputs > 0 {
            public_inputs.push((0, Fr::one()));
        }

        Self { public_inputs }
    }

    pub fn from_public_values(
        num_inputs: usize,
        public_inputs: Vec<(usize, Fr)>,
    ) -> Result<Self, String> {
        let config = Self { public_inputs };
        let _ = config.materialize(num_inputs)?;
        Ok(config)
    }

    fn materialize(
        &self,
        num_inputs: usize,
    ) -> Result<(Vec<PublicInputValue>, Vec<usize>), String> {
        let mut public_by_index = BTreeMap::new();
        if num_inputs > 0 {
            public_by_index.insert(0usize, Fr::one());
        }

        for &(index, value) in &self.public_inputs {
            if index >= num_inputs {
                return Err(format!(
                    "public input x{} exceeds the input range [0, {})",
                    index, num_inputs
                ));
            }
            if index == 0 && value != Fr::one() {
                return Err("x0 must be fixed to 1 and cannot be overwritten with another public value".to_string());
            }

            match public_by_index.insert(index, value) {
                Some(existing) if existing != value => {
                    return Err(format!("public input x{} has conflicting duplicate assignments", index));
                }
                _ => {}
            }
        }

        let public_inputs = public_by_index
            .into_iter()
            .map(|(index, value)| PublicInputValue {
                index,
                value: value.into_bigint().to_string(),
            })
            .collect::<Vec<_>>();

        let public_index_set = public_inputs
            .iter()
            .map(|input| input.index)
            .collect::<BTreeSet<_>>();
        let private_inputs = (0..num_inputs)
            .filter(|index| !public_index_set.contains(index))
            .collect::<Vec<_>>();

        Ok((public_inputs, private_inputs))
    }
}

pub fn export_r1cs_to_json<P: AsRef<Path>>(r1cs: &R1CS, path: P) -> Result<(), Box<dyn Error>> {
    let exported = RmsLinearExport::from_r1cs(r1cs)?;
    write_r1cs_json(path, &exported)
}

pub fn export_r1cs_to_json_with_inputs<P: AsRef<Path>>(
    r1cs: &R1CS,
    path: P,
    input_config: &ExportInputConfig,
) -> Result<(), Box<dyn Error>> {
    let exported = RmsLinearExport::from_r1cs_with_inputs(r1cs, input_config)?;
    write_r1cs_json(path, &exported)
}

pub fn export_r1cs_to_bin<P: AsRef<Path>>(r1cs: &R1CS, path: P) -> Result<(), Box<dyn Error>> {
    let exported = RmsLinearExport::from_r1cs(r1cs)?;
    write_r1cs_bin(path, &exported)
}

pub fn export_r1cs_to_bin_with_inputs<P: AsRef<Path>>(
    r1cs: &R1CS,
    path: P,
    input_config: &ExportInputConfig,
) -> Result<(), Box<dyn Error>> {
    let exported = RmsLinearExport::from_r1cs_with_inputs(r1cs, input_config)?;
    write_r1cs_bin(path, &exported)
}

pub fn write_r1cs_json<P: AsRef<Path>>(
    path: P,
    r1cs: &RmsLinearExport,
) -> Result<(), Box<dyn Error>> {
    write_json_pretty_file(path, r1cs)
}

pub fn write_r1cs_bin<P: AsRef<Path>>(
    path: P,
    r1cs: &RmsLinearExport,
) -> Result<(), Box<dyn Error>> {
    write_bin_file(path, r1cs)
}

pub fn write_r1cs<P: AsRef<Path>>(
    path: P,
    r1cs: &RmsLinearExport,
    format: OutputFormat,
) -> Result<(), Box<dyn Error>> {
    match format {
        OutputFormat::Json => write_r1cs_json(path, r1cs),
        OutputFormat::Bin => write_r1cs_bin(path, r1cs),
    }
}

pub fn load_r1cs_from_json<P: AsRef<Path>>(path: P) -> Result<RmsLinearExport, Box<dyn Error>> {
    let json = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&json)?)
}

pub fn load_r1cs_from_bin<P: AsRef<Path>>(path: P) -> Result<RmsLinearExport, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    Ok(bincode::deserialize(&bytes)?)
}

pub fn export_r1cs_bundle(
    r1cs: &R1CS,
    export_stem: &str,
) -> Result<WrittenArtifacts, Box<dyn Error>> {
    export_r1cs_bundle_with_options(r1cs, export_stem, ExportBundleOptions::default())
}

pub fn export_r1cs_bundle_with_options(
    r1cs: &R1CS,
    export_stem: &str,
    options: ExportBundleOptions,
) -> Result<WrittenArtifacts, Box<dyn Error>> {
    let export = RmsLinearExport::from_r1cs(r1cs)?;
    write_export_bundle_with_options(export_stem, &export, options)
}

pub fn export_r1cs_bundle_with_inputs(
    r1cs: &R1CS,
    export_stem: &str,
    input_config: &ExportInputConfig,
) -> Result<WrittenArtifacts, Box<dyn Error>> {
    export_r1cs_bundle_with_inputs_and_options(
        r1cs,
        export_stem,
        input_config,
        ExportBundleOptions::default(),
    )
}

pub fn export_r1cs_bundle_with_inputs_and_options(
    r1cs: &R1CS,
    export_stem: &str,
    input_config: &ExportInputConfig,
    options: ExportBundleOptions,
) -> Result<WrittenArtifacts, Box<dyn Error>> {
    let export = RmsLinearExport::from_r1cs_with_inputs(r1cs, input_config)?;
    write_export_bundle_with_options(export_stem, &export, options)
}

pub fn write_export_bundle(
    export_stem: &str,
    export: &RmsLinearExport,
) -> Result<WrittenArtifacts, Box<dyn Error>> {
    write_export_bundle_with_options(export_stem, export, ExportBundleOptions::default())
}

pub fn write_export_bundle_with_options(
    export_stem: &str,
    export: &RmsLinearExport,
    options: ExportBundleOptions,
) -> Result<WrittenArtifacts, Box<dyn Error>> {
    let stem_with_constraints =
        append_constraint_count_to_stem(export_stem, export.constraints.len());
    let json_path = options
        .emit_json
        .then(|| format!("{}.json", stem_with_constraints));
    let bin_path = format!("{}.bin", stem_with_constraints);

    if let Some(path) = &json_path {
        write_r1cs(path, export, OutputFormat::Json)?;
    }
    write_r1cs(&bin_path, export, OutputFormat::Bin)?;

    summarize_written_artifacts(json_path, bin_path)
}

pub fn print_export_constraints_preview(export: &RmsLinearExport, limit: usize) {
    for constraint in export.constraints.iter().take(limit) {
        println!(
            "    step {:>2}: ({} ) * ({} ) -> w{}",
            constraint.index,
            terms_to_export_string(&constraint.a_in, "x"),
            terms_to_export_string(&constraint.b_wit, "w"),
            constraint.output_witness
        );
    }
}

pub fn build_rms_export(
    num_inputs: usize,
    num_witnesses: usize,
    execution_order: Vec<usize>,
    constraints: Vec<ExportConstraint>,
    input_config: &ExportInputConfig,
) -> Result<RmsLinearExport, String> {
    let (public_inputs, private_inputs) = input_config.materialize(num_inputs)?;

    Ok(RmsLinearExport {
        version: "rms-linear-v2".to_string(),
        num_inputs,
        num_public_inputs: public_inputs.len(),
        num_private_inputs: private_inputs.len(),
        public_inputs,
        private_inputs,
        num_witnesses,
        output_witnesses: vec![],
        execution_order,
        constraints,
    })
}

impl RmsLinearExport {
    pub fn from_r1cs(r1cs: &R1CS) -> Result<Self, Box<dyn Error>> {
        Self::from_r1cs_with_inputs(r1cs, &ExportInputConfig::all_private(r1cs.num_inputs))
    }

    pub fn from_r1cs_with_inputs(
        r1cs: &R1CS,
        input_config: &ExportInputConfig,
    ) -> Result<Self, Box<dyn Error>> {
        let constraints = r1cs
            .constraints
            .iter()
            .enumerate()
            .map(|(index, constraint)| export_constraint(index, constraint))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(build_rms_export(
            r1cs.num_inputs,
            r1cs.num_witnesses,
            (0..constraints.len()).collect(),
            constraints,
            input_config,
        )?)
    }

    pub fn with_output_witnesses(mut self, output_witnesses: Vec<usize>) -> Self {
        self.output_witnesses = output_witnesses;
        self
    }
}

pub fn terms_to_export_string(terms: &[Term], prefix: &str) -> String {
    if terms.is_empty() {
        return "0".to_string();
    }

    terms
        .iter()
        .map(|term| format_term(term, prefix))
        .collect::<Vec<_>>()
        .join(" + ")
}

fn export_constraint(
    index: usize,
    constraint: &crate::r1cs::Constraint,
) -> Result<ExportConstraint, Box<dyn Error>> {
    if !constraint.is_rms_compatible() {
        return Err(format!(
            "constraint {} is not RMS-compatible and cannot be exported",
            index
        )
        .into());
    }

    let output_witness = extract_output_witness(&constraint.c).ok_or_else(|| {
        format!(
            "constraint {} does not have a single witness output and cannot be exported",
            index
        )
    })?;

    Ok(ExportConstraint {
        index,
        a_in: export_input_terms(&constraint.a)?,
        b_wit: export_witness_terms(&constraint.b)?,
        output_witness,
    })
}

fn export_input_terms(lc: &LinComb) -> Result<Vec<Term>, Box<dyn Error>> {
    lc.terms
        .iter()
        .map(|(coeff, variable)| match variable {
            Variable::Input(index) => Ok(Term {
                index: *index,
                coeff: coeff.into_bigint().to_string(),
            }),
            Variable::Witness(index) => Err(format!(
                "expected input-only linear combination, found witness w{}",
                index
            )
            .into()),
        })
        .collect()
}

fn export_witness_terms(lc: &LinComb) -> Result<Vec<Term>, Box<dyn Error>> {
    lc.terms
        .iter()
        .map(|(coeff, variable)| match variable {
            Variable::Witness(index) => Ok(Term {
                index: *index,
                coeff: coeff.into_bigint().to_string(),
            }),
            Variable::Input(index) => Err(format!(
                "expected witness-only linear combination, found input x{}",
                index
            )
            .into()),
        })
        .collect()
}

fn extract_output_witness(lc: &LinComb) -> Option<usize> {
    match lc.terms.as_slice() {
        [(_, Variable::Witness(index))] => Some(*index),
        _ => None,
    }
}

fn format_term(term: &Term, prefix: &str) -> String {
    match term.coeff.as_str() {
        "1" => format!("{}{}", prefix, term.index),
        coeff => format!("{}*{}{}", coeff, prefix, term.index),
    }
}

fn append_constraint_count_to_stem(export_stem: &str, num_constraints: usize) -> String {
    format!("{}_c{}", export_stem, num_constraints)
}

fn summarize_written_artifacts(
    json_path: Option<String>,
    bin_path: String,
) -> Result<WrittenArtifacts, Box<dyn Error>> {
    let exported_bin = load_r1cs_from_bin(&bin_path)?;
    let json_bin_match = match json_path.as_ref() {
        Some(path) => Some(load_r1cs_from_json(path)? == exported_bin),
        None => None,
    };

    Ok(WrittenArtifacts {
        version: exported_bin.version.clone(),
        num_constraints: exported_bin.constraints.len(),
        json_bin_match,
        json_path,
        bin_path,
    })
}

pub(crate) fn write_json_pretty_file<T: Serialize, P: AsRef<Path>>(
    path: P,
    value: &T,
) -> Result<(), Box<dyn Error>> {
    let path = path.as_ref();
    ensure_parent_dir(path)?;

    let json = serde_json::to_string_pretty(value)?;
    let mut file = fs::File::create(path)?;
    file.write_all(json.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

pub(crate) fn write_bin_file<T: Serialize, P: AsRef<Path>>(
    path: P,
    value: &T,
) -> Result<(), Box<dyn Error>> {
    let path = path.as_ref();
    ensure_parent_dir(path)?;

    let encoded = bincode::serialize(value)?;
    fs::write(path, encoded)?;
    Ok(())
}

fn ensure_parent_dir(path: &Path) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_export_path(extension: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "rms_export_test_{}_{}.{}",
            std::process::id(),
            unique,
            extension
        ))
    }

    fn temp_export_stem() -> String {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos();
        std::env::temp_dir()
            .join(format!(
                "rms_export_bundle_test_{}_{}",
                std::process::id(),
                unique
            ))
            .to_string_lossy()
            .into_owned()
    }

    fn sample_export() -> RmsLinearExport {
        RmsLinearExport {
            version: "rms-linear-v2".to_string(),
            num_inputs: 2,
            num_public_inputs: 1,
            num_private_inputs: 1,
            public_inputs: vec![PublicInputValue {
                index: 0,
                value: "1".to_string(),
            }],
            private_inputs: vec![1],
            num_witnesses: 1,
            output_witnesses: vec![1],
            execution_order: vec![0],
            constraints: vec![ExportConstraint {
                index: 0,
                a_in: vec![Term {
                    index: 0,
                    coeff: "1".to_string(),
                }],
                b_wit: vec![Term {
                    index: 1,
                    coeff: "1".to_string(),
                }],
                output_witness: 1,
            }],
        }
    }

    #[test]
    fn loads_current_json_export() {
        let path = temp_export_path("json");
        let export = sample_export();
        write_json_pretty_file(&path, &export).expect("Failed to write current JSON export");

        let loaded = load_r1cs_from_json(&path).expect("Failed to read current JSON export");

        assert_eq!(loaded, export);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn loads_current_bin_export() {
        let path = temp_export_path("bin");
        let export = sample_export();
        write_bin_file(&path, &export).expect("Failed to write current BIN export");

        let loaded = load_r1cs_from_bin(&path).expect("Failed to read current BIN export");

        assert_eq!(loaded, export);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_legacy_json_export_without_current_fields() {
        let path = temp_export_path("json");
        let legacy = r#"{
  "version": "rms-linear-v1",
  "num_inputs": 2,
  "num_witnesses": 1,
  "execution_order": [0],
  "constraints": [
    {
      "index": 0,
      "a_in": [{"index": 0, "coeff": "1"}],
      "b_wit": [{"index": 1, "coeff": "1"}],
      "output_witness": 1
    }
  ]
}"#;
        fs::write(&path, legacy).expect("Failed to write legacy JSON export");

        let error = load_r1cs_from_json(&path).expect_err("Legacy JSON should no longer be accepted");

        assert!(
            error.to_string().contains("missing field"),
            "unexpected error: {error}"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn write_export_bundle_defaults_to_bin_only() {
        let stem = temp_export_stem();
        let report = write_export_bundle(&stem, &sample_export()).expect("Failed to write default export");

        assert_eq!(report.json_path, None);
        assert_eq!(report.json_bin_match, None);
        assert!(Path::new(&report.bin_path).exists());
        assert!(!Path::new(&format!("{}_c1.json", stem)).exists());

        let _ = fs::remove_file(report.bin_path);
    }

    #[test]
    fn write_export_bundle_can_emit_json_when_requested() {
        let stem = temp_export_stem();
        let report = write_export_bundle_with_options(
            &stem,
            &sample_export(),
            ExportBundleOptions::with_json(),
        )
        .expect("Failed to write export with JSON");

        assert_eq!(report.json_bin_match, Some(true));
        assert!(Path::new(&report.bin_path).exists());
        assert!(report
            .json_path
            .as_ref()
            .is_some_and(|path| Path::new(path).exists()));

        if let Some(json_path) = report.json_path {
            let _ = fs::remove_file(json_path);
        }
        let _ = fs::remove_file(report.bin_path);
    }
}
