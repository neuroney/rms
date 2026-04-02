use crate::r1cs::{
    ExportConstraint, LinComb, PublicInputValue, RmsLinearExport, Term, Variable, R1CS,
};
use ark_bn254::Fr;
use ark_ff::{One, PrimeField};
use serde::{Deserialize, Serialize};
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

#[derive(Clone, Debug)]
pub struct WrittenArtifacts {
    pub json_path: String,
    pub bin_path: String,
    pub version: String,
    pub num_constraints: usize,
    pub json_bin_match: bool,
}

#[derive(Clone, Debug)]
pub struct ExportInputConfig {
    public_inputs: Vec<(usize, Fr)>,
}

#[derive(Clone, Debug, Deserialize)]
struct LegacyRmsLinearExportV1 {
    version: String,
    num_inputs: usize,
    num_witnesses: usize,
    execution_order: Vec<usize>,
    constraints: Vec<ExportConstraint>,
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
                    "public input x{} 超出输入范围 [0, {})",
                    index, num_inputs
                ));
            }
            if index == 0 && value != Fr::one() {
                return Err("x0 必须固定为 1，不能覆写为其他 public value".to_string());
            }

            match public_by_index.insert(index, value) {
                Some(existing) if existing != value => {
                    return Err(format!("public input x{} 出现冲突的重复赋值", index));
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
    if let Ok(v2) = serde_json::from_str::<RmsLinearExport>(&json) {
        return Ok(v2);
    }

    let legacy: LegacyRmsLinearExportV1 = serde_json::from_str(&json)?;
    Ok(legacy.into())
}

pub fn load_r1cs_from_bin<P: AsRef<Path>>(path: P) -> Result<RmsLinearExport, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    if let Ok(v2) = bincode::deserialize::<RmsLinearExport>(&bytes) {
        return Ok(v2);
    }

    let legacy: LegacyRmsLinearExportV1 = bincode::deserialize(&bytes)?;
    Ok(legacy.into())
}

pub fn export_r1cs_bundle(
    r1cs: &R1CS,
    export_stem: &str,
) -> Result<WrittenArtifacts, Box<dyn Error>> {
    let stem_with_constraints =
        append_constraint_count_to_stem(export_stem, r1cs.constraints.len());
    let json_path = format!("{}.json", stem_with_constraints);
    let bin_path = format!("{}.bin", stem_with_constraints);

    export_r1cs_to_json(r1cs, &json_path)?;
    export_r1cs_to_bin(r1cs, &bin_path)?;

    summarize_written_artifacts(json_path, bin_path)
}

pub fn export_r1cs_bundle_with_inputs(
    r1cs: &R1CS,
    export_stem: &str,
    input_config: &ExportInputConfig,
) -> Result<WrittenArtifacts, Box<dyn Error>> {
    let stem_with_constraints =
        append_constraint_count_to_stem(export_stem, r1cs.constraints.len());
    let json_path = format!("{}.json", stem_with_constraints);
    let bin_path = format!("{}.bin", stem_with_constraints);

    export_r1cs_to_json_with_inputs(r1cs, &json_path, input_config)?;
    export_r1cs_to_bin_with_inputs(r1cs, &bin_path, input_config)?;

    summarize_written_artifacts(json_path, bin_path)
}

pub fn write_export_bundle(
    export_stem: &str,
    export: &RmsLinearExport,
) -> Result<WrittenArtifacts, Box<dyn Error>> {
    let stem_with_constraints =
        append_constraint_count_to_stem(export_stem, export.constraints.len());
    let json_path = format!("{}.json", stem_with_constraints);
    let bin_path = format!("{}.bin", stem_with_constraints);

    write_r1cs(&json_path, export, OutputFormat::Json)?;
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

pub fn build_rms_export_v2(
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

        Ok(build_rms_export_v2(
            r1cs.num_inputs,
            r1cs.num_witnesses,
            (0..constraints.len()).collect(),
            constraints,
            input_config,
        )?)
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
    json_path: String,
    bin_path: String,
) -> Result<WrittenArtifacts, Box<dyn Error>> {
    let exported_json = load_r1cs_from_json(&json_path)?;
    let exported_bin = load_r1cs_from_bin(&bin_path)?;

    Ok(WrittenArtifacts {
        version: exported_json.version.clone(),
        num_constraints: exported_json.constraints.len(),
        json_bin_match: exported_json == exported_bin,
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

impl From<LegacyRmsLinearExportV1> for RmsLinearExport {
    fn from(value: LegacyRmsLinearExportV1) -> Self {
        let private_inputs = (0..value.num_inputs).collect::<Vec<_>>();

        RmsLinearExport {
            version: value.version,
            num_inputs: value.num_inputs,
            num_public_inputs: 0,
            num_private_inputs: private_inputs.len(),
            public_inputs: vec![],
            private_inputs,
            num_witnesses: value.num_witnesses,
            execution_order: value.execution_order,
            constraints: value.constraints,
        }
    }
}
