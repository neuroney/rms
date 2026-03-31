use crate::r1cs::{ExportConstraint, LinComb, RmsLinearExport, Term, Variable, R1CS};
use ark_ff::PrimeField;
use serde::{de::DeserializeOwned, Serialize};
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

pub fn export_r1cs_to_json<P: AsRef<Path>>(r1cs: &R1CS, path: P) -> Result<(), Box<dyn Error>> {
    let exported = RmsLinearExport::from_r1cs(r1cs)?;
    write_r1cs_json(path, &exported)
}

pub fn export_r1cs_to_bin<P: AsRef<Path>>(r1cs: &R1CS, path: P) -> Result<(), Box<dyn Error>> {
    let exported = RmsLinearExport::from_r1cs(r1cs)?;
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
    load_json_file(path)
}

pub fn load_r1cs_from_bin<P: AsRef<Path>>(path: P) -> Result<RmsLinearExport, Box<dyn Error>> {
    load_bin_file(path)
}

pub fn export_r1cs_bundle(
    r1cs: &R1CS,
    export_stem: &str,
) -> Result<WrittenArtifacts, Box<dyn Error>> {
    let json_path = format!("{}.json", export_stem);
    let bin_path = format!("{}.bin", export_stem);

    export_r1cs_to_json(r1cs, &json_path)?;
    export_r1cs_to_bin(r1cs, &bin_path)?;

    summarize_written_artifacts(json_path, bin_path)
}

pub fn write_export_bundle(
    export_stem: &str,
    export: &RmsLinearExport,
) -> Result<WrittenArtifacts, Box<dyn Error>> {
    let json_path = format!("{}.json", export_stem);
    let bin_path = format!("{}.bin", export_stem);

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

impl RmsLinearExport {
    pub fn from_r1cs(r1cs: &R1CS) -> Result<Self, Box<dyn Error>> {
        let constraints = r1cs
            .constraints
            .iter()
            .enumerate()
            .map(|(index, constraint)| export_constraint(index, constraint))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(RmsLinearExport {
            version: "rms-linear-v1".to_string(),
            num_inputs: r1cs.num_inputs,
            num_witnesses: r1cs.num_witnesses,
            execution_order: (0..constraints.len()).collect(),
            constraints,
        })
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

pub(crate) fn load_json_file<T: DeserializeOwned, P: AsRef<Path>>(
    path: P,
) -> Result<T, Box<dyn Error>> {
    let json = fs::read_to_string(path)?;
    let value = serde_json::from_str(&json)?;
    Ok(value)
}

pub(crate) fn load_bin_file<T: DeserializeOwned, P: AsRef<Path>>(
    path: P,
) -> Result<T, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    let value = bincode::deserialize(&bytes)?;
    Ok(value)
}

fn ensure_parent_dir(path: &Path) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}
