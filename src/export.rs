use crate::r1cs::{ExportConstraint, LinComb, RmsLinearExport, Term, Variable, R1CS};
use ark_ff::PrimeField;
use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::Path;

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
    let json = serde_json::to_string_pretty(r1cs)?;
    let mut file = fs::File::create(path)?;
    file.write_all(json.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

pub fn write_r1cs_bin<P: AsRef<Path>>(
    path: P,
    r1cs: &RmsLinearExport,
) -> Result<(), Box<dyn Error>> {
    let encoded = bincode::serialize(r1cs)?;
    fs::write(path, encoded)?;
    Ok(())
}

pub fn load_r1cs_from_json<P: AsRef<Path>>(path: P) -> Result<RmsLinearExport, Box<dyn Error>> {
    let json = fs::read_to_string(path)?;
    let exported = serde_json::from_str(&json)?;
    Ok(exported)
}

pub fn load_r1cs_from_bin<P: AsRef<Path>>(path: P) -> Result<RmsLinearExport, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    let exported = bincode::deserialize(&bytes)?;
    Ok(exported)
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
