//! RMS export serialization helpers for JSON/BIN output and input metadata.

use crate::r1cs::{
    ExportConstraint, FieldElement, LinComb, PublicInputValue, RmsLinearExport, Term, Variable,
    R1CS,
};
use ark_bn254::Fr;
use ark_ff::One;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::Path;

pub const RMS_LINEAR_V3: &str = "rms-linear-v3";

const BIN_MAGIC: &[u8; 4] = b"RMS3";
const ZSTD_LEVEL: i32 = 9;

const PRIVATE_INPUTS_EXPLICIT: u8 = 0;
const PRIVATE_INPUTS_RANGE: u8 = 1;
const PRIVATE_INPUTS_BITSET: u8 = 2;

const EXECUTION_ORDER_SEQUENTIAL: u8 = 0;
const EXECUTION_ORDER_EXPLICIT: u8 = 1;

const CONSTRAINT_INDEX_SEQUENTIAL: u8 = 0;
const CONSTRAINT_INDEX_EXPLICIT: u8 = 1;

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

enum PrivateInputLayout {
    Explicit(Vec<usize>),
    Range { start: usize, count: usize },
    Bitset(Vec<u8>),
}

#[derive(Clone, Copy)]
enum ExecutionOrderLayout<'a> {
    Sequential,
    Explicit(&'a [usize]),
}

#[derive(Clone, Copy)]
enum ConstraintIndexLayout {
    Sequential,
    Explicit,
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
                return Err(
                    "x0 must be fixed to 1 and cannot be overwritten with another public value"
                        .to_string(),
                );
            }

            match public_by_index.insert(index, value) {
                Some(existing) if existing != value => {
                    return Err(format!(
                        "public input x{} has conflicting duplicate assignments",
                        index
                    ));
                }
                _ => {}
            }
        }

        let public_inputs = public_by_index
            .into_iter()
            .map(|(index, value)| PublicInputValue::from_fr(index, value))
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

impl PrivateInputLayout {
    fn choose(private_inputs: &[usize], num_inputs: usize) -> Self {
        if private_inputs.is_empty() {
            return Self::Range { start: 0, count: 0 };
        }

        let is_contiguous = private_inputs
            .windows(2)
            .all(|window| window[1] == window[0] + 1);
        if is_contiguous {
            return Self::Range {
                start: private_inputs[0],
                count: private_inputs.len(),
            };
        }

        let explicit_bytes = private_inputs.len().saturating_mul(4);
        let bitset_bytes = (num_inputs + 7) / 8;
        if bitset_bytes < explicit_bytes {
            let mut bitset = vec![0u8; bitset_bytes];
            for &index in private_inputs {
                bitset[index / 8] |= 1 << (index % 8);
            }
            Self::Bitset(bitset)
        } else {
            Self::Explicit(private_inputs.to_vec())
        }
    }

    fn kind(&self) -> u8 {
        match self {
            Self::Explicit(_) => PRIVATE_INPUTS_EXPLICIT,
            Self::Range { .. } => PRIVATE_INPUTS_RANGE,
            Self::Bitset(_) => PRIVATE_INPUTS_BITSET,
        }
    }

    fn write_payload<W: Write>(&self, writer: &mut W) -> Result<(), Box<dyn Error>> {
        match self {
            Self::Explicit(indices) => {
                for &index in indices {
                    write_u32(writer, checked_u32("private input index", index)?)?;
                }
            }
            Self::Range { start, count } => {
                if *count > 0 {
                    write_u32(writer, checked_u32("private input range start", *start)?)?;
                }
            }
            Self::Bitset(bitset) => writer.write_all(bitset)?,
        }

        Ok(())
    }
}

impl<'a> ExecutionOrderLayout<'a> {
    fn from_export(order: &'a [usize], constraint_count: usize) -> Self {
        let is_sequential = order.len() == constraint_count
            && order
                .iter()
                .enumerate()
                .all(|(index, &value)| index == value);
        if is_sequential {
            Self::Sequential
        } else {
            Self::Explicit(order)
        }
    }

    fn kind(&self) -> u8 {
        match self {
            Self::Sequential => EXECUTION_ORDER_SEQUENTIAL,
            Self::Explicit(_) => EXECUTION_ORDER_EXPLICIT,
        }
    }

    fn write_payload<W: Write>(&self, writer: &mut W) -> Result<(), Box<dyn Error>> {
        if let Self::Explicit(order) = self {
            write_u32(writer, checked_u32("execution_order_len", order.len())?)?;
            for &step in *order {
                write_u32(writer, checked_u32("execution_order step", step)?)?;
            }
        }
        Ok(())
    }
}

impl ConstraintIndexLayout {
    fn from_export(constraints: &[ExportConstraint]) -> Self {
        let is_sequential = constraints
            .iter()
            .enumerate()
            .all(|(index, constraint)| constraint.index == index);
        if is_sequential {
            Self::Sequential
        } else {
            Self::Explicit
        }
    }

    fn kind(&self) -> u8 {
        match self {
            Self::Sequential => CONSTRAINT_INDEX_SEQUENTIAL,
            Self::Explicit => CONSTRAINT_INDEX_EXPLICIT,
        }
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
    validate_export(r1cs)?;
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
    let export = serde_json::from_str::<RmsLinearExport>(&json)?;
    validate_export(&export)?;
    Ok(export)
}

pub fn load_r1cs_from_bin<P: AsRef<Path>>(path: P) -> Result<RmsLinearExport, Box<dyn Error>> {
    let file = fs::File::open(path)?;
    let reader = BufReader::new(file);
    let mut decoder = zstd::stream::Decoder::new(reader)?;
    read_v3_payload(&mut decoder)
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
        version: RMS_LINEAR_V3.to_string(),
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
            Variable::Input(index) => Ok(Term::from_fr(*index, *coeff)),
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
            Variable::Witness(index) => Ok(Term::from_fr(*index, *coeff)),
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
    if term.is_one_coeff() {
        format!("{}{}", prefix, term.index)
    } else {
        format!("{}*{}{}", term.coeff, prefix, term.index)
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

pub(crate) fn write_bin_file<P: AsRef<Path>>(
    path: P,
    export: &RmsLinearExport,
) -> Result<(), Box<dyn Error>> {
    validate_export(export)?;

    let path = path.as_ref();
    ensure_parent_dir(path)?;

    let file = fs::File::create(path)?;
    let writer = BufWriter::new(file);
    let mut encoder = zstd::stream::Encoder::new(writer, ZSTD_LEVEL)?;
    write_v3_payload(&mut encoder, export)?;
    let mut writer = encoder.finish()?;
    writer.flush()?;
    Ok(())
}

fn validate_export(export: &RmsLinearExport) -> Result<(), Box<dyn Error>> {
    if export.version != RMS_LINEAR_V3 {
        return Err(invalid_data(format!(
            "unsupported export version {}, expected {}",
            export.version, RMS_LINEAR_V3
        )));
    }
    if export.num_public_inputs != export.public_inputs.len() {
        return Err(invalid_data(format!(
            "num_public_inputs mismatch: header={} actual={}",
            export.num_public_inputs,
            export.public_inputs.len()
        )));
    }
    if export.num_private_inputs != export.private_inputs.len() {
        return Err(invalid_data(format!(
            "num_private_inputs mismatch: header={} actual={}",
            export.num_private_inputs,
            export.private_inputs.len()
        )));
    }
    if export
        .public_inputs
        .iter()
        .any(|input| input.index >= export.num_inputs)
    {
        return Err(invalid_data("public input index exceeds num_inputs"));
    }
    if export
        .private_inputs
        .iter()
        .any(|&index| index >= export.num_inputs)
    {
        return Err(invalid_data("private input index exceeds num_inputs"));
    }

    let public_unique = export
        .public_inputs
        .iter()
        .map(|input| input.index)
        .collect::<BTreeSet<_>>();
    if public_unique.len() != export.public_inputs.len() {
        return Err(invalid_data("public_inputs contains duplicate indices"));
    }

    let private_unique = export
        .private_inputs
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if private_unique.len() != export.private_inputs.len() {
        return Err(invalid_data("private_inputs contains duplicate indices"));
    }

    for (position, constraint) in export.constraints.iter().enumerate() {
        if constraint
            .a_in
            .iter()
            .any(|term| term.index >= export.num_inputs)
        {
            return Err(invalid_data(format!(
                "constraint {} contains an input term outside num_inputs",
                position
            )));
        }
        if constraint
            .b_wit
            .iter()
            .any(|term| term.index == 0 || term.index > export.num_witnesses)
        {
            return Err(invalid_data(format!(
                "constraint {} contains a witness term outside [1, num_witnesses]",
                position
            )));
        }
        if constraint.output_witness == 0 || constraint.output_witness > export.num_witnesses {
            return Err(invalid_data(format!(
                "constraint {} output witness {} outside [1, num_witnesses]",
                position, constraint.output_witness
            )));
        }
    }

    Ok(())
}

fn write_v3_payload<W: Write>(
    writer: &mut W,
    export: &RmsLinearExport,
) -> Result<(), Box<dyn Error>> {
    writer.write_all(BIN_MAGIC)?;
    write_u32(writer, checked_u32("num_inputs", export.num_inputs)?)?;
    write_u32(writer, checked_u32("num_witnesses", export.num_witnesses)?)?;

    write_u32(
        writer,
        checked_u32("public_inputs_len", export.public_inputs.len())?,
    )?;
    for input in &export.public_inputs {
        write_u32(writer, checked_u32("public input index", input.index)?)?;
        writer.write_all(input.value.as_bytes())?;
    }

    let private_layout = PrivateInputLayout::choose(&export.private_inputs, export.num_inputs);
    write_u8(writer, private_layout.kind())?;
    write_u32(
        writer,
        checked_u32("private_inputs_len", export.private_inputs.len())?,
    )?;
    private_layout.write_payload(writer)?;

    write_u32(
        writer,
        checked_u32("output_witnesses_len", export.output_witnesses.len())?,
    )?;
    for &witness in &export.output_witnesses {
        write_u32(writer, checked_u32("output witness", witness)?)?;
    }

    write_u32(
        writer,
        checked_u32("constraint_count", export.constraints.len())?,
    )?;

    let execution_layout =
        ExecutionOrderLayout::from_export(&export.execution_order, export.constraints.len());
    write_u8(writer, execution_layout.kind())?;
    execution_layout.write_payload(writer)?;

    let constraint_index_layout = ConstraintIndexLayout::from_export(&export.constraints);
    write_u8(writer, constraint_index_layout.kind())?;

    for constraint in &export.constraints {
        if matches!(constraint_index_layout, ConstraintIndexLayout::Explicit) {
            write_u32(writer, checked_u32("constraint index", constraint.index)?)?;
        }
        write_term_vec(writer, &constraint.a_in, "constraint a_in")?;
        write_term_vec(writer, &constraint.b_wit, "constraint b_wit")?;
        write_u32(
            writer,
            checked_u32("constraint output witness", constraint.output_witness)?,
        )?;
    }

    Ok(())
}

fn read_v3_payload<R: Read>(reader: &mut R) -> Result<RmsLinearExport, Box<dyn Error>> {
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if &magic != BIN_MAGIC {
        return Err(invalid_data("unexpected RMS binary magic; expected RMS3"));
    }

    let num_inputs = read_u32(reader)? as usize;
    let num_witnesses = read_u32(reader)? as usize;

    let public_inputs_len = read_u32(reader)? as usize;
    let mut public_inputs = Vec::with_capacity(public_inputs_len);
    for _ in 0..public_inputs_len {
        let index = read_u32(reader)? as usize;
        let value = read_field_element(reader)?;
        public_inputs.push(PublicInputValue { index, value });
    }

    let private_layout = read_u8(reader)?;
    let num_private_inputs = read_u32(reader)? as usize;
    let private_inputs =
        read_private_inputs(reader, private_layout, num_private_inputs, num_inputs)?;

    let output_witnesses_len = read_u32(reader)? as usize;
    let mut output_witnesses = Vec::with_capacity(output_witnesses_len);
    for _ in 0..output_witnesses_len {
        output_witnesses.push(read_u32(reader)? as usize);
    }

    let constraint_count = read_u32(reader)? as usize;

    let execution_layout = read_u8(reader)?;
    let execution_order = match execution_layout {
        EXECUTION_ORDER_SEQUENTIAL => (0..constraint_count).collect(),
        EXECUTION_ORDER_EXPLICIT => {
            let len = read_u32(reader)? as usize;
            let mut order = Vec::with_capacity(len);
            for _ in 0..len {
                order.push(read_u32(reader)? as usize);
            }
            order
        }
        other => {
            return Err(invalid_data(format!(
                "unsupported execution order encoding tag {other}"
            )))
        }
    };

    let constraint_index_layout = read_u8(reader)?;
    let mut constraints = Vec::with_capacity(constraint_count);
    for index in 0..constraint_count {
        let actual_index = match constraint_index_layout {
            CONSTRAINT_INDEX_SEQUENTIAL => index,
            CONSTRAINT_INDEX_EXPLICIT => read_u32(reader)? as usize,
            other => {
                return Err(invalid_data(format!(
                    "unsupported constraint index encoding tag {other}"
                )))
            }
        };

        let a_in = read_term_vec(reader)?;
        let b_wit = read_term_vec(reader)?;
        let output_witness = read_u32(reader)? as usize;
        constraints.push(ExportConstraint {
            index: actual_index,
            a_in,
            b_wit,
            output_witness,
        });
    }

    let export = RmsLinearExport {
        version: RMS_LINEAR_V3.to_string(),
        num_inputs,
        num_public_inputs: public_inputs.len(),
        num_private_inputs: private_inputs.len(),
        public_inputs,
        private_inputs,
        num_witnesses,
        output_witnesses,
        execution_order,
        constraints,
    };
    validate_export(&export)?;
    Ok(export)
}

fn read_private_inputs<R: Read>(
    reader: &mut R,
    layout: u8,
    count: usize,
    num_inputs: usize,
) -> Result<Vec<usize>, Box<dyn Error>> {
    let private_inputs = match layout {
        PRIVATE_INPUTS_EXPLICIT => {
            let mut indices = Vec::with_capacity(count);
            for _ in 0..count {
                indices.push(read_u32(reader)? as usize);
            }
            indices
        }
        PRIVATE_INPUTS_RANGE => {
            if count == 0 {
                Vec::new()
            } else {
                let start = read_u32(reader)? as usize;
                (start..start + count).collect()
            }
        }
        PRIVATE_INPUTS_BITSET => {
            let mut bytes = vec![0u8; (num_inputs + 7) / 8];
            reader.read_exact(&mut bytes)?;
            let mut indices = Vec::with_capacity(count);
            for index in 0..num_inputs {
                if (bytes[index / 8] >> (index % 8)) & 1 == 1 {
                    indices.push(index);
                }
            }
            indices
        }
        other => {
            return Err(invalid_data(format!(
                "unsupported private input encoding tag {other}"
            )))
        }
    };

    if private_inputs.len() != count {
        return Err(invalid_data(format!(
            "private input count mismatch: header={} actual={}",
            count,
            private_inputs.len()
        )));
    }

    Ok(private_inputs)
}

fn write_term_vec<W: Write>(
    writer: &mut W,
    terms: &[Term],
    label: &str,
) -> Result<(), Box<dyn Error>> {
    write_u32(writer, checked_u32(label, terms.len())?)?;
    for term in terms {
        write_u32(writer, checked_u32("term index", term.index)?)?;
        writer.write_all(term.coeff.as_bytes())?;
    }
    Ok(())
}

fn read_term_vec<R: Read>(reader: &mut R) -> Result<Vec<Term>, Box<dyn Error>> {
    let len = read_u32(reader)? as usize;
    let mut terms = Vec::with_capacity(len);
    for _ in 0..len {
        let index = read_u32(reader)? as usize;
        let coeff = read_field_element(reader)?;
        terms.push(Term { index, coeff });
    }
    Ok(terms)
}

fn read_field_element<R: Read>(reader: &mut R) -> Result<FieldElement, Box<dyn Error>> {
    let mut bytes = [0u8; FieldElement::BYTE_LEN];
    reader.read_exact(&mut bytes)?;
    FieldElement::from_bytes(bytes).map_err(invalid_data)
}

fn write_u8<W: Write>(writer: &mut W, value: u8) -> io::Result<()> {
    writer.write_all(&[value])
}

fn read_u8<R: Read>(reader: &mut R) -> io::Result<u8> {
    let mut buffer = [0u8; 1];
    reader.read_exact(&mut buffer)?;
    Ok(buffer[0])
}

fn write_u32<W: Write>(writer: &mut W, value: u32) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

fn read_u32<R: Read>(reader: &mut R) -> io::Result<u32> {
    let mut buffer = [0u8; 4];
    reader.read_exact(&mut buffer)?;
    Ok(u32::from_le_bytes(buffer))
}

fn checked_u32(label: &str, value: usize) -> Result<u32, Box<dyn Error>> {
    u32::try_from(value)
        .map_err(|_| invalid_data(format!("{label}={value} exceeds v3 u32 storage range")))
}

fn invalid_data(message: impl Into<String>) -> Box<dyn Error> {
    io::Error::new(io::ErrorKind::InvalidData, message.into()).into()
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
            version: RMS_LINEAR_V3.to_string(),
            num_inputs: 10,
            num_public_inputs: 2,
            num_private_inputs: 6,
            public_inputs: vec![
                PublicInputValue::from_u64(0, 1),
                PublicInputValue::from_u64(7, 9),
            ],
            private_inputs: vec![1, 3, 4, 6, 8, 9],
            num_witnesses: 3,
            output_witnesses: vec![3],
            execution_order: vec![1, 0],
            constraints: vec![
                ExportConstraint {
                    index: 4,
                    a_in: vec![Term::from_i64(0, 1), Term::from_i64(7, -3)],
                    b_wit: vec![Term::from_i64(1, 1)],
                    output_witness: 2,
                },
                ExportConstraint {
                    index: 9,
                    a_in: vec![Term::from_i64(3, 5)],
                    b_wit: vec![Term::from_i64(2, -1)],
                    output_witness: 3,
                },
            ],
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
    fn bin_round_trip_preserves_sequential_compaction_paths() {
        let path = temp_export_path("bin");
        let export = RmsLinearExport {
            version: RMS_LINEAR_V3.to_string(),
            num_inputs: 6,
            num_public_inputs: 1,
            num_private_inputs: 5,
            public_inputs: vec![PublicInputValue::from_u64(0, 1)],
            private_inputs: vec![1, 2, 3, 4, 5],
            num_witnesses: 2,
            output_witnesses: vec![2],
            execution_order: vec![0],
            constraints: vec![ExportConstraint {
                index: 0,
                a_in: vec![Term::from_i64(0, 1)],
                b_wit: vec![Term::from_i64(1, 1)],
                output_witness: 2,
            }],
        };
        write_bin_file(&path, &export).expect("Failed to write compact BIN export");

        let loaded = load_r1cs_from_bin(&path).expect("Failed to read compact BIN export");

        assert_eq!(loaded, export);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_non_v3_json_export() {
        let path = temp_export_path("json");
        let legacy = r#"{
  "version": "rms-linear-v2",
  "num_inputs": 2,
  "num_public_inputs": 1,
  "num_private_inputs": 1,
  "public_inputs": [{"index": 0, "value": "1"}],
  "private_inputs": [1],
  "num_witnesses": 1,
  "output_witnesses": [1],
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

        let error =
            load_r1cs_from_json(&path).expect_err("Legacy JSON should no longer be accepted");

        assert!(
            error.to_string().contains("unsupported export version"),
            "unexpected error: {error}"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn write_export_bundle_defaults_to_bin_only() {
        let stem = temp_export_stem();
        let report =
            write_export_bundle(&stem, &sample_export()).expect("Failed to write default export");

        assert_eq!(report.json_path, None);
        assert_eq!(report.json_bin_match, None);
        assert!(Path::new(&report.bin_path).exists());
        assert!(!Path::new(&format!("{}_c2.json", stem)).exists());

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
