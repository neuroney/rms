//! Circom JSON/R1CS import, normalization, and symbol handling utilities.

use crate::r1cs::{Constraint, LinComb, Variable, R1CS};
use crate::transform::{choudhuri_transform, eliminate_common_subexpressions, TransformResult};
use crate::utils::fr_from_i64;
use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Clone, Debug)]
pub struct ImportedCircomCircuit {
    pub normalized_r1cs: R1CS,
    pub original_constraints: usize,
    pub input_signal_ids: Vec<usize>,
    pub input_signal_to_index: HashMap<usize, usize>,
    pub witness_signal_to_index: HashMap<usize, usize>,
    pub layout: ImportedCircomLayout,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CircomImportFormat {
    ConstraintsJson,
    BinaryR1cs,
}

#[derive(Clone, Debug, Default)]
pub struct ImportedCircomLayout {
    pub public_output_signal_ids: Vec<usize>,
    pub public_input_signal_ids: Vec<usize>,
    pub private_input_signal_ids: Vec<usize>,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct CircomSymEntry {
    pub signal_id: usize,
    pub witness_position: Option<usize>,
    pub component_id: usize,
    pub qualified_name: String,
}

#[derive(Clone, Debug, Default)]
pub struct CircomSymbolTable {
    pub entries: Vec<CircomSymEntry>,
    pub witness_names: HashMap<usize, String>,
    pub signal_names: HashMap<usize, String>,
}

impl CircomImportFormat {
    pub fn display_name(self) -> &'static str {
        match self {
            Self::ConstraintsJson => "Circom constraints JSON",
            Self::BinaryR1cs => "Circom binary R1CS",
        }
    }
}

#[derive(Deserialize)]
struct CircomConstraintsFile {
    constraints: Vec<[HashMap<String, String>; 3]>,
}

#[derive(Clone, Debug)]
struct GenericConstraint {
    a: GenericLinComb,
    b: GenericLinComb,
    c: GenericLinComb,
}

#[derive(Clone, Debug, Default)]
struct GenericLinComb {
    terms: Vec<(Fr, usize)>, // signal 0 is the constant 1
}

#[derive(Clone, Debug)]
enum SignalDefinition {
    Linear(GenericLinComb),
    Quadratic {
        a: GenericLinComb,
        b: GenericLinComb,
        rest: GenericLinComb,
        inv_coeff: Fr,
    },
}

#[derive(Default)]
struct SignalStats {
    ab_occurrences: usize,
    c_occurrences: usize,
}

#[derive(Clone, Debug)]
struct BinaryR1csHeader {
    field_size: usize,
    prime: Vec<u8>,
    n_wires: usize,
    n_pub_out: usize,
    n_pub_in: usize,
    n_prv_in: usize,
    n_labels: u64,
    m_constraints: usize,
}

struct BuildState<'a> {
    r1cs: R1CS,
    signal_defs: HashMap<usize, SignalDefinition>,
    signal_materialized: HashSet<usize>,
    signal_in_progress: HashSet<usize>,
    linear_signal_in_progress: HashSet<usize>,
    input_signal_to_index: HashMap<usize, usize>,
    witness_signal_to_index: HashMap<usize, usize>,
    next_witness: usize,
    zero_witness: Option<usize>,
    input_lift_cache: HashMap<String, usize>,
    constraints: &'a [GenericConstraint],
    linear_constraints_by_signal: HashMap<usize, Vec<usize>>,
    used_linear_constraints: HashSet<usize>,
}

struct AliasResolver {
    parent: HashMap<usize, usize>,
    weight_to_parent: HashMap<usize, Fr>,
    preferred_output_signal_ids: HashSet<usize>,
    protected_input_signal_ids: HashSet<usize>,
}

pub fn import_circom_file<P: AsRef<Path>>(
    path: P,
) -> Result<(ImportedCircomCircuit, CircomImportFormat), Box<dyn Error>> {
    let format = detect_circom_format(path.as_ref())?;
    let imported = match format {
        CircomImportFormat::ConstraintsJson => import_circom_constraints_json(path)?,
        CircomImportFormat::BinaryR1cs => import_circom_r1cs(path)?,
    };
    Ok((imported, format))
}

pub fn import_circom_constraints_json<P: AsRef<Path>>(
    path: P,
) -> Result<ImportedCircomCircuit, Box<dyn Error>> {
    let json = fs::read_to_string(path)?;
    let parsed: CircomConstraintsFile = serde_json::from_str(&json)?;
    let generic_constraints = parsed
        .constraints
        .into_iter()
        .map(parse_generic_constraint)
        .collect::<Result<Vec<_>, _>>()?;

    import_generic_constraints(generic_constraints, None, ImportedCircomLayout::default())
}

pub fn import_circom_r1cs<P: AsRef<Path>>(
    path: P,
) -> Result<ImportedCircomCircuit, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    let (header, generic_constraints) = parse_binary_r1cs(&bytes)?;

    let public_output_signal_ids = (1..=header.n_pub_out).collect::<Vec<_>>();
    let public_input_signal_ids =
        ((1 + header.n_pub_out)..(1 + header.n_pub_out + header.n_pub_in)).collect::<Vec<_>>();
    let private_input_signal_ids = ((1 + header.n_pub_out + header.n_pub_in)
        ..(1 + header.n_pub_out + header.n_pub_in + header.n_prv_in))
        .collect::<Vec<_>>();

    let declared_input_signal_ids = public_input_signal_ids
        .iter()
        .chain(private_input_signal_ids.iter())
        .copied()
        .collect::<Vec<_>>();

    import_generic_constraints(
        generic_constraints,
        Some(declared_input_signal_ids),
        ImportedCircomLayout {
            public_output_signal_ids,
            public_input_signal_ids,
            private_input_signal_ids,
        },
    )
}

pub fn load_circom_sym<P: AsRef<Path>>(path: P) -> Result<CircomSymbolTable, Box<dyn Error>> {
    let contents = fs::read_to_string(path)?;
    let mut table = CircomSymbolTable::default();

    for (line_no, raw_line) in contents.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }

        let mut parts = line.splitn(4, ',');
        let signal_id = parts
            .next()
            .ok_or_else(|| format!(".sym line {} is missing a signal id", line_no + 1))?
            .trim()
            .parse::<usize>()?;
        let witness_position = parts
            .next()
            .ok_or_else(|| format!(".sym line {} is missing a witness position", line_no + 1))?
            .trim()
            .parse::<isize>()?;
        let component_id = parts
            .next()
            .ok_or_else(|| format!(".sym line {} is missing a component id", line_no + 1))?
            .trim()
            .parse::<usize>()?;
        let qualified_name = parts
            .next()
            .ok_or_else(|| format!(".sym line {} is missing a signal name", line_no + 1))?
            .trim()
            .to_string();

        let entry = CircomSymEntry {
            signal_id,
            witness_position: (witness_position >= 0).then_some(witness_position as usize),
            component_id,
            qualified_name: qualified_name.clone(),
        };

        table
            .signal_names
            .entry(signal_id)
            .or_insert_with(|| qualified_name.clone());
        if let Some(witness_position) = entry.witness_position {
            table
                .witness_names
                .entry(witness_position)
                .or_insert_with(|| qualified_name.clone());
        }
        table.entries.push(entry);
    }

    Ok(table)
}

pub fn default_sym_path_for_r1cs(path: &Path) -> PathBuf {
    path.with_extension("sym")
}

#[allow(dead_code)]
pub fn optimize_circom_r1cs(r1cs: &R1CS) -> (TransformResult, R1CS, usize) {
    let transformed = choudhuri_transform(r1cs);
    let (optimized, eliminated) = eliminate_common_subexpressions(&transformed.r1cs);
    (transformed, optimized, eliminated)
}

impl AliasResolver {
    fn new(
        protected_input_signal_ids: &HashSet<usize>,
        preferred_output_signal_ids: &HashSet<usize>,
    ) -> Self {
        Self {
            parent: HashMap::new(),
            weight_to_parent: HashMap::new(),
            preferred_output_signal_ids: preferred_output_signal_ids.clone(),
            protected_input_signal_ids: protected_input_signal_ids.clone(),
        }
    }

    fn canonical_preference_key(&self, signal_id: usize) -> (usize, usize, usize) {
        let output_rank = usize::from(!self.preferred_output_signal_ids.contains(&signal_id));
        let input_rank = usize::from(!self.protected_input_signal_ids.contains(&signal_id));
        (output_rank, input_rank, signal_id)
    }

    fn ensure_node(&mut self, signal_id: usize) {
        self.parent.entry(signal_id).or_insert(signal_id);
        self.weight_to_parent
            .entry(signal_id)
            .or_insert_with(Fr::one);
    }

    fn find(&mut self, signal_id: usize) -> (usize, Fr) {
        self.ensure_node(signal_id);

        let parent = self.parent[&signal_id];
        if parent == signal_id {
            return (signal_id, Fr::one());
        }

        let weight = self.weight_to_parent[&signal_id];
        let (root, parent_factor) = self.find(parent);
        let factor = weight * parent_factor;
        self.parent.insert(signal_id, root);
        self.weight_to_parent.insert(signal_id, factor);
        (root, factor)
    }

    fn union_relation(
        &mut self,
        left_signal: usize,
        right_signal: usize,
        left_equals_ratio_times_right: Fr,
    ) -> Result<(), Box<dyn Error>> {
        let (left_root, left_factor) = self.find(left_signal);
        let (right_root, right_factor) = self.find(right_signal);

        if left_root == right_root {
            return Ok(());
        }

        let keep_left_root =
            self.canonical_preference_key(left_root) <= self.canonical_preference_key(right_root);

        if keep_left_root {
            let denom = left_equals_ratio_times_right * right_factor;
            let weight = left_factor
                * denom.inverse().ok_or_else(|| {
                    format!(
                        "alias constraint cannot be normalized: the ratio for signal {} / {} is not invertible",
                        left_signal, right_signal
                    )
                })?;
            self.parent.insert(right_root, left_root);
            self.weight_to_parent.insert(right_root, weight);
        } else {
            let weight = left_equals_ratio_times_right
                * right_factor
                * left_factor.inverse().ok_or_else(|| {
                    format!(
                        "alias constraint cannot be normalized: the ratio for signal {} / {} is not invertible",
                        left_signal, right_signal
                    )
                })?;
            self.parent.insert(left_root, right_root);
            self.weight_to_parent.insert(left_root, weight);
        }

        Ok(())
    }

    fn canonicalize_signal(&mut self, signal_id: usize) -> (usize, Fr) {
        self.find(signal_id)
    }
}

fn canonicalize_simple_aliases(
    constraints: Vec<GenericConstraint>,
    protected_input_signal_ids: &HashSet<usize>,
    preferred_output_signal_ids: &HashSet<usize>,
) -> Result<Vec<GenericConstraint>, Box<dyn Error>> {
    let mut resolver = AliasResolver::new(protected_input_signal_ids, preferred_output_signal_ids);

    for constraint in &constraints {
        if !should_canonicalize_alias_constraint(constraint, preferred_output_signal_ids) {
            continue;
        }

        let [(left_coeff, left_signal), (right_coeff, right_signal)] =
            constraint.c.terms.as_slice()
        else {
            continue;
        };
        let inv = left_coeff.inverse().ok_or_else(|| {
            format!(
                "The coefficient of signal {} in the alias constraint is not invertible, so alias folding cannot be performed",
                left_signal
            )
        })?;
        let ratio = -*right_coeff * inv;
        resolver.union_relation(*left_signal, *right_signal, ratio)?;
    }

    let rewritten = constraints
        .into_iter()
        .filter(|constraint| {
            !should_canonicalize_alias_constraint(constraint, preferred_output_signal_ids)
        })
        .filter_map(|constraint| {
            let rewritten = GenericConstraint {
                a: canonicalize_aliases_in_lincomb(constraint.a, &mut resolver),
                b: canonicalize_aliases_in_lincomb(constraint.b, &mut resolver),
                c: canonicalize_aliases_in_lincomb(constraint.c, &mut resolver),
            };

            (!(rewritten.a.is_zero() && rewritten.b.is_zero() && rewritten.c.is_zero()))
                .then_some(rewritten)
        })
        .collect::<Vec<_>>();

    Ok(rewritten)
}

fn should_canonicalize_alias_constraint(
    constraint: &GenericConstraint,
    preferred_output_signal_ids: &HashSet<usize>,
) -> bool {
    is_simple_signal_alias(constraint)
        && constraint
            .c
            .terms
            .iter()
            .all(|(_, signal_id)| !preferred_output_signal_ids.contains(signal_id))
}

fn canonicalize_aliases_in_lincomb(
    expr: GenericLinComb,
    resolver: &mut AliasResolver,
) -> GenericLinComb {
    GenericLinComb::from_terms(
        expr.terms
            .into_iter()
            .map(|(coeff, signal_id)| {
                if signal_id == 0 {
                    return (coeff, signal_id);
                }
                let (canonical_signal_id, scale) = resolver.canonicalize_signal(signal_id);
                (coeff * scale, canonical_signal_id)
            })
            .collect(),
    )
}

fn detect_circom_format(path: &Path) -> Result<CircomImportFormat, Box<dyn Error>> {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("json") => Ok(CircomImportFormat::ConstraintsJson),
        Some("r1cs") => Ok(CircomImportFormat::BinaryR1cs),
        _ => Err(format!(
            "Could not recognize Circom file format: {}. Only .json and .r1cs are supported",
            path.display()
        )
        .into()),
    }
}

fn import_generic_constraints(
    generic_constraints: Vec<GenericConstraint>,
    declared_input_signal_ids: Option<Vec<usize>>,
    layout: ImportedCircomLayout,
) -> Result<ImportedCircomCircuit, Box<dyn Error>> {
    let has_declared_inputs = declared_input_signal_ids.is_some();
    let explicit_inputs = declared_input_signal_ids.unwrap_or_default();
    let explicit_input_set = explicit_inputs.iter().copied().collect::<HashSet<_>>();
    let preferred_output_set = layout
        .public_output_signal_ids
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    let generic_constraints = canonicalize_simple_aliases(
        generic_constraints,
        &explicit_input_set,
        &preferred_output_set,
    )?;
    let signal_stats = collect_signal_stats(&generic_constraints);
    let (signal_definitions, consumed_constraints) = extract_signal_definitions(
        &generic_constraints,
        &signal_stats,
        &explicit_input_set,
        &preferred_output_set,
    )?;

    let all_signal_ids = collect_signal_ids(&generic_constraints);
    let input_signal_ids = if !has_declared_inputs {
        all_signal_ids
            .iter()
            .copied()
            .filter(|signal_id| *signal_id != 0 && !signal_definitions.contains_key(signal_id))
            .collect::<Vec<_>>()
    } else {
        explicit_inputs
    };

    let root_signal_ids = collect_root_signal_ids(&signal_definitions, &layout);
    let (live_signal_ids, active_check_constraints) = if layout.public_output_signal_ids.is_empty()
    {
        let live_signal_ids = all_signal_ids
            .iter()
            .copied()
            .filter(|signal_id| *signal_id != 0)
            .collect::<HashSet<_>>();
        let active_check_constraints = generic_constraints
            .iter()
            .enumerate()
            .filter_map(|(constraint_idx, _)| {
                (!consumed_constraints.contains(&constraint_idx)).then_some(constraint_idx)
            })
            .collect::<HashSet<_>>();
        (live_signal_ids, active_check_constraints)
    } else {
        let live_signal_ids = collect_live_signal_ids(
            &root_signal_ids,
            &generic_constraints,
            &signal_definitions,
            &consumed_constraints,
        );
        let active_check_constraints = collect_active_check_constraints(
            &generic_constraints,
            &consumed_constraints,
            &live_signal_ids,
        );
        (live_signal_ids, active_check_constraints)
    };
    let linearly_definable_signal_ids =
        collect_linearly_definable_signal_ids(&generic_constraints, &active_check_constraints);

    let unknown_non_inputs = live_signal_ids
        .iter()
        .copied()
        .filter(|signal_id| {
            *signal_id != 0
                && !signal_definitions.contains_key(signal_id)
                && !input_signal_ids.contains(signal_id)
                && !linearly_definable_signal_ids.contains(signal_id)
        })
        .collect::<Vec<_>>();

    if !unknown_non_inputs.is_empty() {
        return Err(format!(
            "Import failed: found undefined signals that do not belong to external inputs: {:?}. This usually means the circuit depends on hint/witness assignment, which this path does not support for this kind of .r1cs",
            unknown_non_inputs
        )
        .into());
    }

    let (normalized_r1cs, witness_signal_to_index) = build_normalized_r1cs(
        &generic_constraints,
        &signal_definitions,
        &active_check_constraints,
        &input_signal_ids,
        &root_signal_ids,
    )?;

    let mut input_signal_to_index = HashMap::new();
    for (offset, signal_id) in input_signal_ids.iter().copied().enumerate() {
        input_signal_to_index.insert(signal_id, offset + 1);
    }

    Ok(ImportedCircomCircuit {
        normalized_r1cs,
        original_constraints: generic_constraints.len(),
        input_signal_ids,
        input_signal_to_index,
        witness_signal_to_index,
        layout,
    })
}

fn parse_generic_constraint(
    raw: [HashMap<String, String>; 3],
) -> Result<GenericConstraint, Box<dyn Error>> {
    let [a, b, c] = raw;
    Ok(GenericConstraint {
        a: parse_generic_lincomb(a)?,
        b: parse_generic_lincomb(b)?,
        c: parse_generic_lincomb(c)?,
    })
}

fn parse_generic_lincomb(raw: HashMap<String, String>) -> Result<GenericLinComb, Box<dyn Error>> {
    let mut terms = raw
        .into_iter()
        .map(|(signal, coeff)| {
            let signal_id = signal.parse::<usize>()?;
            let coeff =
                Fr::from_str(&coeff).map_err(|_| format!("Failed to parse Circom coefficient: {}", coeff))?;
            Ok((coeff, signal_id))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    terms.sort_by_key(|(_, signal_id)| *signal_id);
    Ok(GenericLinComb::from_terms(terms))
}

fn parse_binary_r1cs(
    bytes: &[u8],
) -> Result<(BinaryR1csHeader, Vec<GenericConstraint>), Box<dyn Error>> {
    let mut reader = Cursor::new(bytes);
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if &magic != b"r1cs" {
        return Err("Invalid .r1cs file: magic mismatch".into());
    }

    let version = read_u32(&mut reader)?;
    if version != 1 {
        return Err(format!("Unsupported .r1cs version: {}", version).into());
    }

    let num_sections = read_u32(&mut reader)? as usize;
    let mut sections = HashMap::new();
    for _ in 0..num_sections {
        let section_type = read_u32(&mut reader)?;
        let section_size = read_u64(&mut reader)? as usize;
        let mut section_bytes = vec![0u8; section_size];
        reader.read_exact(&mut section_bytes)?;
        sections.insert(section_type, section_bytes);
    }

    let header_bytes = sections
        .remove(&1)
        .ok_or("Missing R1CS header section (type 1)")?;
    let header = parse_binary_r1cs_header(&header_bytes)?;

    let expected_prime = pad_le_bytes(<Fr as PrimeField>::MODULUS.to_bytes_le(), header.field_size);
    if header.prime != expected_prime {
        return Err("Only .r1cs files over the BN254 scalar field are supported".into());
    }

    let constraints_bytes = sections
        .remove(&2)
        .ok_or("Missing R1CS constraints section (type 2)")?;
    let constraints = parse_binary_r1cs_constraints(&constraints_bytes, &header)?;

    if let Some(map_bytes) = sections.remove(&3) {
        validate_wire_to_label_section(&map_bytes, header.n_wires)?;
    }

    Ok((header, constraints))
}

fn parse_binary_r1cs_header(bytes: &[u8]) -> Result<BinaryR1csHeader, Box<dyn Error>> {
    let mut reader = Cursor::new(bytes);
    let field_size = read_u32(&mut reader)? as usize;
    if field_size == 0 || field_size % 8 != 0 {
        return Err(format!("Invalid field size: {}", field_size).into());
    }

    let mut prime = vec![0u8; field_size];
    reader.read_exact(&mut prime)?;

    let header = BinaryR1csHeader {
        field_size,
        prime,
        n_wires: read_u32(&mut reader)? as usize,
        n_pub_out: read_u32(&mut reader)? as usize,
        n_pub_in: read_u32(&mut reader)? as usize,
        n_prv_in: read_u32(&mut reader)? as usize,
        n_labels: read_u64(&mut reader)?,
        m_constraints: read_u32(&mut reader)? as usize,
    };

    if header.n_wires == 0 {
        return Err("Invalid .r1cs: nWires cannot be 0".into());
    }

    let reserved_wires = 1 + header.n_pub_out + header.n_pub_in + header.n_prv_in;
    if reserved_wires > header.n_wires {
        return Err(format!(
            "Invalid .r1cs: the total number of input/output wires {} exceeds nWires={}",
            reserved_wires, header.n_wires
        )
        .into());
    }

    let expected_min_labels = header.n_wires as u64;
    if header.n_labels < expected_min_labels {
        return Err(format!(
            "Invalid .r1cs: nLabels={} is less than nWires={}",
            header.n_labels, header.n_wires
        )
        .into());
    }

    if reader.position() != bytes.len() as u64 {
        return Err("R1CS header section length mismatch".into());
    }

    Ok(header)
}

fn parse_binary_r1cs_constraints(
    bytes: &[u8],
    header: &BinaryR1csHeader,
) -> Result<Vec<GenericConstraint>, Box<dyn Error>> {
    let mut reader = Cursor::new(bytes);
    let mut constraints = Vec::with_capacity(header.m_constraints);

    for _ in 0..header.m_constraints {
        let a = parse_binary_r1cs_lincomb(&mut reader, header)?;
        let b = parse_binary_r1cs_lincomb(&mut reader, header)?;
        let c = parse_binary_r1cs_lincomb(&mut reader, header)?;
        constraints.push(GenericConstraint { a, b, c });
    }

    if reader.position() != bytes.len() as u64 {
        return Err("R1CS constraints section length mismatch".into());
    }

    Ok(constraints)
}

fn parse_binary_r1cs_lincomb<R: Read>(
    reader: &mut R,
    header: &BinaryR1csHeader,
) -> Result<GenericLinComb, Box<dyn Error>> {
    let factor_count = read_u32(reader)? as usize;
    let mut terms = Vec::with_capacity(factor_count);

    for _ in 0..factor_count {
        let wire_id = read_u32(reader)? as usize;
        if wire_id >= header.n_wires {
            return Err(format!(
                "Invalid .r1cs: wire id {} exceeds nWires={}",
                wire_id, header.n_wires
            )
            .into());
        }

        let mut coeff_bytes = vec![0u8; header.field_size];
        reader.read_exact(&mut coeff_bytes)?;
        let coeff = Fr::from_le_bytes_mod_order(&coeff_bytes);
        terms.push((coeff, wire_id));
    }

    Ok(GenericLinComb::from_terms(terms))
}

fn validate_wire_to_label_section(bytes: &[u8], n_wires: usize) -> Result<(), Box<dyn Error>> {
    let expected_size = n_wires
        .checked_mul(8)
        .ok_or("wire2label section size overflow")?;
    if bytes.len() != expected_size {
        return Err(format!(
            "wire2label section length mismatch: expected {}, got {}",
            expected_size,
            bytes.len()
        )
        .into());
    }
    Ok(())
}

fn read_u32<R: Read>(reader: &mut R) -> Result<u32, Box<dyn Error>> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_u64<R: Read>(reader: &mut R) -> Result<u64, Box<dyn Error>> {
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

fn pad_le_bytes(mut bytes: Vec<u8>, size: usize) -> Vec<u8> {
    bytes.resize(size, 0);
    bytes
}

fn collect_signal_stats(constraints: &[GenericConstraint]) -> HashMap<usize, SignalStats> {
    let mut stats: HashMap<usize, SignalStats> = HashMap::new();

    for constraint in constraints {
        for (_, signal_id) in constraint.a.terms.iter().chain(constraint.b.terms.iter()) {
            if *signal_id != 0 {
                stats.entry(*signal_id).or_default().ab_occurrences += 1;
            }
        }

        for (_, signal_id) in &constraint.c.terms {
            if *signal_id != 0 {
                stats.entry(*signal_id).or_default().c_occurrences += 1;
            }
        }
    }

    stats
}

fn extract_signal_definitions(
    constraints: &[GenericConstraint],
    signal_stats: &HashMap<usize, SignalStats>,
    protected_signal_ids: &HashSet<usize>,
    preferred_signal_ids: &HashSet<usize>,
) -> Result<(HashMap<usize, SignalDefinition>, HashSet<usize>), Box<dyn Error>> {
    let mut definitions = HashMap::new();
    let mut consumed_constraints = HashSet::new();

    for (constraint_idx, constraint) in constraints.iter().enumerate() {
        if constraint.is_linear() {
            continue;
        }

        if let Some(target) = choose_definition_target(
            &constraint.c,
            signal_stats,
            &definitions,
            protected_signal_ids,
            preferred_signal_ids,
        ) {
            let coeff = constraint
                .c
                .coefficient_of(target)
                .ok_or_else(|| format!("Could not find target signal {} in the quadratic constraint", target))?;
            let inv = coeff
                .inverse()
                .ok_or_else(|| format!("The coefficient of signal {} is not invertible", target))?;
            let rest = constraint.c.without_signal(target);
            definitions.insert(
                target,
                SignalDefinition::Quadratic {
                    a: constraint.a.clone(),
                    b: constraint.b.clone(),
                    rest,
                    inv_coeff: inv,
                },
            );
            consumed_constraints.insert(constraint_idx);
        }
    }

    Ok((definitions, consumed_constraints))
}

fn choose_definition_target(
    lc: &GenericLinComb,
    signal_stats: &HashMap<usize, SignalStats>,
    definitions: &HashMap<usize, SignalDefinition>,
    protected_signal_ids: &HashSet<usize>,
    preferred_signal_ids: &HashSet<usize>,
) -> Option<usize> {
    let candidates = lc
        .terms
        .iter()
        .filter_map(|(_, signal_id)| {
            if *signal_id == 0
                || definitions.contains_key(signal_id)
                || protected_signal_ids.contains(signal_id)
            {
                return None;
            }
            let stats = signal_stats.get(signal_id)?;
            Some((*signal_id, stats))
        })
        .collect::<Vec<_>>();

    if let Some((signal_id, _)) = candidates
        .iter()
        .copied()
        .find(|(signal_id, _)| preferred_signal_ids.contains(signal_id))
    {
        return Some(signal_id);
    }

    if lc.terms.len() == 2 && lc.terms.iter().all(|(_, signal_id)| *signal_id != 0) {
        return candidates
            .into_iter()
            .max_by_key(|(signal_id, stats)| {
                (stats.c_occurrences, stats.ab_occurrences, *signal_id)
            })
            .map(|(signal_id, _)| signal_id);
    }

    candidates
        .into_iter()
        .min_by_key(|(signal_id, stats)| {
            (
                stats.c_occurrences,
                std::cmp::Reverse(stats.ab_occurrences),
                *signal_id,
            )
        })
        .map(|(signal_id, _)| signal_id)
}

fn is_simple_signal_alias(constraint: &GenericConstraint) -> bool {
    constraint.is_linear()
        && constraint.c.terms.len() == 2
        && constraint
            .c
            .terms
            .iter()
            .all(|(_, signal_id)| *signal_id != 0)
}

fn collect_signal_ids(constraints: &[GenericConstraint]) -> Vec<usize> {
    let mut signal_ids = HashSet::new();
    for constraint in constraints {
        for (_, signal_id) in constraint
            .a
            .terms
            .iter()
            .chain(constraint.b.terms.iter())
            .chain(constraint.c.terms.iter())
        {
            signal_ids.insert(*signal_id);
        }
    }

    let mut signal_ids = signal_ids.into_iter().collect::<Vec<_>>();
    signal_ids.sort_unstable();
    signal_ids
}

fn build_normalized_r1cs(
    constraints: &[GenericConstraint],
    signal_definitions: &HashMap<usize, SignalDefinition>,
    active_check_constraints: &HashSet<usize>,
    input_signal_ids: &[usize],
    root_signal_ids: &[usize],
) -> Result<(R1CS, HashMap<usize, usize>), Box<dyn Error>> {
    let input_signal_to_index = input_signal_ids
        .iter()
        .copied()
        .enumerate()
        .map(|(offset, signal_id)| (signal_id, offset + 1))
        .collect::<HashMap<_, _>>();

    let mut state = BuildState {
        r1cs: R1CS::new(input_signal_ids.len() + 1, 1),
        signal_defs: signal_definitions.clone(),
        signal_materialized: HashSet::new(),
        signal_in_progress: HashSet::new(),
        linear_signal_in_progress: HashSet::new(),
        input_signal_to_index,
        witness_signal_to_index: HashMap::new(),
        next_witness: 2,
        zero_witness: None,
        input_lift_cache: HashMap::new(),
        constraints,
        linear_constraints_by_signal: index_linear_constraints_by_signal(
            constraints,
            active_check_constraints,
        ),
        used_linear_constraints: HashSet::new(),
    };

    for &signal_id in root_signal_ids {
        state.materialize_signal(signal_id)?;
    }

    for (constraint_idx, constraint) in constraints.iter().enumerate() {
        if !active_check_constraints.contains(&constraint_idx) {
            continue;
        }
        if state.used_linear_constraints.contains(&constraint_idx) {
            continue;
        }
        state.materialize_check_constraint(constraint)?;
    }

    state.r1cs.num_witnesses = state.next_witness - 1;
    Ok((state.r1cs, state.witness_signal_to_index))
}

impl GenericLinComb {
    fn from_terms(terms: Vec<(Fr, usize)>) -> Self {
        Self {
            terms: normalize_generic_terms(terms),
        }
    }

    fn is_zero(&self) -> bool {
        self.terms.is_empty()
    }

    fn without_signal(&self, signal_id: usize) -> Self {
        Self::from_terms(
            self.terms
                .iter()
                .filter(|(_, current_signal_id)| *current_signal_id != signal_id)
                .copied()
                .collect(),
        )
    }

    fn coefficient_of(&self, signal_id: usize) -> Option<Fr> {
        self.terms.iter().find_map(|(coeff, current_signal_id)| {
            (*current_signal_id == signal_id).then_some(*coeff)
        })
    }

    fn scale(&self, scalar: Fr) -> Self {
        Self::from_terms(
            self.terms
                .iter()
                .map(|(coeff, signal_id)| (*coeff * scalar, *signal_id))
                .collect(),
        )
    }
}

impl GenericConstraint {
    fn is_linear(&self) -> bool {
        self.a.is_zero() || self.b.is_zero()
    }
}

impl<'a> BuildState<'a> {
    fn ensure_signal_definition(&mut self, signal_id: usize) -> Result<(), Box<dyn Error>> {
        if self.input_signal_to_index.contains_key(&signal_id)
            || self.signal_defs.contains_key(&signal_id)
        {
            return Ok(());
        }

        self.solve_linear_signal(signal_id)
    }

    fn solve_linear_signal(&mut self, signal_id: usize) -> Result<(), Box<dyn Error>> {
        if self.input_signal_to_index.contains_key(&signal_id)
            || self.signal_defs.contains_key(&signal_id)
        {
            return Ok(());
        }

        if !self.linear_signal_in_progress.insert(signal_id) {
            return Err(format!("Detected cyclic linear resolution for Circom signal {}", signal_id).into());
        }

        let candidate_indices = self
            .linear_constraints_by_signal
            .get(&signal_id)
            .cloned()
            .unwrap_or_default();

        for constraint_idx in candidate_indices {
            if self.used_linear_constraints.contains(&constraint_idx) {
                continue;
            }

            let constraint = &self.constraints[constraint_idx];
            let Some(coeff) = constraint.c.coefficient_of(signal_id) else {
                continue;
            };
            let Some(inv) = coeff.inverse() else {
                continue;
            };
            let expr = constraint.c.without_signal(signal_id).scale(-inv);

            let mut deps = expr
                .terms
                .iter()
                .map(|(_, dep_signal_id)| *dep_signal_id)
                .filter(|dep_signal_id| {
                    *dep_signal_id != 0 && !self.input_signal_to_index.contains_key(dep_signal_id)
                })
                .collect::<Vec<_>>();
            deps.sort_unstable();
            deps.dedup();

            let mut solvable = true;
            for dep_signal_id in deps {
                if self.signal_defs.contains_key(&dep_signal_id) {
                    continue;
                }
                if self.solve_linear_signal(dep_signal_id).is_err() {
                    solvable = false;
                    break;
                }
            }

            if !solvable {
                continue;
            }

            self.signal_defs
                .insert(signal_id, SignalDefinition::Linear(expr));
            self.used_linear_constraints.insert(constraint_idx);
            self.linear_signal_in_progress.remove(&signal_id);
            return Ok(());
        }

        self.linear_signal_in_progress.remove(&signal_id);
        Err(format!("Signal {} has no solvable linear definition", signal_id).into())
    }

    fn materialize_signal(&mut self, signal_id: usize) -> Result<usize, Box<dyn Error>> {
        if self.input_signal_to_index.contains_key(&signal_id) {
            return Err(format!("Signal {} is an input and cannot be materialized as a witness", signal_id).into());
        }

        self.ensure_signal_definition(signal_id)?;

        let witness_idx = self.ensure_signal_witness_index(signal_id);

        if self.signal_materialized.contains(&signal_id) {
            return Ok(witness_idx);
        }
        if !self.signal_in_progress.insert(signal_id) {
            return Err(format!("Detected cyclic definition for Circom signal {}", signal_id).into());
        }

        let definition = self
            .signal_defs
            .get(&signal_id)
            .cloned()
            .ok_or_else(|| format!("Signal {} is not defined", signal_id))?;

        match definition {
            SignalDefinition::Linear(expr) => {
                self.define_witness_from_generic_lincomb(witness_idx, &expr)?;
            }
            SignalDefinition::Quadratic {
                a,
                b,
                rest,
                inv_coeff,
            } => {
                if rest.is_zero()
                    && self.try_define_direct_quadratic_output(witness_idx, &a, &b, inv_coeff)?
                {
                    self.signal_in_progress.remove(&signal_id);
                    self.signal_materialized.insert(signal_id);
                    return Ok(witness_idx);
                }

                let left = self.materialize_generic_lincomb_as_witness(&a)?;
                let right = self.materialize_generic_lincomb_as_witness(&b)?;
                let product = self.define_mul_witness(left, right);

                let mut terms = vec![(inv_coeff, product)];
                if !rest.is_zero() {
                    let rest_witness =
                        self.materialize_generic_lincomb_as_witness(&rest.scale(-inv_coeff))?;
                    terms.push((Fr::one(), rest_witness));
                }

                self.define_witness_from_witness_terms(witness_idx, terms);
            }
        }

        self.signal_in_progress.remove(&signal_id);
        self.signal_materialized.insert(signal_id);
        Ok(witness_idx)
    }

    fn materialize_check_constraint(
        &mut self,
        constraint: &GenericConstraint,
    ) -> Result<(), Box<dyn Error>> {
        let left = self.materialize_generic_lincomb_as_witness(&constraint.a)?;
        let right = self.materialize_generic_lincomb_as_witness(&constraint.b)?;
        let product = self.define_mul_witness(left, right);
        let expected = self.materialize_generic_lincomb_as_witness(&constraint.c)?;
        let zero = self.ensure_zero_witness();

        self.r1cs.constraints.push(Constraint {
            a: LinComb::from_var(Variable::Input(0)),
            b: LinComb::from_terms(vec![
                (Fr::one(), Variable::Witness(product)),
                (fr_from_i64(-1), Variable::Witness(expected)),
            ]),
            c: LinComb::from_var(Variable::Witness(zero)),
        });

        Ok(())
    }

    fn materialize_generic_lincomb_as_witness(
        &mut self,
        expr: &GenericLinComb,
    ) -> Result<usize, Box<dyn Error>> {
        if expr.is_zero() {
            return Ok(self.ensure_zero_witness());
        }

        let (input_terms, mut witness_terms) = self.decompose_generic_lincomb(expr)?;

        if !input_terms.is_empty() {
            let lifted = self.lift_input_lincomb_to_witness(&input_terms);
            witness_terms.push((Fr::one(), lifted));
        }

        if witness_terms.len() == 1 && witness_terms[0].0 == Fr::one() {
            return Ok(witness_terms[0].1);
        }

        let output = self.allocate_helper_witness();
        self.define_witness_from_witness_terms(output, witness_terms);
        Ok(output)
    }

    fn define_witness_from_generic_lincomb(
        &mut self,
        output_witness: usize,
        expr: &GenericLinComb,
    ) -> Result<(), Box<dyn Error>> {
        if expr.is_zero() {
            self.define_witness_from_witness_terms(
                output_witness,
                vec![(Fr::one(), 1usize), (fr_from_i64(-1), 1usize)],
            );
            return Ok(());
        }

        let (input_terms, mut witness_terms) = self.decompose_generic_lincomb(expr)?;

        if input_terms.is_empty() {
            self.define_witness_from_witness_terms(output_witness, witness_terms);
            return Ok(());
        }

        if witness_terms.is_empty() {
            self.r1cs.add_constraint(
                Constraint {
                    a: input_terms_to_lincomb(&input_terms),
                    b: LinComb::from_var(Variable::Witness(1)),
                    c: LinComb::from_var(Variable::Witness(output_witness)),
                },
                output_witness,
            );
            return Ok(());
        }

        let lifted = self.lift_input_lincomb_to_witness(&input_terms);
        witness_terms.push((Fr::one(), lifted));
        self.define_witness_from_witness_terms(output_witness, witness_terms);
        Ok(())
    }

    fn decompose_generic_lincomb(
        &mut self,
        expr: &GenericLinComb,
    ) -> Result<(Vec<(Fr, usize)>, Vec<(Fr, usize)>), Box<dyn Error>> {
        let mut witness_terms = Vec::new();
        let mut input_terms = Vec::new();
        let mut expanding_linear = HashSet::new();

        for (coeff, signal_id) in &expr.terms {
            self.collect_expanded_term(
                *coeff,
                *signal_id,
                &mut expanding_linear,
                &mut input_terms,
                &mut witness_terms,
            )?;
        }

        Ok((
            normalize_index_terms(input_terms),
            normalize_index_terms(witness_terms),
        ))
    }

    fn try_define_direct_quadratic_output(
        &mut self,
        output_witness: usize,
        left: &GenericLinComb,
        right: &GenericLinComb,
        output_scale: Fr,
    ) -> Result<bool, Box<dyn Error>> {
        if let Some(input_terms) = self.input_terms_only(left) {
            let scaled_inputs = scale_terms(&input_terms, output_scale);
            let (right_inputs, right_witnesses) = self.decompose_generic_lincomb(right)?;

            if !right_inputs.is_empty() && right_witnesses.is_empty() {
                self.r1cs.add_constraint(
                    Constraint {
                        a: input_terms_to_lincomb(&scaled_inputs),
                        b: input_terms_to_lincomb(&right_inputs),
                        c: LinComb::from_var(Variable::Witness(output_witness)),
                    },
                    output_witness,
                );
                return Ok(true);
            }

            if right_inputs.is_empty() {
                self.r1cs.add_constraint(
                    Constraint {
                        a: input_terms_to_lincomb(&scaled_inputs),
                        b: witness_terms_to_lincomb(&right_witnesses),
                        c: LinComb::from_var(Variable::Witness(output_witness)),
                    },
                    output_witness,
                );
                return Ok(true);
            }

            let lifted_right = self.materialize_generic_lincomb_as_witness(right)?;
            self.r1cs.add_constraint(
                Constraint {
                    a: input_terms_to_lincomb(&scaled_inputs),
                    b: LinComb::from_var(Variable::Witness(lifted_right)),
                    c: LinComb::from_var(Variable::Witness(output_witness)),
                },
                output_witness,
            );
            return Ok(true);
        }

        if let Some(input_terms) = self.input_terms_only(right) {
            let scaled_inputs = scale_terms(&input_terms, output_scale);
            let (left_inputs, left_witnesses) = self.decompose_generic_lincomb(left)?;

            if !left_inputs.is_empty() && left_witnesses.is_empty() {
                self.r1cs.add_constraint(
                    Constraint {
                        a: input_terms_to_lincomb(&scaled_inputs),
                        b: input_terms_to_lincomb(&left_inputs),
                        c: LinComb::from_var(Variable::Witness(output_witness)),
                    },
                    output_witness,
                );
                return Ok(true);
            }

            if left_inputs.is_empty() {
                self.r1cs.add_constraint(
                    Constraint {
                        a: input_terms_to_lincomb(&scaled_inputs),
                        b: witness_terms_to_lincomb(&left_witnesses),
                        c: LinComb::from_var(Variable::Witness(output_witness)),
                    },
                    output_witness,
                );
                return Ok(true);
            }

            let lifted_left = self.materialize_generic_lincomb_as_witness(left)?;
            self.r1cs.add_constraint(
                Constraint {
                    a: input_terms_to_lincomb(&scaled_inputs),
                    b: LinComb::from_var(Variable::Witness(lifted_left)),
                    c: LinComb::from_var(Variable::Witness(output_witness)),
                },
                output_witness,
            );
            return Ok(true);
        }

        Ok(false)
    }

    fn input_terms_only(&self, expr: &GenericLinComb) -> Option<Vec<(Fr, usize)>> {
        let mut input_terms = Vec::with_capacity(expr.terms.len());

        for (coeff, signal_id) in &expr.terms {
            if *signal_id == 0 {
                return None;
            }

            let input_idx = *self.input_signal_to_index.get(signal_id)?;
            input_terms.push((*coeff, input_idx));
        }

        Some(input_terms)
    }

    fn collect_expanded_term(
        &mut self,
        coeff: Fr,
        signal_id: usize,
        expanding_linear: &mut HashSet<usize>,
        input_terms: &mut Vec<(Fr, usize)>,
        witness_terms: &mut Vec<(Fr, usize)>,
    ) -> Result<(), Box<dyn Error>> {
        if coeff.is_zero() {
            return Ok(());
        }

        match signal_id {
            0 => {
                witness_terms.push((coeff, 1));
                Ok(())
            }
            signal_id if self.input_signal_to_index.contains_key(&signal_id) => {
                input_terms.push((coeff, self.input_signal_to_index[&signal_id]));
                Ok(())
            }
            signal_id => {
                self.ensure_signal_definition(signal_id)?;
                let definition = self
                    .signal_defs
                    .get(&signal_id)
                    .cloned()
                    .ok_or_else(|| format!("Signal {} is not defined", signal_id))?;

                match definition {
                    SignalDefinition::Linear(expr) => {
                        if !expanding_linear.insert(signal_id) {
                            return Err(format!(
                                "Detected cyclic linear definition for Circom signal {}",
                                signal_id
                            )
                            .into());
                        }

                        for (inner_coeff, inner_signal_id) in expr.terms {
                            self.collect_expanded_term(
                                coeff * inner_coeff,
                                inner_signal_id,
                                expanding_linear,
                                input_terms,
                                witness_terms,
                            )?;
                        }

                        expanding_linear.remove(&signal_id);
                        Ok(())
                    }
                    SignalDefinition::Quadratic { .. } => {
                        let witness_idx = self.materialize_signal(signal_id)?;
                        witness_terms.push((coeff, witness_idx));
                        Ok(())
                    }
                }
            }
        }
    }

    fn define_witness_from_witness_terms(
        &mut self,
        output_witness: usize,
        terms: Vec<(Fr, usize)>,
    ) {
        self.r1cs.add_constraint(
            Constraint {
                a: LinComb::from_var(Variable::Input(0)),
                b: LinComb::from_terms(
                    terms
                        .into_iter()
                        .map(|(coeff, witness)| (coeff, Variable::Witness(witness)))
                        .collect(),
                ),
                c: LinComb::from_var(Variable::Witness(output_witness)),
            },
            output_witness,
        );
    }

    fn lift_input_lincomb_to_witness(&mut self, input_terms: &[(Fr, usize)]) -> usize {
        let key = terms_key(input_terms);
        if let Some(&cached) = self.input_lift_cache.get(&key) {
            return cached;
        }

        let output_witness = self.allocate_helper_witness();
        self.r1cs.add_constraint(
            Constraint {
                a: LinComb::from_terms(
                    input_terms
                        .iter()
                        .map(|(coeff, input_idx)| (*coeff, Variable::Input(*input_idx)))
                        .collect(),
                ),
                b: LinComb::from_var(Variable::Witness(1)),
                c: LinComb::from_var(Variable::Witness(output_witness)),
            },
            output_witness,
        );
        self.input_lift_cache.insert(key, output_witness);
        output_witness
    }

    fn define_mul_witness(&mut self, left: usize, right: usize) -> usize {
        let output_witness = self.allocate_helper_witness();
        self.r1cs.add_constraint(
            Constraint {
                a: LinComb::from_var(Variable::Witness(left)),
                b: LinComb::from_var(Variable::Witness(right)),
                c: LinComb::from_var(Variable::Witness(output_witness)),
            },
            output_witness,
        );
        output_witness
    }

    fn ensure_zero_witness(&mut self) -> usize {
        if let Some(zero) = self.zero_witness {
            return zero;
        }

        let output_witness = self.allocate_helper_witness();
        self.define_witness_from_witness_terms(
            output_witness,
            vec![(Fr::one(), 1usize), (fr_from_i64(-1), 1usize)],
        );
        self.zero_witness = Some(output_witness);
        output_witness
    }

    fn allocate_helper_witness(&mut self) -> usize {
        let witness = self.next_witness;
        self.next_witness += 1;
        witness
    }

    fn ensure_signal_witness_index(&mut self, signal_id: usize) -> usize {
        if let Some(&witness_idx) = self.witness_signal_to_index.get(&signal_id) {
            return witness_idx;
        }

        let witness_idx = self.next_witness;
        self.next_witness += 1;
        self.witness_signal_to_index.insert(signal_id, witness_idx);
        witness_idx
    }
}

fn normalize_generic_terms(mut terms: Vec<(Fr, usize)>) -> Vec<(Fr, usize)> {
    if terms.is_empty() {
        return terms;
    }

    terms.sort_by_key(|(_, signal_id)| *signal_id);
    let mut merged = Vec::new();

    for (coeff, signal_id) in terms {
        if coeff.is_zero() {
            continue;
        }

        if let Some((last_coeff, last_signal_id)) = merged.last_mut() {
            if *last_signal_id == signal_id {
                *last_coeff += coeff;
                continue;
            }
        }

        merged.push((coeff, signal_id));
    }

    merged
        .into_iter()
        .filter(|(coeff, _)| !coeff.is_zero())
        .collect()
}

fn normalize_index_terms(mut terms: Vec<(Fr, usize)>) -> Vec<(Fr, usize)> {
    if terms.is_empty() {
        return terms;
    }

    terms.sort_by_key(|(_, idx)| *idx);
    let mut merged = Vec::new();

    for (coeff, idx) in terms {
        if coeff.is_zero() {
            continue;
        }

        if let Some((last_coeff, last_idx)) = merged.last_mut() {
            if *last_idx == idx {
                *last_coeff += coeff;
                continue;
            }
        }

        merged.push((coeff, idx));
    }

    merged
        .into_iter()
        .filter(|(coeff, _)| !coeff.is_zero())
        .collect()
}

fn collect_root_signal_ids(
    signal_definitions: &HashMap<usize, SignalDefinition>,
    layout: &ImportedCircomLayout,
) -> Vec<usize> {
    if !layout.public_output_signal_ids.is_empty() {
        return layout
            .public_output_signal_ids
            .iter()
            .copied()
            .filter(|signal_id| *signal_id != 0)
            .collect();
    }

    let mut all = signal_definitions.keys().copied().collect::<Vec<_>>();
    all.sort_unstable();
    all
}

fn collect_linearly_definable_signal_ids(
    constraints: &[GenericConstraint],
    active_check_constraints: &HashSet<usize>,
) -> HashSet<usize> {
    let mut signal_ids = HashSet::new();

    for (constraint_idx, constraint) in constraints.iter().enumerate() {
        if !active_check_constraints.contains(&constraint_idx) || !constraint.is_linear() {
            continue;
        }

        for (_, signal_id) in &constraint.c.terms {
            if *signal_id != 0 {
                signal_ids.insert(*signal_id);
            }
        }
    }

    signal_ids
}

fn index_linear_constraints_by_signal(
    constraints: &[GenericConstraint],
    active_check_constraints: &HashSet<usize>,
) -> HashMap<usize, Vec<usize>> {
    let mut index = HashMap::<usize, Vec<usize>>::new();

    for (constraint_idx, constraint) in constraints.iter().enumerate() {
        if !active_check_constraints.contains(&constraint_idx) || !constraint.is_linear() {
            continue;
        }

        for (_, signal_id) in &constraint.c.terms {
            if *signal_id == 0 {
                continue;
            }
            index.entry(*signal_id).or_default().push(constraint_idx);
        }
    }

    index
}

fn collect_live_signal_ids(
    root_signal_ids: &[usize],
    constraints: &[GenericConstraint],
    signal_definitions: &HashMap<usize, SignalDefinition>,
    consumed_constraints: &HashSet<usize>,
) -> HashSet<usize> {
    let mut live_signal_ids = root_signal_ids.iter().copied().collect::<HashSet<_>>();

    loop {
        let mut changed = false;
        let snapshot = live_signal_ids.iter().copied().collect::<Vec<_>>();

        for signal_id in snapshot {
            if let Some(definition) = signal_definitions.get(&signal_id) {
                for dependency in definition_signal_ids(definition) {
                    if dependency != 0 && live_signal_ids.insert(dependency) {
                        changed = true;
                    }
                }
            }
        }

        for (constraint_idx, constraint) in constraints.iter().enumerate() {
            if consumed_constraints.contains(&constraint_idx) {
                continue;
            }

            let signal_ids = constraint_signal_ids(constraint);
            if signal_ids
                .iter()
                .any(|signal_id| live_signal_ids.contains(signal_id))
            {
                for signal_id in signal_ids {
                    if signal_id != 0 && live_signal_ids.insert(signal_id) {
                        changed = true;
                    }
                }
            }
        }

        if !changed {
            return live_signal_ids;
        }
    }
}

fn collect_active_check_constraints(
    constraints: &[GenericConstraint],
    consumed_constraints: &HashSet<usize>,
    live_signal_ids: &HashSet<usize>,
) -> HashSet<usize> {
    constraints
        .iter()
        .enumerate()
        .filter_map(|(constraint_idx, constraint)| {
            if consumed_constraints.contains(&constraint_idx) {
                return None;
            }

            constraint_signal_ids(constraint)
                .iter()
                .any(|signal_id| live_signal_ids.contains(signal_id))
                .then_some(constraint_idx)
        })
        .collect()
}

fn definition_signal_ids(definition: &SignalDefinition) -> Vec<usize> {
    match definition {
        SignalDefinition::Linear(expr) => lincomb_signal_ids(expr),
        SignalDefinition::Quadratic { a, b, rest, .. } => {
            let mut signal_ids = lincomb_signal_ids(a);
            signal_ids.extend(lincomb_signal_ids(b));
            signal_ids.extend(lincomb_signal_ids(rest));
            signal_ids.sort_unstable();
            signal_ids.dedup();
            signal_ids
        }
    }
}

fn constraint_signal_ids(constraint: &GenericConstraint) -> Vec<usize> {
    let mut signal_ids = lincomb_signal_ids(&constraint.a);
    signal_ids.extend(lincomb_signal_ids(&constraint.b));
    signal_ids.extend(lincomb_signal_ids(&constraint.c));
    signal_ids.sort_unstable();
    signal_ids.dedup();
    signal_ids
}

fn lincomb_signal_ids(expr: &GenericLinComb) -> Vec<usize> {
    expr.terms
        .iter()
        .map(|(_, signal_id)| *signal_id)
        .filter(|signal_id| *signal_id != 0)
        .collect()
}

fn scale_terms(terms: &[(Fr, usize)], scalar: Fr) -> Vec<(Fr, usize)> {
    terms
        .iter()
        .map(|(coeff, idx)| (*coeff * scalar, *idx))
        .collect()
}

fn input_terms_to_lincomb(terms: &[(Fr, usize)]) -> LinComb {
    LinComb::from_terms(
        terms
            .iter()
            .map(|(coeff, input_idx)| (*coeff, Variable::Input(*input_idx)))
            .collect(),
    )
}

fn witness_terms_to_lincomb(terms: &[(Fr, usize)]) -> LinComb {
    LinComb::from_terms(
        terms
            .iter()
            .map(|(coeff, witness_idx)| (*coeff, Variable::Witness(*witness_idx)))
            .collect(),
    )
}

fn terms_key(terms: &[(Fr, usize)]) -> String {
    let mut normalized = terms.to_vec();
    normalized.sort_by_key(|(_, idx)| *idx);
    normalized
        .into_iter()
        .map(|(coeff, idx)| format!("{}@{}", coeff.into_bigint(), idx))
        .collect::<Vec<_>>()
        .join("|")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evalr1cs::{execute_circuit, verify_assignment, Assignment};
    use crate::utils::fr_to_u64;

    #[test]
    fn imports_circom_o0_json_and_preserves_basic_multiplier_semantics() {
        let circom_json = r#"{
          "constraints": [
            [{},{},{"2":"1","5":"21888242871839275222246405745257275088548364400416034343698204186575808495616"}],
            [{},{},{"0":"1","2":"2","3":"1","6":"21888242871839275222246405745257275088548364400416034343698204186575808495616"}],
            [{},{},{"1":"21888242871839275222246405745257275088548364400416034343698204186575808495616","4":"1"}],
            [{"5":"21888242871839275222246405745257275088548364400416034343698204186575808495616"},{"6":"1"},{"4":"21888242871839275222246405745257275088548364400416034343698204186575808495616"}]
          ]
        }"#;

        let file = tempfile_path("basic_constraints.json");
        fs::write(&file, circom_json).expect("Failed to write circom fixture");

        let imported = import_circom_constraints_json(&file).expect("Failed to import circom json");
        assert_eq!(imported.original_constraints, 2);
        assert!(imported.normalized_r1cs.constraints.len() >= 4);
        assert_eq!(imported.input_signal_ids, vec![2, 3, 6]);

        let input_x2 = imported.input_signal_to_index[&2];
        let input_x3 = imported.input_signal_to_index[&3];
        let input_x6 = imported.input_signal_to_index[&6];
        let mut assignment = Assignment::new(vec![(input_x2, 3), (input_x3, 11), (input_x6, 18)]);

        assert!(execute_circuit(&imported.normalized_r1cs, &mut assignment).is_some());
        assert!(verify_assignment(&imported.normalized_r1cs, &assignment));

        let output_witness = imported.witness_signal_to_index[&1];
        let output = fr_to_u64(&assignment.witnesses[&output_witness]).expect("Output exceeds u64");
        assert_eq!(output, 54);

        let transformed = choudhuri_transform(&imported.normalized_r1cs);
        let (optimized, _) = eliminate_common_subexpressions(&transformed.r1cs);
        assert!(optimized
            .constraints
            .iter()
            .all(|constraint| constraint.is_rms_compatible()));
    }

    #[test]
    fn imports_official_circomlib_and_fixture_and_preserves_truth_table() {
        let imported = import_circom_constraints_json("./fixtures/circomlib_and.json")
            .expect("Failed to import circomlib AND fixture");

        assert_eq!(imported.original_constraints, 1);
        assert_eq!(imported.input_signal_ids, vec![2, 3]);

        let output_witness = imported.witness_signal_to_index[&1];
        let transformed = choudhuri_transform(&imported.normalized_r1cs);
        let (optimized, _) = eliminate_common_subexpressions(&transformed.r1cs);

        for (a, b, expected) in [(0u64, 0u64, 0u64), (0, 1, 0), (1, 0, 0), (1, 1, 1)] {
            let mut original_assignment = Assignment::new(vec![
                (imported.input_signal_to_index[&2], a),
                (imported.input_signal_to_index[&3], b),
            ]);
            assert!(execute_circuit(&imported.normalized_r1cs, &mut original_assignment).is_some());
            assert!(verify_assignment(
                &imported.normalized_r1cs,
                &original_assignment
            ));
            let original_output =
                fr_to_u64(&original_assignment.witnesses[&output_witness]).expect("Output exceeds u64");

            let mut optimized_assignment = Assignment::new(vec![
                (imported.input_signal_to_index[&2], a),
                (imported.input_signal_to_index[&3], b),
            ]);
            assert!(execute_circuit(&optimized, &mut optimized_assignment).is_some());
            assert!(verify_assignment(&optimized, &optimized_assignment));
            let optimized_output =
                fr_to_u64(&optimized_assignment.witnesses[&output_witness]).expect("Output exceeds u64");

            assert_eq!(
                original_output, expected,
                "Original circuit output incorrect: a={}, b={}",
                a, b
            );
            assert_eq!(
                optimized_output, expected,
                "Transformed output incorrect: a={}, b={}",
                a, b
            );
        }
    }

    #[test]
    fn imports_binary_r1cs_and_preserves_truth_table() {
        let file = tempfile_path("circomlib_and.r1cs");
        fs::write(&file, build_binary_and_r1cs_fixture()).expect("Failed to write .r1cs fixture");

        let imported = import_circom_r1cs(&file).expect("Failed to import binary .r1cs");
        assert_eq!(imported.original_constraints, 1);
        assert_eq!(imported.input_signal_ids, vec![2, 3]);

        let output_witness = imported.witness_signal_to_index[&1];
        let (transformed, optimized, eliminated) = optimize_circom_r1cs(&imported.normalized_r1cs);
        assert_eq!(
            transformed.r1cs.constraints.len(),
            optimized.constraints.len()
        );
        assert_eq!(eliminated, 0);

        for (a, b, expected) in [(0u64, 0u64, 0u64), (0, 1, 0), (1, 0, 0), (1, 1, 1)] {
            let mut original_assignment = Assignment::new(vec![
                (imported.input_signal_to_index[&2], a),
                (imported.input_signal_to_index[&3], b),
            ]);
            assert!(execute_circuit(&imported.normalized_r1cs, &mut original_assignment).is_some());
            assert!(verify_assignment(
                &imported.normalized_r1cs,
                &original_assignment
            ));
            let original_output =
                fr_to_u64(&original_assignment.witnesses[&output_witness]).expect("Output exceeds u64");

            let mut optimized_assignment = Assignment::new(vec![
                (imported.input_signal_to_index[&2], a),
                (imported.input_signal_to_index[&3], b),
            ]);
            assert!(execute_circuit(&optimized, &mut optimized_assignment).is_some());
            assert!(verify_assignment(&optimized, &optimized_assignment));
            let optimized_output =
                fr_to_u64(&optimized_assignment.witnesses[&output_witness]).expect("Output exceeds u64");

            assert_eq!(
                original_output, expected,
                "Original binary-imported circuit output incorrect: a={}, b={}",
                a, b
            );
            assert_eq!(
                optimized_output, expected,
                "Transformed binary-imported circuit output incorrect: a={}, b={}",
                a, b
            );
        }
    }

    #[test]
    fn ignores_dead_unknown_signals_when_reachable_graph_is_well_formed() {
        let constraints = vec![
            GenericConstraint {
                a: GenericLinComb::default(),
                b: GenericLinComb::default(),
                c: GenericLinComb::from_terms(vec![(fr_from_i64(-1), 1), (Fr::one(), 2)]),
            },
            GenericConstraint {
                a: GenericLinComb::from_terms(vec![(Fr::one(), 5)]),
                b: GenericLinComb::from_terms(vec![(Fr::one(), 6)]),
                c: GenericLinComb::from_terms(vec![(Fr::one(), 7)]),
            },
        ];

        let imported = import_generic_constraints(
            constraints,
            Some(vec![2]),
            ImportedCircomLayout {
                public_output_signal_ids: vec![1],
                public_input_signal_ids: vec![2],
                private_input_signal_ids: vec![],
            },
        )
        .expect("Dead signals should not block import");

        assert_eq!(imported.input_signal_ids, vec![2]);
        assert!(!imported.witness_signal_to_index.contains_key(&5));
        assert!(!imported.witness_signal_to_index.contains_key(&6));
        assert!(!imported.witness_signal_to_index.contains_key(&7));

        let mut assignment = Assignment::new(vec![(imported.input_signal_to_index[&2], 9)]);
        assert!(execute_circuit(&imported.normalized_r1cs, &mut assignment).is_some());
        assert!(verify_assignment(&imported.normalized_r1cs, &assignment));

        let output_witness = imported.witness_signal_to_index[&1];
        let output = fr_to_u64(&assignment.witnesses[&output_witness]).expect("Output exceeds u64");
        assert_eq!(output, 9);
    }

    fn tempfile_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("rms_test_{}_{}", std::process::id(), name))
    }

    fn build_binary_and_r1cs_fixture() -> Vec<u8> {
        let field_size = 32usize;
        let header = build_header_section(field_size, 4, 1, 2, 0, 4, 1);
        let constraints = build_constraints_section(&[(
            vec![(2u32, Fr::one())],
            vec![(3u32, Fr::one())],
            vec![(1u32, Fr::one())],
        )]);
        let wire_map = build_wire_map_section(&[0, 1, 2, 3]);

        let mut file = Vec::new();
        file.extend_from_slice(b"r1cs");
        file.extend_from_slice(&1u32.to_le_bytes());
        file.extend_from_slice(&3u32.to_le_bytes());
        append_section(&mut file, 1, &header);
        append_section(&mut file, 2, &constraints);
        append_section(&mut file, 3, &wire_map);
        file
    }

    fn build_header_section(
        field_size: usize,
        n_wires: u32,
        n_pub_out: u32,
        n_pub_in: u32,
        n_prv_in: u32,
        n_labels: u64,
        m_constraints: u32,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(field_size as u32).to_le_bytes());
        bytes.extend_from_slice(&pad_le_bytes(
            <Fr as PrimeField>::MODULUS.to_bytes_le(),
            field_size,
        ));
        bytes.extend_from_slice(&n_wires.to_le_bytes());
        bytes.extend_from_slice(&n_pub_out.to_le_bytes());
        bytes.extend_from_slice(&n_pub_in.to_le_bytes());
        bytes.extend_from_slice(&n_prv_in.to_le_bytes());
        bytes.extend_from_slice(&n_labels.to_le_bytes());
        bytes.extend_from_slice(&m_constraints.to_le_bytes());
        bytes
    }

    fn build_constraints_section(
        constraints: &[(Vec<(u32, Fr)>, Vec<(u32, Fr)>, Vec<(u32, Fr)>)],
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        for (a, b, c) in constraints {
            append_lincomb(&mut bytes, a);
            append_lincomb(&mut bytes, b);
            append_lincomb(&mut bytes, c);
        }
        bytes
    }

    fn append_lincomb(bytes: &mut Vec<u8>, lincomb: &[(u32, Fr)]) {
        bytes.extend_from_slice(&(lincomb.len() as u32).to_le_bytes());
        for (wire_id, coeff) in lincomb {
            bytes.extend_from_slice(&wire_id.to_le_bytes());
            bytes.extend_from_slice(&pad_le_bytes(coeff.into_bigint().to_bytes_le(), 32));
        }
    }

    fn build_wire_map_section(labels: &[u64]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for label in labels {
            bytes.extend_from_slice(&label.to_le_bytes());
        }
        bytes
    }

    fn append_section(file: &mut Vec<u8>, section_type: u32, payload: &[u8]) {
        file.extend_from_slice(&section_type.to_le_bytes());
        file.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        file.extend_from_slice(payload);
    }
}
