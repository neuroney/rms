//! Core R1CS and RMS export data structures plus basic circuit statistics helpers.

use ark_bn254::Fr;
use ark_ff::{BigInt, PrimeField};
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::str::FromStr;

/// Represents variables in the constraint system.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Variable {
    Input(usize),   // Input slot, index starts from 0; RMS exports reserve x0 = 1 as public
    Witness(usize), // Private witness, index starts from 1
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FieldElement {
    bytes: [u8; 32],
}

impl FieldElement {
    pub const BYTE_LEN: usize = 32;
    pub const ZERO: Self = Self { bytes: [0; 32] };

    pub fn from_fr(value: Fr) -> Self {
        let bigint = value.into_bigint();
        let mut bytes = [0u8; Self::BYTE_LEN];
        for (chunk, limb) in bytes.chunks_exact_mut(8).zip(bigint.0.iter()) {
            chunk.copy_from_slice(&limb.to_le_bytes());
        }
        Self { bytes }
    }

    pub fn from_u64(value: u64) -> Self {
        Self::from_fr(Fr::from(value))
    }

    pub fn from_i64(value: i64) -> Self {
        if value >= 0 {
            Self::from_u64(value as u64)
        } else {
            Self::from_fr(-Fr::from((-value) as u64))
        }
    }

    pub fn from_decimal_str(raw: &str) -> Result<Self, String> {
        let value = Fr::from_str(raw)
            .map_err(|_| format!("invalid field element decimal representation: {raw}"))?;
        Ok(Self::from_fr(value))
    }

    pub fn from_bytes(bytes: [u8; Self::BYTE_LEN]) -> Result<Self, String> {
        let value = Self { bytes };
        let _ = value.try_to_fr()?;
        Ok(value)
    }

    pub fn as_bytes(&self) -> &[u8; Self::BYTE_LEN] {
        &self.bytes
    }

    pub fn try_to_fr(&self) -> Result<Fr, String> {
        let mut limbs = [0u64; 4];
        for (idx, chunk) in self.bytes.chunks_exact(8).enumerate() {
            limbs[idx] = u64::from_le_bytes(chunk.try_into().expect("8-byte chunk"));
        }

        Fr::from_bigint(BigInt::<4>(limbs))
            .ok_or_else(|| "field element bytes are not a canonical BN254 scalar".to_string())
    }

    pub fn to_fr(&self) -> Fr {
        self.try_to_fr()
            .expect("FieldElement should always contain a canonical BN254 scalar")
    }

    pub fn to_decimal_string(&self) -> String {
        self.to_fr().into_bigint().to_string()
    }

    pub fn is_zero(&self) -> bool {
        self.bytes.iter().all(|byte| *byte == 0)
    }

    pub fn is_one(&self) -> bool {
        self.bytes[0] == 1 && self.bytes[1..].iter().all(|byte| *byte == 0)
    }
}

impl Default for FieldElement {
    fn default() -> Self {
        Self::ZERO
    }
}

impl From<Fr> for FieldElement {
    fn from(value: Fr) -> Self {
        Self::from_fr(value)
    }
}

impl From<u64> for FieldElement {
    fn from(value: u64) -> Self {
        Self::from_u64(value)
    }
}

impl From<i64> for FieldElement {
    fn from(value: i64) -> Self {
        Self::from_i64(value)
    }
}

impl std::fmt::Display for FieldElement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_decimal_string())
    }
}

impl PartialEq<&str> for FieldElement {
    fn eq(&self, other: &&str) -> bool {
        self.to_decimal_string() == *other
    }
}

impl Serialize for FieldElement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_decimal_string())
        } else {
            self.bytes.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for FieldElement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let raw = String::deserialize(deserializer)?;
            Self::from_decimal_str(&raw).map_err(D::Error::custom)
        } else {
            let bytes = <[u8; Self::BYTE_LEN]>::deserialize(deserializer)?;
            Self::from_bytes(bytes).map_err(D::Error::custom)
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Term {
    pub index: usize,
    pub coeff: FieldElement,
}

impl Term {
    pub fn from_i64(index: usize, coeff: i64) -> Self {
        Self {
            index,
            coeff: FieldElement::from_i64(coeff),
        }
    }

    pub fn from_fr(index: usize, coeff: Fr) -> Self {
        Self {
            index,
            coeff: FieldElement::from_fr(coeff),
        }
    }

    pub fn is_zero_coeff(&self) -> bool {
        self.coeff.is_zero()
    }

    pub fn is_one_coeff(&self) -> bool {
        self.coeff.is_one()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportConstraint {
    pub index: usize,
    pub a_in: Vec<Term>,
    pub b_wit: Vec<Term>,
    pub output_witness: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicInputValue {
    pub index: usize,
    pub value: FieldElement,
}

impl PublicInputValue {
    pub fn from_fr(index: usize, value: Fr) -> Self {
        Self {
            index,
            value: FieldElement::from_fr(value),
        }
    }

    pub fn from_u64(index: usize, value: u64) -> Self {
        Self {
            index,
            value: FieldElement::from_u64(value),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RmsLinearExport {
    pub version: String,
    pub num_inputs: usize,
    pub num_public_inputs: usize,
    pub num_private_inputs: usize,
    pub public_inputs: Vec<PublicInputValue>,
    pub private_inputs: Vec<usize>,
    pub num_witnesses: usize,
    pub output_witnesses: Vec<usize>,
    pub execution_order: Vec<usize>,
    pub constraints: Vec<ExportConstraint>,
}

pub fn rms_linear_name(num_inputs: usize, num_constraints: usize) -> String {
    format!("rms_linear_n{}_d{}", num_inputs, num_constraints)
}

/// A linear combination of variables: \sum (coeff * var)
#[derive(Clone, Debug)]
pub struct LinComb {
    pub terms: Vec<(Fr, Variable)>,
}

impl LinComb {
    pub fn from_terms(terms: Vec<(Fr, Variable)>) -> Self {
        LinComb { terms }
    }

    pub fn from_var(v: Variable) -> Self {
        LinComb {
            terms: vec![(ark_ff::One::one(), v)],
        }
    }

    pub fn is_input_only(&self) -> bool {
        self.terms
            .iter()
            .all(|(_, var)| matches!(var, Variable::Input(_)))
    }

    pub fn is_witness_only(&self) -> bool {
        self.terms
            .iter()
            .all(|(_, var)| matches!(var, Variable::Witness(_)))
    }
}

/// A quadratic constraint of the form: a * b = c
#[derive(Clone, Debug)]
pub struct Constraint {
    pub a: LinComb,
    pub b: LinComb,
    pub c: LinComb,
}

impl Constraint {
    /// Checks if the constraint fits the RMS (Relaxed-R1CS) compatibility: Input * Witness = Witness
    pub fn is_rms_compatible(&self) -> bool {
        self.a.is_input_only() && self.b.is_witness_only()
    }

    pub fn is_input_input(&self) -> bool {
        self.a.is_input_only() && self.b.is_input_only()
    }

    /// Checks if the constraint is a multiplication of two witnesses.
    pub fn is_witness_witness(&self) -> bool {
        let a_has_w = self
            .a
            .terms
            .iter()
            .any(|(_, v)| matches!(v, Variable::Witness(_)));
        let b_has_w = self
            .b
            .terms
            .iter()
            .any(|(_, v)| matches!(v, Variable::Witness(_)));
        a_has_w && b_has_w
    }
}

/// Rank-1 Constraint System structure.
#[derive(Clone, Debug)]
pub struct R1CS {
    pub num_inputs: usize,
    pub num_witnesses: usize,
    pub constraints: Vec<Constraint>,
    pub origin: HashMap<usize, usize>, // Maps witness_idx to the constraint_idx that defined it
}

impl R1CS {
    pub fn new(num_inputs: usize, num_witnesses: usize) -> Self {
        R1CS {
            num_inputs,
            num_witnesses,
            constraints: vec![],
            origin: HashMap::new(),
        }
    }

    pub fn add_constraint(&mut self, c: Constraint, output_witness: usize) {
        let idx = self.constraints.len();
        self.origin.insert(output_witness, idx);
        self.constraints.push(c);
    }

    pub fn count_ww_gates(&self) -> usize {
        self.constraints
            .iter()
            .filter(|c| c.is_witness_witness())
            .count()
    }

    pub fn count_rms_gates(&self) -> usize {
        self.constraints
            .iter()
            .filter(|c| c.is_rms_compatible())
            .count()
    }

    pub fn count_ii_gates(&self) -> usize {
        self.constraints
            .iter()
            .filter(|c| c.is_input_input())
            .count()
    }

    pub fn print_stats(&self) {
        let total = self.constraints.len();
        if total == 0 {
            println!("  (empty circuit)");
            return;
        }
        let ww = self.count_ww_gates();
        let ii = self.count_ii_gates();
        let rms = self.count_rms_gates();
        println!("  Total constraints: {}", total);
        println!(
            "  RMS-compatible:  {} ({:.1}%)",
            rms,
            100.0 * rms as f64 / total as f64
        );
        println!(
            "  input×input:     {} ({:.1}%)",
            ii,
            100.0 * ii as f64 / total as f64
        );
        println!(
            "  witness×witness: {} ({:.1}%)",
            ww,
            100.0 * ww as f64 / total as f64
        );
        println!("  input slots:     {}", self.num_inputs);
        println!("  witnesses:       {}", self.num_witnesses);
    }
}
