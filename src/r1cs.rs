use ark_bn254::Fr;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents variables in the constraint system.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Variable {
    Input(usize),   // Public input, index starts from 0, x0 = 1
    Witness(usize), // Private witness, index starts from 1
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Term {
    pub index: usize,
    pub coeff: String,
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
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RmsLinearExport {
    pub version: String,
    pub num_inputs: usize,
    #[serde(default)]
    pub num_public_inputs: usize,
    #[serde(default)]
    pub num_private_inputs: usize,
    #[serde(default)]
    pub public_inputs: Vec<PublicInputValue>,
    #[serde(default)]
    pub private_inputs: Vec<usize>,
    pub num_witnesses: usize,
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
            println!("  (空电路)");
            return;
        }
        let ww = self.count_ww_gates();
        let ii = self.count_ii_gates();
        let rms = self.count_rms_gates();
        println!("  总约束数:        {}", total);
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
        println!("  public inputs:   {}", self.num_inputs);
        println!("  witnesses:       {}", self.num_witnesses);
    }
}
