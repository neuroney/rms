//! Shared formatting and preview utilities for circuit/debug output.

use crate::r1cs::{LinComb, Variable, R1CS};
use ark_bn254::Fr;
use ark_ff::PrimeField;

pub const PREVIEW_MAX_VECTOR_ITEMS: usize = 12;
pub const PREVIEW_MAX_MATRIX_ROWS: usize = 6;
pub const PREVIEW_MAX_MATRIX_COLS: usize = 6;

pub fn var_to_string(v: &Variable) -> String {
    match v {
        Variable::Input(i) => format!("x{}", i),
        Variable::Witness(i) => format!("w{}", i),
    }
}

pub fn coeff_to_string(coeff: &Fr) -> String {
    coeff.into_bigint().to_string()
}

pub fn fr_from_i64(value: i64) -> Fr {
    if value >= 0 {
        Fr::from(value as u64)
    } else {
        -Fr::from((-value) as u64)
    }
}

pub fn fr_to_u64(value: &Fr) -> Option<u64> {
    value.into_bigint().to_string().parse().ok()
}

pub fn lincomb_to_string(lc: &LinComb) -> String {
    if lc.terms.is_empty() {
        return "0".to_string();
    }
    lc.terms
        .iter()
        .map(|(coeff, v)| match coeff_to_string(coeff).as_str() {
            "1" => var_to_string(v),
            coeff => format!("{}*{}", coeff, var_to_string(v)),
        })
        .collect::<Vec<_>>()
        .join("+")
}

pub fn print_constraints(r1cs: &R1CS) {
    for (i, c) in r1cs.constraints.iter().enumerate() {
        let kind = if c.is_rms_compatible() {
            "RMS ✓"
        } else if c.is_input_input() {
            "I×I  "
        } else if c.is_witness_witness() {
            "W×W  "
        } else {
            "Other"
        };

        println!(
            "  Constraint {:3}: ({:<14}) * ({:<14}) = ({:<10})  [{}]",
            i,
            lincomb_to_string(&c.a),
            lincomb_to_string(&c.b),
            lincomb_to_string(&c.c),
            kind,
        );
    }
    println!();
}

pub fn format_preview_list<T, F>(values: &[T], max_items: usize, format_item: F) -> String
where
    F: Fn(&T) -> String,
{
    let shown = values.len().min(max_items);
    let mut formatted = values
        .iter()
        .take(shown)
        .map(format_item)
        .collect::<Vec<_>>();
    if values.len() > max_items {
        formatted.push(format!("... (+{} more)", values.len() - max_items));
    }
    format!("[{}]", formatted.join(", "))
}

pub fn print_preview_matrix<T, F>(name: &str, matrix: &[Vec<T>], format_item: F)
where
    F: Fn(&T) -> String + Copy,
{
    println!("    {} =", name);
    for row in matrix.iter().take(PREVIEW_MAX_MATRIX_ROWS) {
        let shown = row.len().min(PREVIEW_MAX_MATRIX_COLS);
        let mut formatted = row.iter().take(shown).map(format_item).collect::<Vec<_>>();
        if row.len() > PREVIEW_MAX_MATRIX_COLS {
            formatted.push(format!(
                "... (+{} cols)",
                row.len() - PREVIEW_MAX_MATRIX_COLS
            ));
        }
        println!("      [{}]", formatted.join(", "));
    }

    if matrix.len() > PREVIEW_MAX_MATRIX_ROWS {
        println!(
            "      ... (+{} rows)",
            matrix.len() - PREVIEW_MAX_MATRIX_ROWS
        );
    }
}
