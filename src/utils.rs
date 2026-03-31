use crate::r1cs::{LinComb, Variable, R1CS};
use ark_bn254::Fr;
use ark_ff::PrimeField;

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
