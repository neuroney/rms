use crate::r1cs::{LinComb, Variable, R1CS};
use crate::utils::coeff_to_string;
use ark_bn254::Fr;
use ark_ff::{One, Zero};
use std::collections::HashMap;

/// Stores the actual values assigned to variables during execution.
pub struct Assignment {
    pub inputs: HashMap<usize, Fr>,
    pub witnesses: HashMap<usize, Fr>,
}

impl Assignment {
    pub fn new(inputs: Vec<(usize, u64)>) -> Self {
        Self::from_field_inputs(
            inputs
                .into_iter()
                .map(|(idx, val)| (idx, Fr::from(val)))
                .collect(),
        )
    }

    pub fn from_field_inputs(inputs: Vec<(usize, Fr)>) -> Self {
        let mut inp = HashMap::new();
        for (idx, val) in inputs {
            inp.insert(idx, val);
        }
        inp.insert(0, Fr::one()); // x0 = 1 default
        let mut wit = HashMap::new();
        wit.insert(1, Fr::one()); // w1 = 1 default
        Assignment {
            inputs: inp,
            witnesses: wit,
        }
    }

    pub fn get_var(&self, v: &Variable) -> Option<Fr> {
        match v {
            Variable::Input(i) => self.inputs.get(i).copied(),
            Variable::Witness(i) => self.witnesses.get(i).copied(),
        }
    }

    pub fn eval_lincomb(&self, lc: &LinComb) -> Option<Fr> {
        let mut sum = Fr::zero();
        for (coeff, var) in &lc.terms {
            let val = self.get_var(var)?;
            sum += *coeff * val;
        }
        Some(sum)
    }
}

/// Executes the circuit to compute all witness values.
pub fn execute_circuit(r1cs: &R1CS, assignment: &mut Assignment) -> Option<()> {
    for (i, c) in r1cs.constraints.iter().enumerate() {
        let a_val = assignment.eval_lincomb(&c.a)?;
        let b_val = assignment.eval_lincomb(&c.b)?;
        let expected = a_val * b_val;

        match &c.c.terms[..] {
            [(_, Variable::Witness(out_idx))] => {
                if assignment.witnesses.contains_key(out_idx) {
                    // 已有值，验证一致性即可
                    let existing = assignment.witnesses[out_idx];
                    if existing != expected {
                        println!(
                            "  [错误] 约束 {} 不满足: {} × {} = {} 但 w{} 已有值 {}",
                            i,
                            coeff_to_string(&a_val),
                            coeff_to_string(&b_val),
                            coeff_to_string(&expected),
                            out_idx,
                            coeff_to_string(&existing)
                        );
                        return None;
                    }
                } else {
                    // 新变量，写入
                    assignment.witnesses.insert(*out_idx, expected);
                }
            }
            _ => {
                let c_val = assignment.eval_lincomb(&c.c)?;
                if c_val != expected {
                    println!(
                        "  [错误] 约束 {} 不满足: {} × {} = {} 但期望 {}",
                        i,
                        coeff_to_string(&a_val),
                        coeff_to_string(&b_val),
                        coeff_to_string(&c_val),
                        coeff_to_string(&expected)
                    );
                    return None;
                }
            }
        }
    }
    Some(())
}

/// Verifies if the assignment satisfies all constraints in the R1CS.
pub fn verify_assignment(r1cs: &R1CS, assignment: &Assignment) -> bool {
    let mut all_ok = true;
    for (i, c) in r1cs.constraints.iter().enumerate() {
        let a_val = match assignment.eval_lincomb(&c.a) {
            Some(v) => v,
            None => {
                println!("  [错误] 约束 {} 的 A 含未定义变量", i);
                all_ok = false;
                continue;
            }
        };
        let b_val = match assignment.eval_lincomb(&c.b) {
            Some(v) => v,
            None => {
                println!("  [错误] 约束 {} 的 B 含未定义变量", i);
                all_ok = false;
                continue;
            }
        };
        let c_val = match assignment.eval_lincomb(&c.c) {
            Some(v) => v,
            None => {
                println!("  [错误] 约束 {} 的 C 含未定义变量", i);
                all_ok = false;
                continue;
            }
        };

        if a_val * b_val != c_val {
            println!(
                "  [错误] 约束 {} 不满足: {} × {} ≠ {}",
                i,
                coeff_to_string(&a_val),
                coeff_to_string(&b_val),
                coeff_to_string(&c_val)
            );
            all_ok = false;
        }
    }
    all_ok
}

pub fn get_output(r1cs: &R1CS, assignment: &Assignment) -> Option<Fr> {
    // 找到 constraints 里最后一个输出 witness 的值
    let last_constraint = r1cs.constraints.last()?;
    match &last_constraint.c.terms[..] {
        [(_, Variable::Witness(out_idx))] => assignment.witnesses.get(out_idx).copied(),
        _ => assignment.eval_lincomb(&last_constraint.c),
    }
}
