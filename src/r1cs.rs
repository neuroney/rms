use ark_bn254::Fr;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::HashSet;

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
pub struct RmsLinearExport {
    pub version: String,
    pub num_inputs: usize,
    pub num_witnesses: usize,
    pub execution_order: Vec<usize>,
    pub constraints: Vec<ExportConstraint>,
}

#[derive(Clone, Debug)]
pub struct MatrixMulCircuit {
    pub r1cs: R1CS,
    pub left_input_indices: Vec<Vec<usize>>,
    pub right_input_indices: Vec<Vec<usize>>,
    pub output_witness_indices: Vec<Vec<usize>>,
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

pub fn generate_controlled_r1cs(
    num_inputs: usize,
    max_witnesses: usize,
    total_constraints: usize,
    ww_ratio: f64,
) -> R1CS {
    assert!(num_inputs >= 1, "至少需要 x0");
    let mut rng = rand::thread_rng();
    let mut r1cs = R1CS::new(num_inputs, 0); // 实际 num_witnesses 在生成后确定

    let mut defined: Vec<usize> = vec![1];
    let mut next_w = 2usize;

    // 已使用的输入组合集合
    let mut rms_seen: HashSet<(usize, usize)> = HashSet::new();
    let mut ii_seen: HashSet<(usize, usize)> = HashSet::new();
    let mut ww_seen: HashSet<(usize, usize)> = HashSet::new();

    // identity 约束本身算一个 rms_seen
    //rms_seen.insert((0, 1));

    let num_ww = (total_constraints as f64 * ww_ratio).round() as usize;
    let max_ii = total_constraints.saturating_sub(num_ww);
    let num_ii = ((total_constraints as f64) * 0.10).round() as usize;
    let num_ii = num_ii.min(max_ii);
    let num_rms = total_constraints - num_ww - num_ii;

    // ── RMS-compatible 约束 ──────────────────────────────────
    let mut generated_rms = 0;
    while generated_rms < num_rms {
        if next_w > max_witnesses {
            break;
        }

        // 计算当前还有多少可用的 RMS 组合
        // 总可能 = num_inputs × defined.len()，已用 = rms_seen.len()
        let total_possible = num_inputs * defined.len();
        if rms_seen.len() >= total_possible {
            println!(
                "  [警告] RMS 组合已耗尽，实际生成 {} 个（目标 {}）",
                generated_rms, num_rms
            );
            break;
        }

        // 重新采样直到找到新组合
        let (input_idx, w_idx) = loop {
            let i = rng.gen_range(0..num_inputs);
            let w = defined[rng.gen_range(0..defined.len())];
            if !rms_seen.contains(&(i, w)) {
                break (i, w);
            }
        };

        rms_seen.insert((input_idx, w_idx));
        r1cs.add_constraint(
            Constraint {
                a: LinComb::from_var(Variable::Input(input_idx)),
                b: LinComb::from_var(Variable::Witness(w_idx)),
                c: LinComb::from_var(Variable::Witness(next_w)),
            },
            next_w,
        );
        defined.push(next_w);
        next_w += 1;
        generated_rms += 1;
    }

    // ── input×input 约束（约 10%）────────────────────────────
    let input_start = if num_inputs > 1 { 1 } else { 0 };
    let input_count = num_inputs - input_start;
    let mut generated_ii = 0;
    while generated_ii < num_ii {
        if next_w > max_witnesses {
            break;
        }

        if input_count == 0 {
            break;
        }

        let total_possible = input_count * (input_count + 1) / 2;
        if ii_seen.len() >= total_possible {
            println!(
                "  [警告] input×input 组合已耗尽，实际生成 {} 个（目标 {}）",
                generated_ii, num_ii
            );
            break;
        }

        let (left_idx, right_idx) = loop {
            let a = input_start + rng.gen_range(0..input_count);
            let b = input_start + rng.gen_range(0..input_count);
            let key = (a.min(b), a.max(b));
            if !ii_seen.contains(&key) {
                break (a, b);
            }
        };

        let key = (left_idx.min(right_idx), left_idx.max(right_idx));
        ii_seen.insert(key);

        r1cs.add_constraint(
            Constraint {
                a: LinComb::from_var(Variable::Input(left_idx)),
                b: LinComb::from_var(Variable::Input(right_idx)),
                c: LinComb::from_var(Variable::Witness(next_w)),
            },
            next_w,
        );
        defined.push(next_w);
        next_w += 1;
        generated_ii += 1;
    }

    // ── witness×witness 约束 ─────────────────────────────────
    let mut generated_ww = 0;
    while generated_ww < num_ww {
        if next_w > max_witnesses {
            break;
        }

        if defined.len() < 2 {
            // 不够两个 witness，先补一个 RMS 约束
            let input_idx = rng.gen_range(0..num_inputs);
            let key = (input_idx, 1usize);
            if !rms_seen.contains(&key) {
                rms_seen.insert(key);
                r1cs.add_constraint(
                    Constraint {
                        a: LinComb::from_var(Variable::Input(input_idx)),
                        b: LinComb::from_var(Variable::Witness(1)),
                        c: LinComb::from_var(Variable::Witness(next_w)),
                    },
                    next_w,
                );
                defined.push(next_w);
                next_w += 1;
            }
            continue;
        }

        // 计算当前还有多少可用的 w×w 组合
        // 无序对数量 = defined.len() * (defined.len() + 1) / 2
        let n = defined.len();
        let total_possible = n * (n + 1) / 2;
        if ww_seen.len() >= total_possible {
            println!(
                "  [警告] w×w 组合已耗尽，实际生成 {} 个（目标 {}）",
                generated_ww, num_ww
            );
            break;
        }

        // 重新采样直到找到新组合
        let (left_idx, right_idx) = loop {
            let a = defined[rng.gen_range(0..defined.len())];
            let b = defined[rng.gen_range(0..defined.len())];
            // 用无序对作为 key（乘法交换律）
            let key = (a.min(b), a.max(b));
            if !ww_seen.contains(&key) {
                break (a, b);
            }
        };

        let key = (left_idx.min(right_idx), left_idx.max(right_idx));
        ww_seen.insert(key);

        r1cs.add_constraint(
            Constraint {
                a: LinComb::from_var(Variable::Witness(left_idx)),
                b: LinComb::from_var(Variable::Witness(right_idx)),
                c: LinComb::from_var(Variable::Witness(next_w)),
            },
            next_w,
        );
        defined.push(next_w);
        next_w += 1;
        generated_ww += 1;
    }

    // witness 数量由生成过程动态确定，而非预设值
    r1cs.num_witnesses = next_w - 1;
    r1cs
}

pub fn generate_matrix_mul_r1cs(rows: usize, shared: usize, cols: usize) -> MatrixMulCircuit {
    assert!(rows > 0, "左矩阵行数必须大于 0");
    assert!(shared > 0, "矩阵内积维度必须大于 0");
    assert!(cols > 0, "右矩阵列数必须大于 0");

    let num_inputs = 1 + rows * shared + shared * cols; // x0 预留为常数 1
    let mut r1cs = R1CS::new(num_inputs, 0);

    let mut next_input = 1usize;
    let mut left_input_indices = vec![vec![0; shared]; rows];
    for row in &mut left_input_indices {
        for input_idx in row.iter_mut() {
            *input_idx = next_input;
            next_input += 1;
        }
    }

    let mut right_input_indices = vec![vec![0; cols]; shared];
    for row in &mut right_input_indices {
        for input_idx in row.iter_mut() {
            *input_idx = next_input;
            next_input += 1;
        }
    }

    let mut next_w = 2usize; // w1 预留为常数 1
    let mut output_witness_indices = vec![vec![0; cols]; rows];

    for i in 0..rows {
        for j in 0..cols {
            let mut product_witnesses = Vec::with_capacity(shared);

            for k in 0..shared {
                let out_w = next_w;
                next_w += 1;
                r1cs.add_constraint(
                    Constraint {
                        a: LinComb::from_var(Variable::Input(left_input_indices[i][k])),
                        b: LinComb::from_var(Variable::Input(right_input_indices[k][j])),
                        c: LinComb::from_var(Variable::Witness(out_w)),
                    },
                    out_w,
                );
                product_witnesses.push(out_w);
            }

            let output_witness = if product_witnesses.len() == 1 {
                product_witnesses[0]
            } else {
                let out_w = next_w;
                next_w += 1;
                r1cs.add_constraint(
                    Constraint {
                        a: LinComb::from_var(Variable::Input(0)),
                        b: LinComb::from_terms(
                            product_witnesses
                                .iter()
                                .map(|witness| (ark_ff::One::one(), Variable::Witness(*witness)))
                                .collect(),
                        ),
                        c: LinComb::from_var(Variable::Witness(out_w)),
                    },
                    out_w,
                );
                out_w
            };

            output_witness_indices[i][j] = output_witness;
        }
    }

    r1cs.num_witnesses = next_w - 1;

    MatrixMulCircuit {
        r1cs,
        left_input_indices,
        right_input_indices,
        output_witness_indices,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evalr1cs::{execute_circuit, verify_assignment, Assignment};
    use crate::transform::{choudhuri_transform, eliminate_common_subexpressions};
    use crate::utils::fr_to_u64;

    fn build_assignment(
        circuit: &MatrixMulCircuit,
        left: [[u64; 2]; 2],
        right: [[u64; 2]; 2],
    ) -> Assignment {
        let mut inputs = Vec::new();

        for (i, row) in left.iter().enumerate() {
            for (k, value) in row.iter().enumerate() {
                inputs.push((circuit.left_input_indices[i][k], *value));
            }
        }

        for (k, row) in right.iter().enumerate() {
            for (j, value) in row.iter().enumerate() {
                inputs.push((circuit.right_input_indices[k][j], *value));
            }
        }

        Assignment::new(inputs)
    }

    fn read_outputs(circuit: &MatrixMulCircuit, assignment: &Assignment) -> Vec<Vec<u64>> {
        circuit
            .output_witness_indices
            .iter()
            .map(|row| {
                row.iter()
                    .map(|witness_idx| {
                        fr_to_u64(&assignment.witnesses[witness_idx]).expect("矩阵输出超出 u64")
                    })
                    .collect()
            })
            .collect()
    }

    #[test]
    fn matrix_mul_2x2_transforms_to_rms_and_preserves_output() {
        let circuit = generate_matrix_mul_r1cs(2, 2, 2);
        let transformed = choudhuri_transform(&circuit.r1cs);
        let (optimized, eliminated) = eliminate_common_subexpressions(&transformed.r1cs);

        assert!(optimized
            .constraints
            .iter()
            .all(|constraint| constraint.is_rms_compatible()));
        assert_eq!(transformed.r1cs.constraints.len(), 16);
        assert_eq!(eliminated, 0);
        assert_eq!(optimized.constraints.len(), 16);

        let left = [[1, 2], [3, 4]];
        let right = [[5, 6], [7, 8]];

        let mut original_assignment = build_assignment(&circuit, left, right);
        assert!(execute_circuit(&circuit.r1cs, &mut original_assignment).is_some());
        assert!(verify_assignment(&circuit.r1cs, &original_assignment));
        let original_outputs = read_outputs(&circuit, &original_assignment);
        assert_eq!(original_outputs, vec![vec![19, 22], vec![43, 50]]);

        let mut optimized_assignment = build_assignment(&circuit, left, right);
        assert!(execute_circuit(&optimized, &mut optimized_assignment).is_some());
        assert!(verify_assignment(&optimized, &optimized_assignment));
        let optimized_outputs = read_outputs(&circuit, &optimized_assignment);
        assert_eq!(optimized_outputs, original_outputs);
    }
}
