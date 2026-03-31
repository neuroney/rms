use crate::r1cs::{Constraint, LinComb, Variable, R1CS};

#[derive(Clone, Debug)]
pub struct MatrixMulCircuit {
    pub r1cs: R1CS,
    pub left_input_indices: Vec<Vec<usize>>,
    pub right_input_indices: Vec<Vec<usize>>,
    pub output_witness_indices: Vec<Vec<usize>>,
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

    fn build_matrix_assignment(
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

    fn read_matrix_outputs(circuit: &MatrixMulCircuit, assignment: &Assignment) -> Vec<Vec<u64>> {
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

        let mut original_assignment = build_matrix_assignment(&circuit, left, right);
        assert!(execute_circuit(&circuit.r1cs, &mut original_assignment).is_some());
        assert!(verify_assignment(&circuit.r1cs, &original_assignment));
        let original_outputs = read_matrix_outputs(&circuit, &original_assignment);
        assert_eq!(original_outputs, vec![vec![19, 22], vec![43, 50]]);

        let mut optimized_assignment = build_matrix_assignment(&circuit, left, right);
        assert!(execute_circuit(&optimized, &mut optimized_assignment).is_some());
        assert!(verify_assignment(&optimized, &optimized_assignment));
        let optimized_outputs = read_matrix_outputs(&circuit, &optimized_assignment);
        assert_eq!(optimized_outputs, original_outputs);
    }
}
