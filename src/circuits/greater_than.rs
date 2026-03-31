use crate::r1cs::{Constraint, LinComb, Variable, R1CS};
use ark_bn254::Fr;

#[derive(Clone, Debug)]
pub struct GreaterThanCircuit {
    pub r1cs: R1CS,
    pub num_bits: usize,
    pub alpha_input_indices: Vec<usize>, // LSB first
    pub beta_input_indices: Vec<usize>,  // LSB first
    pub equal_bit_witness_indices: Vec<usize>,
    pub greater_bit_witness_indices: Vec<usize>,
    pub prefix_result_witness_indices: Vec<usize>,
    pub output_witness_index: usize,
}

pub fn generate_greater_than_r1cs(num_bits: usize) -> GreaterThanCircuit {
    assert!(num_bits > 0, "比较位宽必须大于 0");

    let num_inputs = 1 + 2 * num_bits; // x0 预留为常数 1
    let mut r1cs = R1CS::new(num_inputs, 0);

    let mut next_input = 1usize;
    let mut alpha_input_indices = Vec::with_capacity(num_bits);
    for _ in 0..num_bits {
        alpha_input_indices.push(next_input);
        next_input += 1;
    }

    let mut beta_input_indices = Vec::with_capacity(num_bits);
    for _ in 0..num_bits {
        beta_input_indices.push(next_input);
        next_input += 1;
    }

    let mut next_w = 2usize; // w1 预留为常数 1
    let zero_witness = next_w;
    next_w += 1;
    r1cs.add_constraint(
        Constraint {
            a: LinComb::from_var(Variable::Input(0)),
            b: LinComb::from_terms(vec![]),
            c: LinComb::from_var(Variable::Witness(zero_witness)),
        },
        zero_witness,
    );

    let one = Fr::from(1u64);
    let minus_one = -Fr::from(1u64);

    let mut equal_bit_witness_indices = Vec::with_capacity(num_bits);
    let mut greater_bit_witness_indices = Vec::with_capacity(num_bits);
    let mut prefix_result_witness_indices = Vec::with_capacity(num_bits);

    let mut prefix_prev = zero_witness;

    for bit in 0..num_bits {
        let alpha_idx = alpha_input_indices[bit];
        let beta_idx = beta_input_indices[bit];

        let alpha_beta_witness = next_w;
        next_w += 1;
        r1cs.add_constraint(
            Constraint {
                a: LinComb::from_var(Variable::Input(alpha_idx)),
                b: LinComb::from_var(Variable::Input(beta_idx)),
                c: LinComb::from_var(Variable::Witness(alpha_beta_witness)),
            },
            alpha_beta_witness,
        );

        let both_zero_witness = next_w;
        next_w += 1;
        r1cs.add_constraint(
            Constraint {
                a: LinComb::from_terms(vec![
                    (one, Variable::Input(0)),
                    (minus_one, Variable::Input(alpha_idx)),
                ]),
                b: LinComb::from_terms(vec![
                    (one, Variable::Input(0)),
                    (minus_one, Variable::Input(beta_idx)),
                ]),
                c: LinComb::from_var(Variable::Witness(both_zero_witness)),
            },
            both_zero_witness,
        );

        let equal_bit_witness = next_w;
        next_w += 1;
        r1cs.add_constraint(
            Constraint {
                a: LinComb::from_var(Variable::Input(0)),
                b: LinComb::from_terms(vec![
                    (one, Variable::Witness(alpha_beta_witness)),
                    (one, Variable::Witness(both_zero_witness)),
                ]),
                c: LinComb::from_var(Variable::Witness(equal_bit_witness)),
            },
            equal_bit_witness,
        );

        let greater_bit_witness = next_w;
        next_w += 1;
        r1cs.add_constraint(
            Constraint {
                a: LinComb::from_var(Variable::Input(alpha_idx)),
                b: LinComb::from_terms(vec![
                    (one, Variable::Input(0)),
                    (minus_one, Variable::Input(beta_idx)),
                ]),
                c: LinComb::from_var(Variable::Witness(greater_bit_witness)),
            },
            greater_bit_witness,
        );

        let equal_and_prev_witness = next_w;
        next_w += 1;
        r1cs.add_constraint(
            Constraint {
                a: LinComb::from_var(Variable::Witness(equal_bit_witness)),
                b: LinComb::from_var(Variable::Witness(prefix_prev)),
                c: LinComb::from_var(Variable::Witness(equal_and_prev_witness)),
            },
            equal_and_prev_witness,
        );

        let prefix_result_witness = next_w;
        next_w += 1;
        r1cs.add_constraint(
            Constraint {
                a: LinComb::from_var(Variable::Input(0)),
                b: LinComb::from_terms(vec![
                    (one, Variable::Witness(greater_bit_witness)),
                    (one, Variable::Witness(equal_and_prev_witness)),
                ]),
                c: LinComb::from_var(Variable::Witness(prefix_result_witness)),
            },
            prefix_result_witness,
        );

        equal_bit_witness_indices.push(equal_bit_witness);
        greater_bit_witness_indices.push(greater_bit_witness);
        prefix_result_witness_indices.push(prefix_result_witness);
        prefix_prev = prefix_result_witness;
    }

    r1cs.num_witnesses = next_w - 1;

    GreaterThanCircuit {
        r1cs,
        num_bits,
        alpha_input_indices,
        beta_input_indices,
        equal_bit_witness_indices,
        greater_bit_witness_indices,
        prefix_result_witness_indices,
        output_witness_index: prefix_prev,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evalr1cs::{execute_circuit, verify_assignment, Assignment};
    use crate::transform::{choudhuri_transform, eliminate_common_subexpressions};
    use crate::utils::fr_to_u64;

    fn build_greater_than_assignment(
        circuit: &GreaterThanCircuit,
        alpha: u64,
        beta: u64,
    ) -> Assignment {
        assert!(
            circuit.num_bits <= u64::BITS as usize,
            "测试输入目前仅支持不超过 64 bit"
        );
        if circuit.num_bits < u64::BITS as usize {
            let upper_bound = 1u64 << circuit.num_bits;
            assert!(
                alpha < upper_bound,
                "alpha 超出 {} bit 范围",
                circuit.num_bits
            );
            assert!(
                beta < upper_bound,
                "beta 超出 {} bit 范围",
                circuit.num_bits
            );
        }

        let mut inputs = Vec::with_capacity(circuit.num_bits * 2);
        for (bit, input_idx) in circuit.alpha_input_indices.iter().enumerate() {
            inputs.push((*input_idx, (alpha >> bit) & 1));
        }
        for (bit, input_idx) in circuit.beta_input_indices.iter().enumerate() {
            inputs.push((*input_idx, (beta >> bit) & 1));
        }

        Assignment::new(inputs)
    }

    fn read_greater_than_output(circuit: &GreaterThanCircuit, assignment: &Assignment) -> u64 {
        fr_to_u64(&assignment.witnesses[&circuit.output_witness_index]).expect("比较输出超出 u64")
    }

    #[test]
    fn greater_than_4_bit_transforms_to_rms_and_preserves_output() {
        let circuit = generate_greater_than_r1cs(4);
        let transformed = choudhuri_transform(&circuit.r1cs);
        let (optimized, _eliminated) = eliminate_common_subexpressions(&transformed.r1cs);

        assert!(optimized
            .constraints
            .iter()
            .all(|constraint| constraint.is_rms_compatible()));

        for (alpha, beta, expected) in [
            (0u64, 0u64, 0u64),
            (1, 0, 1),
            (0, 1, 0),
            (6, 6, 0),
            (9, 6, 1),
            (6, 9, 0),
            (15, 14, 1),
            (8, 12, 0),
        ] {
            let mut original_assignment = build_greater_than_assignment(&circuit, alpha, beta);
            assert!(execute_circuit(&circuit.r1cs, &mut original_assignment).is_some());
            assert!(verify_assignment(&circuit.r1cs, &original_assignment));
            assert_eq!(
                read_greater_than_output(&circuit, &original_assignment),
                expected
            );

            let mut optimized_assignment = build_greater_than_assignment(&circuit, alpha, beta);
            assert!(execute_circuit(&optimized, &mut optimized_assignment).is_some());
            assert!(verify_assignment(&optimized, &optimized_assignment));
            assert_eq!(
                read_greater_than_output(&circuit, &optimized_assignment),
                expected
            );
        }
    }
}
