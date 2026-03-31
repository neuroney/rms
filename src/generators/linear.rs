use crate::export::{write_r1cs, OutputFormat};
use crate::r1cs::{ExportConstraint, RmsLinearExport, Term};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

pub const DEFAULT_NUM_INPUTS: usize = 5;
pub const DEFAULT_MIN_EXP: u32 = 1;
pub const DEFAULT_MAX_EXP: u32 = 12;
pub const DEFAULT_BASE_SEED: u64 = 42;

const COEFF_POOL: &[i64] = &[-3, -2, -1, 1, 2, 3];

fn sample_coeff<R: Rng>(rng: &mut R) -> i64 {
    let idx = rng.gen_range(0..COEFF_POOL.len());
    COEFF_POOL[idx]
}

fn sample_unique_indices<R: Rng>(rng: &mut R, upper_exclusive: usize, k: usize) -> Vec<usize> {
    assert!(upper_exclusive >= 1);
    assert!(k >= 1);

    let want = k.min(upper_exclusive);
    let mut picked = BTreeSet::new();
    while picked.len() < want {
        picked.insert(rng.gen_range(0..upper_exclusive));
    }
    picked.into_iter().collect()
}

fn sample_unique_witness_indices<R: Rng>(
    rng: &mut R,
    max_existing_witness: usize,
    k: usize,
) -> Vec<usize> {
    assert!(max_existing_witness >= 1);
    assert!(k >= 1);

    let want = k.min(max_existing_witness);
    let mut picked = BTreeSet::new();
    while picked.len() < want {
        picked.insert(rng.gen_range(1..=max_existing_witness));
    }
    picked.into_iter().collect()
}

fn sample_input_linear_combo<R: Rng>(rng: &mut R, num_inputs: usize) -> Vec<Term> {
    let arity = rng.gen_range(1..=num_inputs.min(3));
    let indices = sample_unique_indices(rng, num_inputs, arity);

    indices
        .into_iter()
        .map(|index| Term {
            index,
            coeff: sample_coeff(rng).to_string(),
        })
        .collect()
}

fn sample_witness_linear_combo<R: Rng>(rng: &mut R, max_existing_witness: usize) -> Vec<Term> {
    let arity = rng.gen_range(1..=max_existing_witness.min(3));
    let indices = sample_unique_witness_indices(rng, max_existing_witness, arity);

    indices
        .into_iter()
        .map(|index| Term {
            index,
            coeff: sample_coeff(rng).to_string(),
        })
        .collect()
}

pub fn build_random_rms_linear<R: Rng>(
    num_inputs: usize,
    depth: usize,
    rng: &mut R,
) -> Result<RmsLinearExport, String> {
    if num_inputs == 0 {
        return Err("num_inputs must be >= 1".to_string());
    }

    let num_witnesses = depth + 1;
    let execution_order: Vec<usize> = (0..depth).collect();
    let mut constraints = Vec::with_capacity(depth);

    for index in 0..depth {
        let max_existing_witness = index + 1;
        let output_witness = index + 2;

        constraints.push(ExportConstraint {
            index,
            a_in: sample_input_linear_combo(rng, num_inputs),
            b_wit: sample_witness_linear_combo(rng, max_existing_witness),
            output_witness,
        });
    }

    Ok(RmsLinearExport {
        version: "rms-linear-v1".to_string(),
        num_inputs,
        num_witnesses,
        execution_order,
        constraints,
    })
}

pub fn generate_batch_suite<P: AsRef<Path>>(
    out_dir: P,
    num_inputs: usize,
    min_exp: u32,
    max_exp: u32,
    base_seed: u64,
    format: OutputFormat,
) -> Result<(), String> {
    if min_exp > max_exp {
        return Err(format!(
            "min_exp must be <= max_exp, got {min_exp} > {max_exp}"
        ));
    }

    let out_dir = out_dir.as_ref();
    fs::create_dir_all(out_dir)
        .map_err(|err| format!("failed to create output dir {}: {err}", out_dir.display()))?;

    for exp in min_exp..=max_exp {
        let depth = 1usize << exp;
        let seed = base_seed.wrapping_add(depth as u64);
        let mut rng = StdRng::seed_from_u64(seed);
        let r1cs = build_random_rms_linear(num_inputs, depth, &mut rng)?;

        let filename = format!(
            "rms_linear_n{}_d{}.{}",
            num_inputs,
            depth,
            format.extension()
        );
        let path = out_dir.join(filename);
        write_r1cs(&path, &r1cs, format).map_err(|err| err.to_string())?;

        println!(
            "wrote {}",
            std::fs::canonicalize(&path)
                .unwrap_or(path.clone())
                .display()
        );
    }

    Ok(())
}

pub fn generate_default_batch_suite<P: AsRef<Path>>(
    out_dir: P,
    format: OutputFormat,
) -> Result<(), String> {
    generate_batch_suite(
        out_dir,
        DEFAULT_NUM_INPUTS,
        DEFAULT_MIN_EXP,
        DEFAULT_MAX_EXP,
        DEFAULT_BASE_SEED,
        format,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linear_generator_produces_sequential_constraints() {
        let mut rng = StdRng::seed_from_u64(7);
        let export = build_random_rms_linear(4, 6, &mut rng).expect("linear export");

        assert_eq!(export.version, "rms-linear-v1");
        assert_eq!(export.num_inputs, 4);
        assert_eq!(export.num_witnesses, 7);
        assert_eq!(export.execution_order, vec![0, 1, 2, 3, 4, 5]);

        for (index, constraint) in export.constraints.iter().enumerate() {
            assert_eq!(constraint.index, index);
            assert_eq!(constraint.output_witness, index + 2);
            assert!(!constraint.a_in.is_empty());
            assert!(!constraint.b_wit.is_empty());
            assert!(constraint.b_wit.iter().all(|term| term.index <= index + 1));
        }
    }
}
