use crate::export::{write_bin_file, write_json_pretty_file, OutputFormat};
use rand::{rngs::StdRng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub const DEFAULT_NUM_INPUTS: usize = 5;
pub const DEFAULT_MIN_EXP: u32 = 1;
pub const DEFAULT_MAX_EXP: u32 = 12;
pub const DEFAULT_BASE_SEED: u64 = 42;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RmsMulExport {
    pub version: String,
    pub num_inputs: usize,
    pub num_witnesses: usize,
    pub execution_order: Vec<usize>,
    pub constraints: Vec<[usize; 4]>,
}

pub fn build_random_rms<R: Rng>(
    num_inputs: usize,
    depth: usize,
    rng: &mut R,
) -> Result<RmsMulExport, String> {
    if num_inputs == 0 {
        return Err("num_inputs must be >= 1".to_string());
    }

    let num_witnesses = depth + 1;
    let execution_order: Vec<usize> = (0..depth).collect();
    let mut constraints = Vec::with_capacity(depth);

    for index in 0..depth {
        let input_idx = rng.gen_range(0..num_inputs);
        let witness_in = rng.gen_range(1..=(index + 1));
        let witness_out = index + 2;

        constraints.push([index, input_idx, witness_in, witness_out]);
    }

    Ok(RmsMulExport {
        version: "rms-mul-v1".to_string(),
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
        let export = build_random_rms(num_inputs, depth, &mut rng)?;
        let filename = format!("rms_mul_n{}_d{}.{}", num_inputs, depth, format.extension());
        let path = out_dir.join(filename);

        match format {
            OutputFormat::Json => {
                write_json_pretty_file(&path, &export).map_err(|err| err.to_string())?
            }
            OutputFormat::Bin => write_bin_file(&path, &export).map_err(|err| err.to_string())?,
        }

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
    fn mul_generator_uses_existing_witnesses_only() {
        let mut rng = StdRng::seed_from_u64(9);
        let export = build_random_rms(5, 8, &mut rng).expect("mul export");

        assert_eq!(export.version, "rms-mul-v1");
        assert_eq!(export.num_witnesses, 9);
        assert_eq!(export.constraints.len(), 8);

        for (index, constraint) in export.constraints.iter().enumerate() {
            assert_eq!(constraint[0], index);
            assert!(constraint[1] < 5);
            assert!(constraint[2] <= index + 1);
            assert_eq!(constraint[3], index + 2);
        }
    }
}
