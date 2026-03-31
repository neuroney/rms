//! Benchmark and fixture generators imported from the production RMS toolchain.

use std::path::PathBuf;

pub mod linear;
pub mod mul;
pub mod poly;

pub fn default_fixture_out_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("data/generated")
}
