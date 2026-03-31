#![forbid(unsafe_code)]

//! Library entry point for the RMS circuit toolkit.
//!
//! Public API is organized into:
//! - [`circom`]: import Circom-authored circuits and transform them into RMS.
//! - [`matrix_mul`], [`greater_than`], [`random_mul`], [`random_linear`], [`dense_poly`]:
//!   canonical circuit modules and runnable demos.
//! - [`evalr1cs`]: witness execution and verification helpers.
//! - [`export`]: JSON/BIN import-export helpers.
//! - [`r1cs`], [`transform`], [`utils`]: core circuit data structures and helpers.
//! - [`cli`]: command-line dispatch used by the binary target.

pub mod circom;
pub mod cli;
pub mod dense_poly;
pub mod evalr1cs;
pub mod export;
pub mod greater_than;
pub mod matrix_mul;
pub mod r1cs;
pub mod random_linear;
pub mod random_mul;
pub mod transform;
pub mod utils;

mod circom_reader;
