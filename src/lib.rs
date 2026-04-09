#![forbid(unsafe_code)]

//! Library entrypoint exporting RMS demos, Circom import flows, and helpers.

//! Library entry point for the RMS circuit toolkit.
//!
//! Public API is organized into:
//! - [`circom`]: import Circom-authored circuits and transform them into RMS.
//! - [`db_select`], [`fix_mat`], [`two_mat`], [`greater_than`], [`mimc7`],
//!   [`page_rank`], [`random_mul`], [`random_linear`], [`dense_poly`]:
//!   canonical circuit modules and runnable demos.
//! - [`evalr1cs`]: witness execution and verification helpers.
//! - [`export`]: JSON/BIN import-export helpers.
//! - [`r1cs`], [`transform`], [`utils`]: core circuit data structures and helpers.
//! - [`cli`]: command-line dispatch used by the binary target.

pub mod circom;
pub mod cli;
pub mod db_select;
pub mod dense_poly;
pub mod evalr1cs;
pub mod export;
pub mod fix_mat;
pub mod greater_than;
pub mod mimc7;
pub mod page_rank;
pub mod r1cs;
pub mod random_linear;
pub mod random_mul;
pub mod transform;
pub mod two_mat;
pub mod utils;

mod circom_reader;
