#![forbid(unsafe_code)]

//! Library entry point for the RMS circuit toolkit.
//!
//! Public API is organized into:
//! - [`circuits`]: hand-built reusable circuit generators.
//! - [`circom_json`]: Circom import pipeline internals.
//! - [`evalr1cs`]: witness execution and verification helpers.
//! - [`export`]: JSON/BIN import-export helpers.
//! - [`generators`]: production-style RMS fixture generators and compilers.
//! - [`pipelines`]: demo pipelines used by the CLI and Cargo examples.
//! - [`r1cs`], [`transform`], [`utils`]: core circuit data structures and helpers.
//! - [`cli`]: command-line dispatch used by the binary target.

pub mod circom_json;
pub mod circuits;
pub mod cli;
pub mod evalr1cs;
pub mod export;
pub mod generators;
pub mod pipelines;
pub mod r1cs;
pub mod transform;
pub mod utils;
