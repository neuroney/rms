#![forbid(unsafe_code)]

//! Library entry point for the RMS circuit toolkit.
//!
//! Public API is organized into:
//! - [`core`]: reusable circuit/import/export/transform functionality.
//! - [`examples`]: runnable demo pipelines built on top of the core API.
//! - [`cli`]: command-line dispatch used by the binary target.

mod circom_json;
mod circuits;
mod evalr1cs;
mod export;
mod r1cs;
mod transform;
mod utils;

pub mod cli;
pub mod core;
pub mod examples;
