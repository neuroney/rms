//! Hand-built example circuits on top of the generic R1CS data model.

pub mod greater_than;
pub mod matrix_mul;

pub use greater_than::{generate_greater_than_r1cs, GreaterThanCircuit};
pub use matrix_mul::{generate_matrix_mul_r1cs, MatrixMulCircuit};
