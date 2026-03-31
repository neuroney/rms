# Repository Layout

This repository now follows the usual Rust split:

- reusable library code lives in `src/`
- runnable Cargo examples live in root-level `examples/`
- standalone tool binaries live in `src/bin/`

## Active Structure

- `src/circuits/`
  Reusable hand-built circuit generators. Keeping this under `src/` is the
  conventional Rust choice because it is library code, not an example.
- `src/generators/`
  Reusable RMS fixture generation logic imported from the production codebase.
- `src/pipelines/`
  Demo pipeline functions shared by the main CLI and Cargo examples.
- `examples/`
  Thin Cargo example entrypoints such as `matrix_mul` and `circom_json`.
- `src/bin/`
  Thin generator binaries such as `gen_rms_linear` and `gen_rms_poly_full`.
- `scripts/`
  Helper scripts for Circom batch runs and R1CS inspection.
- `data/generated/`
  Default output directory for generated fixture artifacts.

## Mapping From Imported Source

- `ref/r1cs_generators/src/r1cs_export.rs`
  Merged into `src/export.rs`.
- `ref/r1cs_generators/src/rms_poly.rs`
  Merged into `src/generators/poly.rs`.
- `ref/r1cs_generators/src/bin/gen_rms_linear.rs`
  Now exposed as `src/bin/gen_rms_linear.rs` with shared logic in
  `src/generators/linear.rs`.
- `ref/r1cs_generators/src/bin/gen_rms_mul.rs`
  Now exposed as `src/bin/gen_rms_mul.rs` with shared logic in
  `src/generators/mul.rs`.
- `ref/r1cs_generators/src/bin/gen_rms_poly.rs`
  Now exposed as `src/bin/gen_rms_poly.rs` with shared logic in
  `src/generators/poly.rs`.
- `ref/r1cs_generators/src/bin/gen_rms_poly_full.rs`
  Now exposed as `src/bin/gen_rms_poly_full.rs` with shared logic in
  `src/generators/poly.rs`.

`ref/` is no longer needed after integration and has been removed.
