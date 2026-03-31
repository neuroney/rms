# RMS Toolkit

Hand-built R1CS/RMS playground for:

- constructing small circuits directly in Rust
- importing Circom JSON and binary `.r1cs` artifacts
- executing witness assignments against normalized circuits
- applying the Choudhuri transform and CSE optimization
- exporting RMS-compatible linear circuits to JSON and BIN

The project is library-first: reusable logic lives in the core library, while demo pipelines and the CLI sit on top.

## Project Layout

```text
src/
  lib.rs            # crate entrypoint
  core/             # public core API surface
  circuits/         # hand-built circuit generators
  cli.rs            # command-line dispatch
  examples/         # runnable demo pipelines
  circom_json.rs    # Circom import pipeline internals
  evalr1cs.rs       # circuit execution and verification
  export.rs         # JSON/BIN export helpers
  r1cs.rs           # circuit data structures and hand-built generators
  transform.rs      # Choudhuri transform and CSE
  utils.rs          # shared formatting and field helpers
```

Public API is organized under:

- `zkbench::core::r1cs`
- `zkbench::core::circuits`
- `zkbench::core::eval`
- `zkbench::core::transform`
- `zkbench::core::export`
- `zkbench::core::circom`
- `zkbench::examples`

## Examples

The repository currently ships these demo pipelines:

- `matrix_mul`: hand-built matrix multiplication circuit
- `greater_than`: hand-built secure integer comparison circuit
- `random`: synthetic RMS/R1CS transformation experiments
- `circom <path>`: import a Circom constraints JSON or binary `.r1cs` file

## CLI Usage

```bash
cargo run
cargo run -- matrix_mul
cargo run -- greater_than
cargo run -- random
cargo run -- circom fixtures/circomlib_and_o0.json
```

`cargo run` defaults to the matrix multiplication example.

## Development

Format and test locally with:

```bash
cargo fmt
cargo test -- --nocapture
```

## Notes

- Generated export artifacts are written under `target/`.
- Circom fixture batch runs are orchestrated by `scripts/run_fixture_circom_batch.sh`.
- Node dependencies in `package.json` are only needed for Circom/snarkjs-based fixture workflows.
