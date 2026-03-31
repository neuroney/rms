# RMS Toolkit

Hand-built R1CS/RMS playground for:

- constructing small circuits directly in Rust
- importing Circom JSON and binary `.r1cs` artifacts
- executing witness assignments against normalized circuits
- applying the Choudhuri transform and CSE optimization
- exporting RMS-compatible linear circuits to JSON and BIN
- generating production-style RMS benchmark fixtures and polynomial circuits

The project is library-first: reusable logic lives in `src/`, runnable demos live in Cargo's root-level `examples/`, and generator tools live in `src/bin/`.

## Project Layout

```text
src/
  lib.rs            # crate entrypoint
  circuits/         # hand-built circuit generators
  generators/       # imported production RMS fixture generators
  pipelines/        # demo pipelines used by CLI and examples
  bin/              # standalone generator binaries
  cli.rs            # command-line dispatch
  circom_json.rs    # Circom import pipeline internals
  evalr1cs.rs       # circuit execution and verification
  export.rs         # JSON/BIN export helpers
  r1cs.rs           # circuit data structures and hand-built generators
  transform.rs      # Choudhuri transform and CSE
  utils.rs          # shared formatting and field helpers
examples/           # Cargo examples (recommended modern Rust layout)
data/generated/     # generated RMS benchmark artifacts (gitignored)
fixtures/           # checked-in Circom inputs and example artifacts
scripts/            # Circom batch and R1CS analysis helpers
docs/               # repository structure and migration notes
```

Public API is organized under:

- `zkbench::r1cs`
- `zkbench::circuits`
- `zkbench::circom_json`
- `zkbench::evalr1cs`
- `zkbench::export`
- `zkbench::generators`
- `zkbench::pipelines`
- `zkbench::transform`
- `zkbench::utils`

`docs/repository-layout.md` records how the imported source code maps onto the active repository layout.

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
cargo run --example matrix_mul
cargo run --example greater_than
cargo run --example random_rms
cargo run --example circom_json -- fixtures/circomlib_and_o0.json
cargo run --bin gen_rms_linear
cargo run --bin gen_rms_mul
cargo run --bin gen_rms_poly json
RMS_POLY_FULL_MAX_DEGREE=7 cargo run --bin gen_rms_poly_full bin
```

`cargo run` defaults to the matrix multiplication example.

Generator outputs are written to `data/generated/` by default.

## Development

Format and test locally with:

```bash
cargo fmt
cargo test -- --nocapture
```

## Notes

- Generated export artifacts are written under `target/`.
- Benchmark fixture generators write to `data/generated/`.
- Circom fixture batch runs are orchestrated by `scripts/run_fixture_circom_batch.sh`.
- R1CS inspection helpers live in `scripts/analyze_r1cs.py` and `scripts/compare_circuits.py`.
- Node dependencies in `package.json` are only needed for Circom/snarkjs-based fixture workflows.
- Reusable library modules belong under `src/`; modern Rust examples are root-level `examples/`; executable tools belong in `src/bin/`.
