# RMS Toolkit

This repository focuses on one job: generate RMS-compatible `.bin` artifacts.

It exposes a small set of top-level circuit modules, while keeping shared R1CS and
export machinery reusable from the library.

## Project Layout

```text
src/
  lib.rs            # crate entrypoint
  cli.rs            # command-line dispatch
  circom.rs         # public Circom import + transform workflow
  circom_reader.rs  # Circom parsing/import internals
  matrix_mul.rs     # matrix multiplication demo + API
  greater_than.rs   # greater-than demo + API
  page_rank.rs      # sparse PageRank demo + API
  random_mul.rs     # random RMS multiplication-chain demo + API
  random_linear.rs  # random RMS linear-chain demo + API
  dense_poly.rs     # dense polynomial demo + API
  evalr1cs.rs       # circuit execution and verification
  export.rs         # JSON/BIN export helpers
  r1cs.rs           # shared circuit data structures
  transform.rs      # Choudhuri transform and CSE
  utils.rs          # shared formatting and field helpers
data/               # exported artifacts and reusable generated outputs
fixtures/           # checked-in Circom inputs and example artifacts
scripts/            # Circom batch and R1CS analysis helpers
docs/               # repository structure notes
```

Public API is organized under:

- `rmsgen::circom`
- `rmsgen::matrix_mul`
- `rmsgen::greater_than`
- `rmsgen::page_rank`
- `rmsgen::random_mul`
- `rmsgen::random_linear`
- `rmsgen::dense_poly`
- `rmsgen::export`
- `rmsgen::evalr1cs`
- `rmsgen::r1cs`
- `rmsgen::transform`
- `rmsgen::utils`

## Commands

The repository centers on these 7 CLI commands:

- `circom`: read a Circom constraints JSON, binary `.r1cs`, or `.circom` source and convert it to RMS
- `greater_than`: hand-written greater-than circuit exported as RMS
- `matrix_mul`: hand-written matrix multiplication circuit exported as RMS
- `page_rank`: hand-written fixed-iteration PageRank circuit exported as RMS
- `random_mul`: directly sampled RMS multiplication chain
- `random_linear`: directly sampled RMS linear circuit
- `dense_poly`: dense multivariate polynomial compiled into RMS

## CLI Usage

```bash
cargo run
cargo run -- matrix_mul 6
cargo run -- matrix_mul 4 8 6
cargo run -- greater_than 16
cargo run -- page_rank 8
cargo run -- random_mul 8 128
cargo run -- random_linear 8 128
cargo run -- dense_poly 6 3
cargo run -- circom fixtures/circomlib_and_o0.json
```

`cargo run` defaults to the matrix multiplication command.

Parameter summary:

- `matrix_mul`: `dim` or `rows shared cols`
- `greater_than`: `bit`
- `page_rank`: `iterations`
- `random_mul`: `num_inputs num_constraints`
- `random_linear`: `num_inputs num_constraints`
- `dense_poly`: `num_vars degree`

Commands export `.json` and `.bin` files under `data/`.

Current exports use `rms-linear-v2`, which records:

- `public_inputs` with concrete field values
- `private_inputs` as index metadata only
- `x0 = 1` as a reserved public input

## Development

```bash
cargo fmt
cargo test -- --nocapture
```

## Notes

- CLI export artifacts are written under `data/`.
- Hand-written demos export `x0 = 1` as the only default public input and mark the remaining
  external inputs as private.
- Circom exports preserve declared public/private inputs when the corresponding public values are
  available from the reference witness flow.
- `page_rank` keeps the Google matrix sparse in the circuit by compiling
  edge propagation, dangling-mass handling, and teleportation as separate RMS steps.
- Circom fixture batch runs are orchestrated by `scripts/run_fixture_circom_batch.sh`.
- R1CS inspection helpers live in `scripts/analyze_r1cs.py` and `scripts/compare_circuits.py`.
- Node dependencies in `package.json` are only needed for Circom/snarkjs-based fixture workflows.
