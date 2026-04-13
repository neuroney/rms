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
  db_select.rs      # public/private DB selection demos + API
  fix_mat.rs        # fixed public matrix times private vector demo + API
  two_mat.rs        # two private matrices multiplication demo + API
  greater_than.rs   # greater-than demo + API
  mimc7.rs          # hand-written MiMC7 RMS demo + API
  page_rank.rs      # sparse PageRank demo + API
  random_mul.rs     # random RMS multiplication-chain demo + API
  random_linear.rs  # random RMS linear-chain demo + API
  polyev.rs         # PolyEV polynomial demo + API
  evalr1cs.rs       # circuit execution and verification
  export.rs         # JSON/BIN export helpers
  r1cs.rs           # shared circuit data structures
  transform.rs      # Choudhuri transform and CSE
  utils.rs          # shared formatting and field helpers
data/               # runtime-generated exported artifacts
fixtures/           # checked-in Circom inputs and example artifacts
scripts/            # scaling and R1CS analysis helpers
docs/               # format and migration notes
```

Public API is organized under:

- `rmsgen::circom`
- `rmsgen::db_select`
- `rmsgen::fix_mat`
- `rmsgen::two_mat`
- `rmsgen::greater_than`
- `rmsgen::mimc7`
- `rmsgen::page_rank`
- `rmsgen::random_mul`
- `rmsgen::random_linear`
- `rmsgen::polyev`
- `rmsgen::export`
- `rmsgen::evalr1cs`
- `rmsgen::r1cs`
- `rmsgen::transform`
- `rmsgen::utils`

## Commands

The repository centers on these 11 CLI commands:

- `circom`: read a Circom constraints JSON, binary `.r1cs`, or `.circom` source and convert it to RMS
- `fixmat`: fixed public matrix times private vector, exported as RMS
- `greater_than`: hand-written greater-than circuit exported as RMS
- `mimc7`: hand-written recursive MiMC7 circuit with `x <- (x + k_i)^7`
- `pir`: private selection over a public database
- `privdb`: private selection over a private database
- `twomat`: two private matrices multiplication circuit exported as RMS
- `page_rank`: hand-written fixed-iteration PageRank circuit exported as RMS
- `random_mul`: directly sampled RMS multiplication chain
- `random_linear`: directly sampled RMS linear circuit
- `polyev`: dense multivariate polynomial compiled into RMS

## CLI Usage

```bash
cargo run
cargo run -- fixmat 6
cargo run -- twomat 6
cargo run -- pir 3
cargo run -- privdb 3
cargo run -- greater_than 16
cargo run -- mimc7 91
cargo run -- page_rank 8
cargo run -- page_rank 32 8
cargo run -- random_mul 8 128
cargo run -- random_linear 8 128
cargo run -- polyev 6 3
cargo run -- circom fixtures/circomlib_and.json
```

`cargo run` defaults to the `twomat` command.

Parameter summary:

- `fixmat`: `dim`
- `twomat`: `dim`
- `pir`: `x` (0-based address, DB is a public input, sets `n = 2^x`)
- `privdb`: `x` (0-based address, DB is a private input, sets `n = 2^x`)
- `greater_than`: `bit` (generates demo inputs bit by bit and supports arbitrary bit widths)
- `mimc7`: `num_rounds` (uses fixture-provided fixed round constants and iterates `x <- (x + k_i)^7`, up to 91 rounds)
- `page_rank`: `iterations` or `num_vertices iterations`
- `random_mul`: `num_inputs num_constraints`
- `random_linear`: `num_inputs num_constraints`
- `polyev`: `num_vars degree`

Commands export `.bin` files under `data/` by default.
Append `--json` to also emit a matching `.json` file.

Current exports use `rms-linear-v3`.

Binary `.bin` artifacts now contain a zstd-compressed custom payload with:

- `public_inputs` with 32-byte canonical BN254 field values
- `private_inputs` encoded as an explicit list, contiguous range, or bitset
- `output_witnesses` as the exported sample output witness index list
- `execution_order` omitted from the payload when it is sequential
- `constraint.index` omitted from the payload when it matches the array position
- `x0 = 1` as a reserved public input

Reader migration notes live in [docs/rms-linear-v3-reader-migration.md](docs/rms-linear-v3-reader-migration.md).

## Development

```bash
cargo fmt
cargo test -- --nocapture
```

## Notes

- CLI export artifacts are written under `data/`.
- Hand-written demos reserve `x0 = 1` as a public constant; demos that need an explicit zero
  constant reserve `x1 = 0` as an extra public input and mark the remaining external inputs as
  private.
- `fixmat` fixes a public `n x n` matrix in the circuit at setup time and keeps only the private
  input vector as external inputs.
- `twomat` keeps both `n x n` operands private.
- Circom exports preserve declared public/private inputs when the corresponding public values are
  available from the reference witness flow.
- `page_rank` keeps the circuit sparse by exposing per-edge propagation weights and the initial
  rank vector as private inputs, while compiling only a public sparse support pattern plus uniform
  teleportation constants into RMS.
- `page_rank` samples a sparse directed graph for the public support pattern by default:
  no self-loops and `p = min(8 / (n - 1), 1)`, which keeps expected out-degree roughly constant as
  `n` grows; demo private edge weights are then derived from `alpha = 17 / 20`.
- Scaling bin sweeps for the hand-written benchmarks can be launched via `scripts/run_scaling_bin_batch.sh`.
- R1CS inspection helpers live in `scripts/analyze_r1cs.py`; binary inspection now requires zstd support.
- Node dependencies in `package.json` are only needed for Circom/snarkjs-based fixture workflows.
