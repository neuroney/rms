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
  dense_poly.rs     # dense polynomial demo + API
  evalr1cs.rs       # circuit execution and verification
  export.rs         # JSON/BIN export helpers
  r1cs.rs           # shared circuit data structures
  transform.rs      # Choudhuri transform and CSE
  utils.rs          # shared formatting and field helpers
data/               # runtime-generated exported artifacts
fixtures/           # checked-in Circom inputs and example artifacts
scripts/            # scaling and R1CS analysis helpers
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
- `rmsgen::dense_poly`
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
- `pubdb`: private selection over a public database
- `privdb`: private selection over a private database
- `twomat`: two private matrices multiplication circuit exported as RMS
- `page_rank`: hand-written fixed-iteration PageRank circuit exported as RMS
- `random_mul`: directly sampled RMS multiplication chain
- `random_linear`: directly sampled RMS linear circuit
- `dense_poly`: dense multivariate polynomial compiled into RMS

## CLI Usage

```bash
cargo run
cargo run -- fixmat 6
cargo run -- twomat 6
cargo run -- pubdb 3
cargo run -- privdb 3
cargo run -- greater_than 16
cargo run -- mimc7 91
cargo run -- page_rank 8
cargo run -- page_rank 32 8
cargo run -- random_mul 8 128
cargo run -- random_linear 8 128
cargo run -- dense_poly 6 3
cargo run -- circom fixtures/circomlib_and.json
```

`cargo run` defaults to the `twomat` command.

Parameter summary:

- `fixmat`: `dim`
- `twomat`: `dim`
- `pubdb`: `x`（0-based 地址，DB 为 public input，设置 `n = 2^x`）
- `privdb`: `x`（0-based 地址，DB 为 private input，设置 `n = 2^x`）
- `greater_than`: `bit`（按位生成演示输入，支持任意位宽）
- `mimc7`: `num_rounds`（使用 fixture 内置的固定 round constants，按 `x <- (x + k_i)^7` 递推，最大 91）
- `page_rank`: `iterations` or `num_vertices iterations`
- `random_mul`: `num_inputs num_constraints`
- `random_linear`: `num_inputs num_constraints`
- `dense_poly`: `num_vars degree`

Commands export `.json` and `.bin` files under `data/`.

Current exports use `rms-linear-v2`, which records:

- `public_inputs` with concrete field values
- `private_inputs` as index metadata only
- `output_witnesses` as the exported sample output witness index list
- `x0 = 1` as a reserved public input

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
- R1CS inspection helpers live in `scripts/analyze_r1cs.py`.
- Node dependencies in `package.json` are only needed for Circom/snarkjs-based fixture workflows.
