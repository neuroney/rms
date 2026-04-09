//! Command-line entrypoint and dispatch.

use crate::{
    circom, db_select, dense_poly, fix_mat, greater_than, mimc7, page_rank, random_linear,
    random_mul, two_mat,
};
use std::process::ExitCode;

pub fn run() -> ExitCode {
    match dispatch(std::env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(args: Vec<String>) -> Result<(), String> {
    let Some(command) = args.first() else {
        two_mat::run();
        return Ok(());
    };

    let rest = &args[1..];
    match command.as_str() {
        "fixmat" | "fix_mat" | "fix-mat" => fix_mat::run_with_args(rest),
        "twomat" | "two_mat" | "two-mat" => two_mat::run_with_args(rest),
        "pubdb" | "pub_db" | "pub-db" => db_select::run_pub_with_args(rest),
        "privdb" | "priv_db" | "priv-db" => db_select::run_priv_with_args(rest),
        "greater" | "gt" | "greater_than" | "greaterthan" => greater_than::run_with_args(rest),
        "mimc7" | "mimc" => mimc7::run_with_args(rest),
        "pagerank" | "page_rank" | "page-rank" => page_rank::run_with_args(rest),
        "random_mul" | "mul" => random_mul::run_with_args(rest),
        "random_linear" | "linear" => random_linear::run_with_args(rest),
        "dense_poly" | "poly" | "poly_dense" => dense_poly::run_with_args(rest),
        "circom" | "circom_json" | "circom_r1cs" | "import" => circom::run_with_args(rest),
        "--help" | "-h" | "help" => {
            print_usage();
            Ok(())
        }
        _ => Err(format!("Unknown command: {}\n\n{}", args.join(" "), usage_text())),
    }
}

fn print_usage() {
    println!("{}", usage_text());
}

fn usage_text() -> &'static str {
    "\
RMS Toolkit

Usage:
  cargo run
  cargo run -- fixmat [dim] [--json]
  cargo run -- twomat [dim] [--json]
  cargo run -- pubdb [x] [--json]
  cargo run -- privdb [x] [--json]
  cargo run -- greater_than [bit] [--json]
  cargo run -- mimc7 [num_rounds] [--json]
  cargo run -- page_rank [iterations] [--json]
  cargo run -- page_rank [num_vertices iterations] [--json]
  cargo run -- random_mul [num_inputs num_constraints] [--json]
  cargo run -- random_linear [num_inputs num_constraints] [--json]
  cargo run -- dense_poly [num_vars degree] [--json]
  cargo run -- import <constraints.json|circuit.r1cs|circuit.circom> [--json]
  cargo run -- circom <constraints.json|circuit.r1cs|circuit.circom> [--json]

Notes:
    Defaults to the TwoMat example.
    The toolkit includes 11 core commands: circom, dense_poly, fixmat, greater_than, mimc7, page_rank, privdb, pubdb, random_linear, random_mul, and twomat.
    Ten of them generate the final RMS artifact through Rust code paths; `circom` imports a generic Circom circuit and converts it to RMS.
    `fixmat` takes the square dimension for public fixed-matrix times private-vector multiplication, and `twomat` takes the dimension for two private square matrices.
    `page_rank` supports `iterations` or `num_vertices iterations`; `pubdb` and `privdb` take exponent `x` and set `n=2^x`; the remaining commands accept their respective size parameters.
    By default only `.bin` is exported; append `--json` to also emit `.json`."
}
