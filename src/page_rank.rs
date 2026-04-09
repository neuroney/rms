//! Sparse PageRank demo circuit generation, transformation, evaluation, and export.

use crate::evalr1cs::{execute_circuit, verify_assignment, Assignment};
use crate::export::{
    load_r1cs_from_bin, split_export_cli_args, terms_to_export_string,
    write_export_bundle_with_options, ExportBundleOptions, ExportInputConfig, WrittenArtifacts,
};
use crate::r1cs::{Constraint, LinComb, RmsLinearExport, Variable, R1CS};
use crate::transform::{
    choudhuri_transform, eliminate_common_subexpressions_preserving_witnesses, TransformResult,
};
use crate::utils::{
    format_preview_list, print_constraints, print_preview_matrix, PREVIEW_MAX_MATRIX_ROWS,
    PREVIEW_MAX_VECTOR_ITEMS,
};
use ark_bn254::Fr;
use ark_ff::{Field, One, Zero};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::collections::BTreeSet;

pub const DEFAULT_NUM_VERTICES: usize = 16;
pub const DEFAULT_ITERATIONS: usize = 5;
pub const DEFAULT_TARGET_OUT_DEGREE: usize = 8;
pub const DEFAULT_SEED: u64 = 42;
pub const DEFAULT_ALPHA_NUM: u64 = 17;
pub const DEFAULT_ALPHA_DEN: u64 = 20;
const FIRST_EXTERNAL_INPUT_INDEX: usize = 1;
const PROBABILITY_EPSILON: f64 = 1e-9;

#[derive(Clone, Debug)]
pub struct SparseEdgeInput {
    pub source: usize,
    pub target: usize,
    pub weight: Fr,
    pub weight_approx: f64,
}

#[derive(Clone, Debug)]
pub struct PageRankCircuit {
    pub r1cs: R1CS,
    pub num_vertices: usize,
    pub num_iterations: usize,
    pub edge_weight_input_indices: Vec<usize>,
    pub initial_rank_input_indices: Vec<usize>,
    pub iteration_rank_witness_indices: Vec<Vec<usize>>,
    pub residual_scaled_witness_indices: Vec<Vec<usize>>,
    pub residual_total_witness_indices: Vec<usize>,
    pub output_witness_indices: Vec<usize>,
}

#[derive(Clone, Debug)]
pub struct PageRankRunConfig {
    pub num_vertices: usize,
    pub edge_weights: Vec<SparseEdgeInput>,
    pub initial_rank: Vec<Fr>,
    pub initial_rank_approx: Vec<f64>,
    pub iterations: usize,
    pub export_stem: String,
}

#[derive(Clone, Debug)]
pub struct CompiledPageRank {
    pub num_vertices: usize,
    pub iterations: usize,
    pub support: Vec<Vec<u8>>,
    pub edge_weights: Vec<SparseEdgeInput>,
    pub teleport: Vec<Fr>,
    pub teleport_approx: Vec<f64>,
    pub out_degrees: Vec<usize>,
    pub outgoing_edge_indices: Vec<Vec<usize>>,
    pub incoming_edge_indices: Vec<Vec<usize>>,
    pub row_weight_sums: Vec<Fr>,
    pub row_weight_sums_approx: Vec<f64>,
    pub residual_mass: Vec<Fr>,
    pub residual_mass_approx: Vec<f64>,
}

#[derive(Clone, Debug)]
pub struct GeneratedPageRank {
    pub config: PageRankRunConfig,
    pub compiled: CompiledPageRank,
    pub circuit: PageRankCircuit,
    pub input_assignment: Vec<(usize, Fr)>,
    pub initial_rank: Vec<Fr>,
    pub initial_rank_approx: Vec<f64>,
    pub expected_output: Vec<Fr>,
    pub expected_output_approx: Vec<f64>,
}

#[derive(Clone, Debug)]
pub struct TransformedPageRank {
    pub transformed: TransformResult,
    pub optimized: R1CS,
    pub eliminated: usize,
}

#[derive(Clone, Debug)]
pub struct PageRankEvalReport {
    pub expected_output: Vec<Fr>,
    pub expected_output_approx: Vec<f64>,
    pub original_output: Vec<Fr>,
    pub transformed_output: Vec<Fr>,
    pub original_valid: bool,
    pub transformed_valid: bool,
    pub outputs_match: bool,
}

pub type PageRankExportReport = WrittenArtifacts;

impl PageRankRunConfig {
    pub fn demo() -> Self {
        Self::sampled(DEFAULT_NUM_VERTICES, DEFAULT_ITERATIONS, DEFAULT_SEED)
    }

    pub fn demo_with_iterations(iterations: usize) -> Self {
        Self::sampled(DEFAULT_NUM_VERTICES, iterations, DEFAULT_SEED)
    }

    pub fn sampled(num_vertices: usize, iterations: usize, seed: u64) -> Self {
        let adjacency = sample_sparse_directed_graph(num_vertices, DEFAULT_TARGET_OUT_DEGREE, seed);
        let edge_weights = build_private_edge_weights_from_adjacency(
            &adjacency,
            DEFAULT_ALPHA_NUM,
            DEFAULT_ALPHA_DEN,
        );
        let (initial_rank, initial_rank_approx) =
            build_sample_rank_vector(num_vertices, seed.wrapping_add(1));

        Self {
            num_vertices,
            edge_weights,
            initial_rank,
            initial_rank_approx,
            iterations,
            export_stem: format!("data/page_rank_{}v_{}iter", num_vertices, iterations),
        }
    }

    pub fn from_adjacency(adjacency: Vec<Vec<u8>>, iterations: usize) -> Self {
        validate_adjacency(&adjacency);
        let num_vertices = adjacency.len();
        let edge_weights = build_private_edge_weights_from_adjacency(
            &adjacency,
            DEFAULT_ALPHA_NUM,
            DEFAULT_ALPHA_DEN,
        );
        let (initial_rank, initial_rank_approx) = build_uniform_rank_vector(num_vertices);

        Self {
            num_vertices,
            edge_weights,
            initial_rank,
            initial_rank_approx,
            iterations,
            export_stem: format!("data/page_rank_{}v_{}iter", num_vertices, iterations),
        }
    }

    pub fn from_sparse_private_inputs(
        num_vertices: usize,
        edge_weights: Vec<SparseEdgeInput>,
        initial_rank: Vec<Fr>,
        initial_rank_approx: Vec<f64>,
        iterations: usize,
    ) -> Self {
        Self {
            num_vertices,
            edge_weights,
            initial_rank,
            initial_rank_approx,
            iterations,
            export_stem: format!("data/page_rank_{}v_{}iter_custom", num_vertices, iterations),
        }
    }
}

pub fn generate_page_rank_r1cs(compiled: &CompiledPageRank) -> PageRankCircuit {
    assert!(compiled.num_vertices > 0, "PageRank vertex count must be greater than 0");
    assert!(compiled.iterations > 0, "PageRank iteration count must be greater than 0");

    let num_inputs =
        FIRST_EXTERNAL_INPUT_INDEX + compiled.edge_weights.len() + compiled.num_vertices;
    let mut r1cs = R1CS::new(num_inputs, 0);

    let edge_weight_input_indices = (FIRST_EXTERNAL_INPUT_INDEX
        ..FIRST_EXTERNAL_INPUT_INDEX + compiled.edge_weights.len())
        .collect::<Vec<_>>();
    let initial_rank_input_indices = (FIRST_EXTERNAL_INPUT_INDEX + compiled.edge_weights.len()
        ..FIRST_EXTERNAL_INPUT_INDEX + compiled.edge_weights.len() + compiled.num_vertices)
        .collect::<Vec<_>>();

    let mut next_witness = 2usize;

    let mut current_rank_witnesses = Vec::with_capacity(compiled.num_vertices);
    for &input_idx in &initial_rank_input_indices {
        let witness_idx = next_witness;
        next_witness += 1;
        r1cs.add_constraint(
            Constraint {
                a: LinComb::from_var(Variable::Input(input_idx)),
                b: LinComb::from_var(Variable::Witness(1)),
                c: LinComb::from_var(Variable::Witness(witness_idx)),
            },
            witness_idx,
        );
        current_rank_witnesses.push(witness_idx);
    }

    let mut iteration_rank_witness_indices = vec![current_rank_witnesses.clone()];
    let mut residual_scaled_witness_indices = Vec::with_capacity(compiled.iterations);
    let mut residual_total_witness_indices = Vec::with_capacity(compiled.iterations);

    for _ in 0..compiled.iterations {
        let mut residual_scaled_sources = Vec::with_capacity(compiled.num_vertices);
        for source in 0..compiled.num_vertices {
            let witness_idx = next_witness;
            next_witness += 1;

            let mut residual_terms =
                Vec::with_capacity(1 + compiled.outgoing_edge_indices[source].len());
            residual_terms.push((Fr::one(), Variable::Input(0)));
            for &edge_idx in &compiled.outgoing_edge_indices[source] {
                residual_terms.push((
                    -Fr::one(),
                    Variable::Input(edge_weight_input_indices[edge_idx]),
                ));
            }

            r1cs.add_constraint(
                Constraint {
                    a: LinComb::from_terms(residual_terms),
                    b: LinComb::from_var(Variable::Witness(current_rank_witnesses[source])),
                    c: LinComb::from_var(Variable::Witness(witness_idx)),
                },
                witness_idx,
            );
            residual_scaled_sources.push(witness_idx);
        }
        residual_scaled_witness_indices.push(residual_scaled_sources.clone());

        let residual_total_witness = next_witness;
        next_witness += 1;
        r1cs.add_constraint(
            Constraint {
                a: LinComb::from_var(Variable::Input(0)),
                b: witness_sum_lincomb(&residual_scaled_sources),
                c: LinComb::from_var(Variable::Witness(residual_total_witness)),
            },
            residual_total_witness,
        );
        residual_total_witness_indices.push(residual_total_witness);

        let mut edge_contrib_witnesses = Vec::with_capacity(compiled.edge_weights.len());
        for (edge_idx, edge) in compiled.edge_weights.iter().enumerate() {
            let witness_idx = next_witness;
            next_witness += 1;
            r1cs.add_constraint(
                Constraint {
                    a: LinComb::from_var(Variable::Input(edge_weight_input_indices[edge_idx])),
                    b: LinComb::from_var(Variable::Witness(current_rank_witnesses[edge.source])),
                    c: LinComb::from_var(Variable::Witness(witness_idx)),
                },
                witness_idx,
            );
            edge_contrib_witnesses.push(witness_idx);
        }

        let mut next_rank_witnesses = Vec::with_capacity(compiled.num_vertices);
        for target in 0..compiled.num_vertices {
            let teleport_term_witness = next_witness;
            next_witness += 1;
            r1cs.add_constraint(
                Constraint {
                    a: LinComb::from_terms(vec![(compiled.teleport[target], Variable::Input(0))]),
                    b: LinComb::from_var(Variable::Witness(residual_total_witness)),
                    c: LinComb::from_var(Variable::Witness(teleport_term_witness)),
                },
                teleport_term_witness,
            );

            let next_rank_witness = next_witness;
            next_witness += 1;
            let mut terms = compiled.incoming_edge_indices[target]
                .iter()
                .map(|&edge_idx| {
                    (
                        Fr::one(),
                        Variable::Witness(edge_contrib_witnesses[edge_idx]),
                    )
                })
                .collect::<Vec<_>>();
            terms.push((Fr::one(), Variable::Witness(teleport_term_witness)));

            r1cs.add_constraint(
                Constraint {
                    a: LinComb::from_var(Variable::Input(0)),
                    b: LinComb::from_terms(terms),
                    c: LinComb::from_var(Variable::Witness(next_rank_witness)),
                },
                next_rank_witness,
            );
            next_rank_witnesses.push(next_rank_witness);
        }

        current_rank_witnesses = next_rank_witnesses.clone();
        iteration_rank_witness_indices.push(next_rank_witnesses);
    }

    r1cs.num_witnesses = next_witness - 1;

    PageRankCircuit {
        output_witness_indices: current_rank_witnesses,
        r1cs,
        num_vertices: compiled.num_vertices,
        num_iterations: compiled.iterations,
        edge_weight_input_indices,
        initial_rank_input_indices,
        iteration_rank_witness_indices,
        residual_scaled_witness_indices,
        residual_total_witness_indices,
    }
}

pub fn generate_circuit(config: PageRankRunConfig) -> GeneratedPageRank {
    validate_config(&config);

    let compiled = compile_page_rank(&config);
    let circuit = generate_page_rank_r1cs(&compiled);
    let initial_rank = config.initial_rank.clone();
    let initial_rank_approx = config.initial_rank_approx.clone();
    let input_assignment = build_private_input_assignment(
        &circuit.edge_weight_input_indices,
        &compiled.edge_weights,
        &circuit.initial_rank_input_indices,
        &initial_rank,
    );
    let expected_output = simulate_sparse_field(&compiled, &initial_rank);
    let expected_output_approx = simulate_sparse_f64(&compiled, &initial_rank_approx);

    GeneratedPageRank {
        config,
        compiled,
        circuit,
        input_assignment,
        initial_rank,
        initial_rank_approx,
        expected_output,
        expected_output_approx,
    }
}

pub fn transform_circuit(generated: &GeneratedPageRank) -> TransformedPageRank {
    let transformed = choudhuri_transform(&generated.circuit.r1cs);
    let (optimized, eliminated) = eliminate_common_subexpressions_preserving_witnesses(
        &transformed.r1cs,
        &generated.circuit.output_witness_indices,
    );

    TransformedPageRank {
        transformed,
        optimized,
        eliminated,
    }
}

pub fn evaluate_equivalence(
    generated: &GeneratedPageRank,
    transformed: &TransformedPageRank,
) -> PageRankEvalReport {
    let mut original_assignment = Assignment::from_field_inputs(generated.input_assignment.clone());
    let _ = execute_circuit(&generated.circuit.r1cs, &mut original_assignment).is_some();
    let original_valid = verify_assignment(&generated.circuit.r1cs, &original_assignment);
    let original_output = read_output_vector(
        &generated.circuit.output_witness_indices,
        &original_assignment,
    );

    let mut transformed_assignment =
        Assignment::from_field_inputs(generated.input_assignment.clone());
    let _ = execute_circuit(&transformed.optimized, &mut transformed_assignment).is_some();
    let transformed_valid = verify_assignment(&transformed.optimized, &transformed_assignment);
    let transformed_output = read_output_vector(
        &generated.circuit.output_witness_indices,
        &transformed_assignment,
    );

    PageRankEvalReport {
        expected_output: generated.expected_output.clone(),
        expected_output_approx: generated.expected_output_approx.clone(),
        original_output: original_output.clone(),
        transformed_output: transformed_output.clone(),
        original_valid,
        transformed_valid,
        outputs_match: original_output == generated.expected_output
            && transformed_output == generated.expected_output,
    }
}

pub fn export_circuit(
    generated: &GeneratedPageRank,
    transformed: &TransformedPageRank,
) -> Result<PageRankExportReport, Box<dyn std::error::Error>> {
    export_circuit_with_options(generated, transformed, ExportBundleOptions::default())
}

pub fn export_circuit_with_options(
    generated: &GeneratedPageRank,
    transformed: &TransformedPageRank,
    export_options: ExportBundleOptions,
) -> Result<PageRankExportReport, Box<dyn std::error::Error>> {
    let export = RmsLinearExport::from_r1cs_with_inputs(
        &transformed.optimized,
        &page_rank_export_input_config(generated.circuit.r1cs.num_inputs),
    )?
    .with_output_witnesses(generated.circuit.output_witness_indices.clone());

    write_export_bundle_with_options(&generated.config.export_stem, &export, export_options)
}

pub fn run() {
    run_with_args(&[]).expect("PageRank example failed");
}

pub fn run_with_args(args: &[String]) -> Result<(), String> {
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        return Err(usage_text().to_string());
    }

    let (args, export_options) = split_export_cli_args(args);
    let config = match args.as_slice() {
        [] => PageRankRunConfig::demo(),
        [iterations] => PageRankRunConfig::demo_with_iterations(parse_positive_usize_arg(
            "iterations",
            iterations,
        )?),
        [num_vertices, iterations] => PageRankRunConfig::sampled(
            parse_positive_usize_arg("num_vertices", num_vertices)?,
            parse_positive_usize_arg("iterations", iterations)?,
            DEFAULT_SEED,
        ),
        _ => return Err(usage_text().to_string()),
    };

    run_with_config(config, export_options)
}

fn run_with_config(
    config: PageRankRunConfig,
    export_options: ExportBundleOptions,
) -> Result<(), String> {
    let generated = generate_circuit(config);
    let transformed = transform_circuit(&generated);
    let evaluation = evaluate_equivalence(&generated, &transformed);
    let export = export_circuit_with_options(&generated, &transformed, export_options)
        .map_err(|err| format!("Failed to export PageRank RMS circuit: {err}"))?;

    let audit_matrix = build_transition_matrix_approx(&generated.compiled);

    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║  PageRank: public sparse support + private edge weights/initial rank ║");
    println!("╚══════════════════════════════════════════════════════╝\n");

    println!("[1. Circuit generation]");
    println!("  Vertex count: {}", generated.compiled.num_vertices);
    println!("  Sparse edge count: {}", generated.compiled.edge_weights.len());
    println!(
        "  Average public out-degree: {:.2}",
        average_out_degree(&generated.compiled.out_degrees)
    );
    println!(
        "  Demo sampling weight: alpha = {}/{} (used only to generate private edge weights)",
        DEFAULT_ALPHA_NUM, DEFAULT_ALPHA_DEN
    );
    println!("  Public sparse support S:");
    print_adjacency_matrix(&generated.compiled.support);
    println!("  Private edge weights W_sparse (printed for demo audit only):");
    print_private_edge_weights(
        &generated.compiled.edge_weights,
        &generated.compiled.outgoing_edge_indices,
    );
    println!("  Per-row private weight sum / teleport residual:");
    print_row_mass_summary(
        &generated.compiled.row_weight_sums_approx,
        &generated.compiled.residual_mass_approx,
    );
    println!(
        "  Private initial rank r^(0): {}",
        format_approx_vector(&generated.initial_rank_approx)
    );
    println!("  Dense transition matrix G for audit only:");
    print_approx_matrix("G", &audit_matrix);
    generated.circuit.r1cs.print_stats();

    println!("\n[2. Circuit transformation]");
    transformed.transformed.r1cs.print_stats();
    println!(
        "  Choudhuri blowup factor: {:.2}x",
        transformed.transformed.blowup_factor
    );
    println!("  CSE eliminated duplicate constraints: {}", transformed.eliminated);
    println!(
        "  Final blowup factor: {:.2}x",
        transformed.optimized.constraints.len() as f64
            / generated.circuit.r1cs.constraints.len() as f64
    );

    println!("\n[3. Eval consistency]");
    println!(
        "  Expected PageRank(T): {}",
        format_approx_vector(&evaluation.expected_output_approx)
    );
    println!(
        "  Outputs match: {}  [constraints satisfied: orig={}, rms+cse={}]",
        evaluation.outputs_match, evaluation.original_valid, evaluation.transformed_valid
    );

    println!("\n[4. Circuit export]");
    println!("  BIN:  {}", export.bin_path);
    if let Some(json_path) = &export.json_path {
        println!("  JSON: {}", json_path);
    }
    println!("  Version: {}", export.version);
    println!("  Constraints: {}", export.num_constraints);
    if let Some(json_bin_match) = export.json_bin_match {
        println!("  JSON/BIN contents match: {}", json_bin_match);
    }
    println!("  First 8 final RMS constraints:");
    let exported_bin = load_r1cs_from_bin(&export.bin_path).expect("Failed to read BIN export file");
    for constraint in exported_bin.constraints.iter().take(8) {
        println!(
            "    step {:>2}: ({} ) * ({} ) -> w{}",
            constraint.index,
            terms_to_export_string(&constraint.a_in, "x"),
            terms_to_export_string(&constraint.b_wit, "w"),
            constraint.output_witness
        );
    }

    println!("\n[Preview of the first 8 original constraints]");
    let original_preview = R1CS {
        num_inputs: generated.circuit.r1cs.num_inputs,
        num_witnesses: generated.circuit.r1cs.num_witnesses,
        constraints: generated
            .circuit
            .r1cs
            .constraints
            .iter()
            .take(8)
            .cloned()
            .collect(),
        origin: generated.circuit.r1cs.origin.clone(),
    };
    print_constraints(&original_preview);

    Ok(())
}

fn validate_config(config: &PageRankRunConfig) {
    assert!(config.num_vertices > 0, "PageRank graph cannot be empty");
    assert!(config.iterations > 0, "PageRank iteration count must be greater than 0");
    assert_eq!(
        config.initial_rank.len(),
        config.num_vertices,
        "Initial rank length must equal the vertex count"
    );
    assert_eq!(
        config.initial_rank_approx.len(),
        config.num_vertices,
        "Initial rank approximation length must equal the vertex count"
    );

    let initial_sum = config.initial_rank_approx.iter().sum::<f64>();
    assert!(
        (initial_sum - 1.0).abs() <= PROBABILITY_EPSILON,
        "Initial rank approximation must sum to 1, current sum is {initial_sum:.6}"
    );
    assert!(
        config
            .initial_rank_approx
            .iter()
            .all(|&value| value >= -PROBABILITY_EPSILON),
        "Initial rank approximation values must be non-negative"
    );

    let mut seen_edges = BTreeSet::new();
    let mut row_weight_sums_approx = vec![0.0; config.num_vertices];
    for edge in &config.edge_weights {
        assert!(
            edge.source < config.num_vertices && edge.target < config.num_vertices,
            "Edge ({}, {}) exceeds vertex range [0, {})",
            edge.source,
            edge.target,
            config.num_vertices
        );
        assert!(
            seen_edges.insert((edge.source, edge.target)),
            "Duplicate sparse edge ({}, {})",
            edge.source,
            edge.target
        );
        assert!(
            edge.weight_approx >= -PROBABILITY_EPSILON,
            "Edge weight approximation must be non-negative"
        );
        row_weight_sums_approx[edge.source] += edge.weight_approx;
    }

    for (source, row_sum) in row_weight_sums_approx.iter().enumerate() {
        assert!(
            *row_sum <= 1.0 + PROBABILITY_EPSILON,
            "Sparse edge weight sum for source v{} must not exceed 1, current sum is {:.6}",
            source,
            row_sum
        );
    }
}

fn validate_adjacency(adjacency: &[Vec<u8>]) {
    assert!(!adjacency.is_empty(), "PageRank graph cannot be empty");
    let num_vertices = adjacency.len();
    for (row_idx, row) in adjacency.iter().enumerate() {
        assert_eq!(
            row.len(),
            num_vertices,
            "Adjacency matrix row {} length does not match the vertex count",
            row_idx
        );
        assert!(
            row.iter().all(|&value| matches!(value, 0 | 1)),
            "Adjacency matrix must be a 0/1 matrix"
        );
    }
}

fn compile_page_rank(config: &PageRankRunConfig) -> CompiledPageRank {
    let mut support = vec![vec![0u8; config.num_vertices]; config.num_vertices];
    let mut outgoing_edge_indices = vec![Vec::new(); config.num_vertices];
    let mut incoming_edge_indices = vec![Vec::new(); config.num_vertices];
    let mut row_weight_sums = vec![Fr::zero(); config.num_vertices];
    let mut row_weight_sums_approx = vec![0.0; config.num_vertices];

    for (edge_idx, edge) in config.edge_weights.iter().enumerate() {
        support[edge.source][edge.target] = 1;
        outgoing_edge_indices[edge.source].push(edge_idx);
        incoming_edge_indices[edge.target].push(edge_idx);
        row_weight_sums[edge.source] += edge.weight;
        row_weight_sums_approx[edge.source] += edge.weight_approx;
    }

    let residual_mass = row_weight_sums
        .iter()
        .map(|row_sum| Fr::one() - *row_sum)
        .collect::<Vec<_>>();
    let residual_mass_approx = row_weight_sums_approx
        .iter()
        .map(|row_sum| 1.0 - row_sum)
        .collect::<Vec<_>>();
    let out_degrees = outgoing_edge_indices
        .iter()
        .map(|edges| edges.len())
        .collect::<Vec<_>>();
    let teleport = vec![fr_fraction(1, config.num_vertices as u64); config.num_vertices];
    let teleport_approx = vec![1.0 / config.num_vertices as f64; config.num_vertices];

    CompiledPageRank {
        num_vertices: config.num_vertices,
        iterations: config.iterations,
        support,
        edge_weights: config.edge_weights.clone(),
        teleport,
        teleport_approx,
        out_degrees,
        outgoing_edge_indices,
        incoming_edge_indices,
        row_weight_sums,
        row_weight_sums_approx,
        residual_mass,
        residual_mass_approx,
    }
}

fn build_uniform_rank_vector(num_vertices: usize) -> (Vec<Fr>, Vec<f64>) {
    let rank = fr_fraction(1, num_vertices as u64);
    let rank_approx = 1.0 / num_vertices as f64;
    (vec![rank; num_vertices], vec![rank_approx; num_vertices])
}

fn build_sample_rank_vector(num_vertices: usize, seed: u64) -> (Vec<Fr>, Vec<f64>) {
    assert!(num_vertices > 0, "PageRank graph cannot be empty");

    let mut rng = StdRng::seed_from_u64(seed);
    let raw_weights = (0..num_vertices)
        .map(|_| rng.gen_range(1u64..=10u64))
        .collect::<Vec<_>>();
    let total = raw_weights.iter().sum::<u64>();
    let total_inv = fr_inverse_u64(total);

    let initial_rank = raw_weights
        .iter()
        .map(|&value| Fr::from(value) * total_inv)
        .collect::<Vec<_>>();
    let initial_rank_approx = raw_weights
        .iter()
        .map(|&value| value as f64 / total as f64)
        .collect::<Vec<_>>();

    (initial_rank, initial_rank_approx)
}

fn build_private_edge_weights_from_adjacency(
    adjacency: &[Vec<u8>],
    alpha_num: u64,
    alpha_den: u64,
) -> Vec<SparseEdgeInput> {
    let alpha = fr_fraction(alpha_num, alpha_den);
    let alpha_approx = alpha_num as f64 / alpha_den as f64;
    let num_vertices = adjacency.len();
    let mut edge_weights = Vec::new();

    for source in 0..num_vertices {
        let out_degree = adjacency[source]
            .iter()
            .map(|&value| usize::from(value))
            .sum::<usize>();
        if out_degree == 0 {
            continue;
        }

        let weight = alpha * fr_inverse_u64(out_degree as u64);
        let weight_approx = alpha_approx / out_degree as f64;
        for target in 0..num_vertices {
            if adjacency[source][target] == 1 {
                edge_weights.push(SparseEdgeInput {
                    source,
                    target,
                    weight,
                    weight_approx,
                });
            }
        }
    }

    edge_weights
}

fn sample_sparse_directed_graph(
    num_vertices: usize,
    target_out_degree: usize,
    seed: u64,
) -> Vec<Vec<u8>> {
    assert!(num_vertices > 0, "PageRank graph cannot be empty");
    if num_vertices == 1 {
        return vec![vec![0]];
    }

    let edge_probability = (target_out_degree as f64 / (num_vertices - 1) as f64).clamp(0.0, 1.0);
    let mut rng = StdRng::seed_from_u64(seed);
    let mut adjacency = vec![vec![0u8; num_vertices]; num_vertices];

    for (source, row) in adjacency.iter_mut().enumerate() {
        for (target, value) in row.iter_mut().enumerate() {
            if source == target {
                continue;
            }

            if rng.gen_bool(edge_probability) {
                *value = 1;
            }
        }
    }

    adjacency
}

fn build_private_input_assignment(
    edge_weight_input_indices: &[usize],
    edge_weights: &[SparseEdgeInput],
    initial_rank_input_indices: &[usize],
    initial_rank: &[Fr],
) -> Vec<(usize, Fr)> {
    let mut inputs = Vec::with_capacity(edge_weights.len() + initial_rank.len());
    inputs.extend(
        edge_weight_input_indices
            .iter()
            .zip(edge_weights.iter())
            .map(|(&index, edge)| (index, edge.weight)),
    );
    inputs.extend(
        initial_rank_input_indices
            .iter()
            .zip(initial_rank.iter())
            .map(|(&index, &value)| (index, value)),
    );
    inputs
}

fn page_rank_export_input_config(num_inputs: usize) -> ExportInputConfig {
    ExportInputConfig::all_private(num_inputs)
}

fn witness_sum_lincomb(witnesses: &[usize]) -> LinComb {
    LinComb::from_terms(
        witnesses
            .iter()
            .map(|&witness| (Fr::one(), Variable::Witness(witness)))
            .collect(),
    )
}

fn simulate_sparse_field(compiled: &CompiledPageRank, initial_rank: &[Fr]) -> Vec<Fr> {
    let mut current = initial_rank.to_vec();

    for _ in 0..compiled.iterations {
        let residual_total = compiled
            .residual_mass
            .iter()
            .enumerate()
            .map(|(source, residual)| *residual * current[source])
            .fold(Fr::zero(), |acc, value| acc + value);

        let mut next = vec![Fr::zero(); compiled.num_vertices];
        for edge in &compiled.edge_weights {
            next[edge.target] += edge.weight * current[edge.source];
        }
        for target in 0..compiled.num_vertices {
            next[target] += compiled.teleport[target] * residual_total;
        }
        current = next;
    }

    current
}

fn simulate_sparse_f64(compiled: &CompiledPageRank, initial_rank: &[f64]) -> Vec<f64> {
    let mut current = initial_rank.to_vec();

    for _ in 0..compiled.iterations {
        let residual_total = compiled
            .residual_mass_approx
            .iter()
            .enumerate()
            .map(|(source, residual)| residual * current[source])
            .sum::<f64>();

        let mut next = vec![0.0; compiled.num_vertices];
        for edge in &compiled.edge_weights {
            next[edge.target] += edge.weight_approx * current[edge.source];
        }
        for target in 0..compiled.num_vertices {
            next[target] += compiled.teleport_approx[target] * residual_total;
        }
        current = next;
    }

    current
}

fn build_transition_matrix_approx(compiled: &CompiledPageRank) -> Vec<Vec<f64>> {
    let mut transition = vec![vec![0.0; compiled.num_vertices]; compiled.num_vertices];

    for source in 0..compiled.num_vertices {
        for target in 0..compiled.num_vertices {
            transition[source][target] +=
                compiled.teleport_approx[target] * compiled.residual_mass_approx[source];
        }
    }
    for edge in &compiled.edge_weights {
        transition[edge.source][edge.target] += edge.weight_approx;
    }

    transition
}

#[cfg(test)]
fn build_transition_matrix_field(compiled: &CompiledPageRank) -> Vec<Vec<Fr>> {
    let mut transition = vec![vec![Fr::zero(); compiled.num_vertices]; compiled.num_vertices];

    for source in 0..compiled.num_vertices {
        for target in 0..compiled.num_vertices {
            transition[source][target] +=
                compiled.teleport[target] * compiled.residual_mass[source];
        }
    }
    for edge in &compiled.edge_weights {
        transition[edge.source][edge.target] += edge.weight;
    }

    transition
}

#[cfg(test)]
fn simulate_dense_field(
    transition_matrix: &[Vec<Fr>],
    initial_rank: &[Fr],
    iterations: usize,
) -> Vec<Fr> {
    let mut current = initial_rank.to_vec();
    let num_vertices = current.len();

    for _ in 0..iterations {
        let mut next = vec![Fr::zero(); num_vertices];
        for target in 0..num_vertices {
            for source in 0..num_vertices {
                next[target] += transition_matrix[source][target] * current[source];
            }
        }
        current = next;
    }

    current
}

fn read_output_vector(output_witnesses: &[usize], assignment: &Assignment) -> Vec<Fr> {
    output_witnesses
        .iter()
        .map(|&witness_idx| assignment.witnesses[&witness_idx])
        .collect()
}

fn print_adjacency_matrix(adjacency: &[Vec<u8>]) {
    for row in adjacency.iter().take(PREVIEW_MAX_MATRIX_ROWS) {
        let shown = row.len().min(crate::utils::PREVIEW_MAX_MATRIX_COLS);
        let mut formatted = row
            .iter()
            .take(shown)
            .map(|value| format!("{:>2}", value))
            .collect::<Vec<_>>();
        if row.len() > crate::utils::PREVIEW_MAX_MATRIX_COLS {
            formatted.push(format!(
                "... (+{} cols)",
                row.len() - crate::utils::PREVIEW_MAX_MATRIX_COLS
            ));
        }
        println!("      [{}]", formatted.join(", "));
    }

    if adjacency.len() > PREVIEW_MAX_MATRIX_ROWS {
        println!(
            "      ... (+{} rows)",
            adjacency.len() - PREVIEW_MAX_MATRIX_ROWS
        );
    }
}

fn print_private_edge_weights(
    edge_weights: &[SparseEdgeInput],
    outgoing_edge_indices: &[Vec<usize>],
) {
    for (source, edge_indices) in outgoing_edge_indices
        .iter()
        .take(PREVIEW_MAX_MATRIX_ROWS)
        .enumerate()
    {
        if edge_indices.is_empty() {
            println!("    v{}: none", source);
            continue;
        }

        let formatted = format_preview_list(edge_indices, PREVIEW_MAX_VECTOR_ITEMS, |edge_idx| {
            let edge = &edge_weights[*edge_idx];
            format!("v{}: {:.6}", edge.target, edge.weight_approx)
        });
        println!("    v{} -> {}", source, formatted);
    }

    if outgoing_edge_indices.len() > PREVIEW_MAX_MATRIX_ROWS {
        println!(
            "    ... (+{} source rows)",
            outgoing_edge_indices.len() - PREVIEW_MAX_MATRIX_ROWS
        );
    }
}

fn print_row_mass_summary(row_weight_sums_approx: &[f64], residual_mass_approx: &[f64]) {
    for (source, (&row_sum, &residual)) in row_weight_sums_approx
        .iter()
        .zip(residual_mass_approx.iter())
        .take(PREVIEW_MAX_MATRIX_ROWS)
        .enumerate()
    {
        println!(
            "    v{}: row-sum≈{:.6}, residual≈{:.6}",
            source, row_sum, residual
        );
    }

    if row_weight_sums_approx.len() > PREVIEW_MAX_MATRIX_ROWS {
        println!(
            "    ... (+{} rows)",
            row_weight_sums_approx.len() - PREVIEW_MAX_MATRIX_ROWS
        );
    }
}

fn print_approx_matrix(name: &str, matrix: &[Vec<f64>]) {
    print_preview_matrix(name, matrix, |value| format!("{:>8.6}", value));
}

fn average_out_degree(out_degrees: &[usize]) -> f64 {
    out_degrees.iter().sum::<usize>() as f64 / out_degrees.len() as f64
}

fn format_approx_vector(values: &[f64]) -> String {
    format_preview_list(values, PREVIEW_MAX_VECTOR_ITEMS, |value| {
        format!("{:>8.6}", value)
    })
}

fn parse_positive_usize_arg(name: &str, raw: &str) -> Result<usize, String> {
    let value = raw
        .parse::<usize>()
        .map_err(|err| format!("{name} must be a non-negative integer, got {raw:?}: {err}"))?;
    if value == 0 {
        return Err(format!("{name} must be greater than 0"));
    }
    Ok(value)
}

fn fr_fraction(num: u64, den: u64) -> Fr {
    assert!(den > 0, "Denominator must be greater than 0");
    Fr::from(num) * fr_inverse_u64(den)
}

fn fr_inverse_u64(value: u64) -> Fr {
    Fr::from(value).inverse().expect("Denominator must be invertible in the current field")
}

fn usage_text() -> &'static str {
    "\
Usage:
  cargo run -- page_rank [--json]
  cargo run -- page_rank <iterations> [--json]
  cargo run -- page_rank <num_vertices> <iterations> [--json]

Notes:
    Default parameters: num_vertices=16, iterations=5.
    The public portion keeps only x0=1 and the sparse support pattern; private inputs include sparse edge weights and the initial rank.
    Demo private edge weights are derived from alpha=17/20 and a sampled adjacency matrix, and the row residual mass is distributed via uniform teleport.
    The sparse support is sampled as a directed G(n, p) graph by default, without self-loops, with p=min(8/(n-1), 1).
    By default only `.bin` is exported; append `--json` to also emit `.json`."
}

#[cfg(test)]
mod circuit_tests {
    use super::*;
    use crate::r1cs::RmsLinearExport;

    #[test]
    fn sparse_private_weights_match_dense_transition_semantics() {
        let config = PageRankRunConfig::from_adjacency(
            vec![
                vec![0, 1, 1, 0],
                vec![0, 0, 1, 0],
                vec![1, 0, 0, 0],
                vec![0, 0, 0, 0],
            ],
            3,
        );
        let compiled = compile_page_rank(&config);
        let dense_transition = build_transition_matrix_field(&compiled);
        let sparse_output = simulate_sparse_field(&compiled, &config.initial_rank);
        let dense_output =
            simulate_dense_field(&dense_transition, &config.initial_rank, compiled.iterations);

        assert_eq!(sparse_output, dense_output);
    }

    #[test]
    fn page_rank_circuit_is_rms_and_preserves_output() {
        let generated = generate_circuit(PageRankRunConfig::sampled(4, 2, DEFAULT_SEED));
        let transformed = transform_circuit(&generated);

        assert!(generated
            .circuit
            .r1cs
            .constraints
            .iter()
            .all(|constraint| constraint.is_rms_compatible()));
        assert!(generated
            .circuit
            .r1cs
            .constraints
            .iter()
            .all(|constraint| !constraint.a.terms.is_empty()));
        assert!(transformed
            .optimized
            .constraints
            .iter()
            .all(|constraint| constraint.is_rms_compatible()));
        assert!(transformed
            .optimized
            .constraints
            .iter()
            .all(|constraint| !constraint.a.terms.is_empty()));

        let mut original_assignment =
            Assignment::from_field_inputs(generated.input_assignment.clone());
        assert!(execute_circuit(&generated.circuit.r1cs, &mut original_assignment).is_some());
        assert!(verify_assignment(
            &generated.circuit.r1cs,
            &original_assignment
        ));
        let original_output = read_output_vector(
            &generated.circuit.output_witness_indices,
            &original_assignment,
        );
        assert_eq!(original_output, generated.expected_output);

        let mut optimized_assignment =
            Assignment::from_field_inputs(generated.input_assignment.clone());
        assert!(execute_circuit(&transformed.optimized, &mut optimized_assignment).is_some());
        assert!(verify_assignment(
            &transformed.optimized,
            &optimized_assignment
        ));
        let optimized_output = read_output_vector(
            &generated.circuit.output_witness_indices,
            &optimized_assignment,
        );
        assert_eq!(optimized_output, generated.expected_output);
    }

    #[test]
    fn page_rank_transform_preserves_outputs_for_zero_in_degree_targets() {
        let generated = generate_circuit(PageRankRunConfig::from_adjacency(
            vec![
                vec![0, 1, 1, 0],
                vec![0, 0, 1, 0],
                vec![1, 0, 0, 0],
                vec![0, 0, 0, 0],
            ],
            2,
        ));
        let transformed = transform_circuit(&generated);

        let mut optimized_assignment =
            Assignment::from_field_inputs(generated.input_assignment.clone());
        assert!(execute_circuit(&transformed.optimized, &mut optimized_assignment).is_some());
        assert!(verify_assignment(
            &transformed.optimized,
            &optimized_assignment
        ));

        let optimized_output = read_output_vector(
            &generated.circuit.output_witness_indices,
            &optimized_assignment,
        );
        assert_eq!(optimized_output, generated.expected_output);
    }

    #[test]
    fn export_marks_edge_weights_and_initial_rank_private() {
        let generated = generate_circuit(PageRankRunConfig::from_adjacency(
            vec![
                vec![0, 1, 1, 0],
                vec![0, 0, 1, 0],
                vec![1, 0, 0, 0],
                vec![0, 0, 0, 0],
            ],
            2,
        ));
        let export = RmsLinearExport::from_r1cs_with_inputs(
            &generated.circuit.r1cs,
            &page_rank_export_input_config(generated.circuit.r1cs.num_inputs),
        )
        .expect("Failed to export RMS with input metadata")
        .with_output_witnesses(generated.circuit.output_witness_indices.clone());

        assert_eq!(export.num_public_inputs, 1);
        assert_eq!(export.public_inputs[0].index, 0);
        assert_eq!(export.public_inputs[0].value, "1");
        assert_eq!(
            export.num_private_inputs,
            generated.compiled.edge_weights.len() + generated.compiled.num_vertices
        );

        let expected_private_inputs = generated
            .circuit
            .edge_weight_input_indices
            .iter()
            .chain(generated.circuit.initial_rank_input_indices.iter())
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(export.private_inputs, expected_private_inputs);
        assert_eq!(
            export.output_witnesses,
            generated.circuit.output_witness_indices
        );
    }

    #[test]
    fn sampled_graph_is_square_and_has_no_self_loops() {
        let adjacency = sample_sparse_directed_graph(12, DEFAULT_TARGET_OUT_DEGREE, DEFAULT_SEED);

        assert_eq!(adjacency.len(), 12);
        assert!(adjacency.iter().all(|row| row.len() == 12));
        assert!(adjacency
            .iter()
            .enumerate()
            .all(|(index, row)| row[index] == 0));
    }
}

#[cfg(test)]
mod pipeline_tests {
    use super::*;

    #[test]
    fn page_rank_demo_pipeline_keeps_output_after_transform() {
        let generated = generate_circuit(PageRankRunConfig::demo());
        let transformed = transform_circuit(&generated);
        let evaluation = evaluate_equivalence(&generated, &transformed);

        assert!(evaluation.original_valid);
        assert!(evaluation.transformed_valid);
        assert!(evaluation.outputs_match);
        assert_eq!(evaluation.original_output, evaluation.expected_output);
        assert_eq!(evaluation.transformed_output, evaluation.expected_output);
    }
}
