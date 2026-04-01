use crate::evalr1cs::{execute_circuit, verify_assignment, Assignment};
use crate::export::{
    export_r1cs_bundle, load_r1cs_from_json, terms_to_export_string, WrittenArtifacts,
};
use crate::r1cs::{Constraint, LinComb, Variable, R1CS};
use crate::transform::{choudhuri_transform, eliminate_common_subexpressions, TransformResult};
use crate::utils::print_constraints;
use ark_bn254::Fr;
use ark_ff::{Field, One, Zero};

#[derive(Clone, Debug)]
pub struct PageRankCircuit {
    pub r1cs: R1CS,
    pub num_vertices: usize,
    pub num_iterations: usize,
    pub initial_rank_input_indices: Vec<usize>,
    pub iteration_rank_witness_indices: Vec<Vec<usize>>,
    pub total_mass_witness_indices: Vec<usize>,
    pub dangling_mass_witness_indices: Vec<usize>,
    pub teleport_scalar_witness_indices: Vec<usize>,
    pub output_witness_indices: Vec<usize>,
}

#[derive(Clone, Debug)]
pub struct PageRankRunConfig {
    pub adjacency: Vec<Vec<u8>>,
    pub alpha_num: u64,
    pub alpha_den: u64,
    pub iterations: usize,
    pub export_stem: String,
}

#[derive(Clone, Debug)]
pub struct CompiledPageRank {
    pub num_vertices: usize,
    pub iterations: usize,
    pub adjacency: Vec<Vec<u8>>,
    pub alpha: Fr,
    pub one_minus_alpha: Fr,
    pub alpha_approx: f64,
    pub teleport: Vec<Fr>,
    pub teleport_approx: Vec<f64>,
    pub out_degrees: Vec<usize>,
    pub dangling_vertices: Vec<usize>,
    pub source_weights: Vec<Option<Fr>>,
    pub source_weights_approx: Vec<Option<f64>>,
    pub incoming_sources: Vec<Vec<usize>>,
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
        Self::demo_with_iterations(5)
    }

    pub fn demo_with_iterations(iterations: usize) -> Self {
        let adjacency = vec![
            vec![0, 1, 1, 0],
            vec![0, 0, 1, 0],
            vec![1, 0, 0, 0],
            vec![0, 0, 0, 0],
        ];

        Self {
            export_stem: format!("data/page_rank_{}v_{}iter_rms", adjacency.len(), iterations),
            adjacency,
            alpha_num: 17,
            alpha_den: 20,
            iterations,
        }
    }
}

pub fn generate_page_rank_r1cs(compiled: &CompiledPageRank) -> PageRankCircuit {
    assert!(compiled.num_vertices > 0, "PageRank 顶点数必须大于 0");
    assert!(compiled.iterations > 0, "PageRank 迭代次数必须大于 0");

    let num_inputs = 1 + compiled.num_vertices;
    let mut r1cs = R1CS::new(num_inputs, 0);

    let initial_rank_input_indices = (1..=compiled.num_vertices).collect::<Vec<_>>();

    let mut next_witness = 2usize;
    let zero_witness = next_witness;
    next_witness += 1;
    r1cs.add_constraint(
        Constraint {
            a: LinComb::from_var(Variable::Input(0)),
            b: LinComb::from_terms(vec![]),
            c: LinComb::from_var(Variable::Witness(zero_witness)),
        },
        zero_witness,
    );

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
    let mut total_mass_witness_indices = Vec::with_capacity(compiled.iterations);
    let mut dangling_mass_witness_indices = Vec::with_capacity(compiled.iterations);
    let mut teleport_scalar_witness_indices = Vec::with_capacity(compiled.iterations);

    for _ in 0..compiled.iterations {
        let total_mass_witness = next_witness;
        next_witness += 1;
        r1cs.add_constraint(
            Constraint {
                a: LinComb::from_var(Variable::Input(0)),
                b: witness_sum_lincomb(&current_rank_witnesses),
                c: LinComb::from_var(Variable::Witness(total_mass_witness)),
            },
            total_mass_witness,
        );
        total_mass_witness_indices.push(total_mass_witness);

        let dangling_mass_witness = if compiled.dangling_vertices.is_empty() {
            zero_witness
        } else {
            let witness_idx = next_witness;
            next_witness += 1;
            r1cs.add_constraint(
                Constraint {
                    a: LinComb::from_var(Variable::Input(0)),
                    b: witness_sum_lincomb(
                        &compiled
                            .dangling_vertices
                            .iter()
                            .map(|&vertex| current_rank_witnesses[vertex])
                            .collect::<Vec<_>>(),
                    ),
                    c: LinComb::from_var(Variable::Witness(witness_idx)),
                },
                witness_idx,
            );
            witness_idx
        };
        dangling_mass_witness_indices.push(dangling_mass_witness);

        let teleport_scalar_witness = next_witness;
        next_witness += 1;
        let mut teleport_scalar_terms = Vec::with_capacity(2);
        if !compiled.one_minus_alpha.is_zero() {
            teleport_scalar_terms.push((
                compiled.one_minus_alpha,
                Variable::Witness(total_mass_witness),
            ));
        }
        if !compiled.alpha.is_zero() {
            teleport_scalar_terms.push((compiled.alpha, Variable::Witness(dangling_mass_witness)));
        }
        r1cs.add_constraint(
            Constraint {
                a: LinComb::from_var(Variable::Input(0)),
                b: LinComb::from_terms(teleport_scalar_terms),
                c: LinComb::from_var(Variable::Witness(teleport_scalar_witness)),
            },
            teleport_scalar_witness,
        );
        teleport_scalar_witness_indices.push(teleport_scalar_witness);

        let mut scaled_source_witnesses = vec![zero_witness; compiled.num_vertices];
        for source in 0..compiled.num_vertices {
            let Some(weight) = compiled.source_weights[source] else {
                continue;
            };

            let witness_idx = next_witness;
            next_witness += 1;
            r1cs.add_constraint(
                Constraint {
                    a: LinComb::from_terms(vec![(weight, Variable::Input(0))]),
                    b: LinComb::from_var(Variable::Witness(current_rank_witnesses[source])),
                    c: LinComb::from_var(Variable::Witness(witness_idx)),
                },
                witness_idx,
            );
            scaled_source_witnesses[source] = witness_idx;
        }

        let mut next_rank_witnesses = Vec::with_capacity(compiled.num_vertices);
        for target in 0..compiled.num_vertices {
            let teleport_term_witness = next_witness;
            next_witness += 1;
            r1cs.add_constraint(
                Constraint {
                    a: LinComb::from_terms(vec![(compiled.teleport[target], Variable::Input(0))]),
                    b: LinComb::from_var(Variable::Witness(teleport_scalar_witness)),
                    c: LinComb::from_var(Variable::Witness(teleport_term_witness)),
                },
                teleport_term_witness,
            );

            let next_rank_witness = next_witness;
            next_witness += 1;
            let mut terms = compiled.incoming_sources[target]
                .iter()
                .map(|&source| {
                    (
                        Fr::one(),
                        Variable::Witness(scaled_source_witnesses[source]),
                    )
                })
                .collect::<Vec<_>>();
            terms.push((Fr::one(), Variable::Witness(teleport_term_witness)));
            terms.push((
                Fr::from((target + 1) as u64),
                Variable::Witness(zero_witness),
            ));

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
        initial_rank_input_indices,
        iteration_rank_witness_indices,
        total_mass_witness_indices,
        dangling_mass_witness_indices,
        teleport_scalar_witness_indices,
    }
}

pub fn generate_circuit(config: PageRankRunConfig) -> GeneratedPageRank {
    validate_config(&config);

    let compiled = compile_page_rank(&config);
    let circuit = generate_page_rank_r1cs(&compiled);
    let (initial_rank, initial_rank_approx) = build_uniform_rank_vector(compiled.num_vertices);
    let input_assignment =
        build_initial_rank_inputs(&circuit.initial_rank_input_indices, &initial_rank);
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
    let (optimized, eliminated) = eliminate_common_subexpressions(&transformed.r1cs);

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
    export_r1cs_bundle(&transformed.optimized, &generated.config.export_stem)
}

pub fn run() {
    run_with_args(&[]).expect("PageRank 示例失败");
}

pub fn run_with_args(args: &[String]) -> Result<(), String> {
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        return Err(usage_text().to_string());
    }

    let config = match args {
        [] => PageRankRunConfig::demo(),
        [iterations] => PageRankRunConfig::demo_with_iterations(parse_positive_usize_arg(
            "iterations",
            iterations,
        )?),
        _ => return Err(usage_text().to_string()),
    };

    run_with_config(config)
}

fn run_with_config(config: PageRankRunConfig) -> Result<(), String> {
    let generated = generate_circuit(config);
    let transformed = transform_circuit(&generated);
    let evaluation = evaluate_equivalence(&generated, &transformed);
    let export = export_circuit(&generated, &transformed)
        .map_err(|err| format!("导出 PageRank RMS 电路失败: {err}"))?;

    let google_matrix = build_google_matrix_approx(
        &generated.compiled.adjacency,
        generated.compiled.alpha_approx,
        &generated.compiled.teleport_approx,
        &generated.compiled.out_degrees,
    );

    println!("\n╔══════════════════════════════════════════════════╗");
    println!("║  PageRank 示例：稀疏传播 + dangling + teleport   ║");
    println!("╚══════════════════════════════════════════════════╝\n");

    println!("【1. 生成电路】");
    println!("  顶点数: {}", generated.compiled.num_vertices);
    println!("  迭代次数: {}", generated.compiled.iterations);
    println!(
        "  alpha = {}/{} ≈ {:.6}",
        generated.config.alpha_num, generated.config.alpha_den, generated.compiled.alpha_approx
    );
    println!(
        "  dangling 顶点: {}",
        format_vertex_list(&generated.compiled.dangling_vertices)
    );
    println!("  邻接矩阵 A:");
    print_adjacency_matrix(&generated.compiled.adjacency);
    println!("  稀疏源权重 alpha / d_i:");
    print_source_weights(
        &generated.compiled.out_degrees,
        &generated.compiled.source_weights_approx,
    );
    println!("  仅用于审计的 Google 矩阵 G（电路实际不显式展开它）:");
    print_approx_matrix("G", &google_matrix);
    println!(
        "  初始 rank r^(0): {}",
        format_approx_vector(&generated.initial_rank_approx)
    );
    generated.circuit.r1cs.print_stats();

    println!("\n【2. 电路转换】");
    transformed.transformed.r1cs.print_stats();
    println!(
        "  Choudhuri 膨胀倍数: {:.2}x",
        transformed.transformed.blowup_factor
    );
    println!("  CSE 消除重复约束:  {}", transformed.eliminated);
    println!(
        "  最终膨胀倍数:      {:.2}x",
        transformed.optimized.constraints.len() as f64
            / generated.circuit.r1cs.constraints.len() as f64
    );

    println!("\n【3. Eval 一致性】");
    println!(
        "  期望 PageRank(T): {}",
        format_approx_vector(&evaluation.expected_output_approx)
    );
    println!(
        "  输出一致: {}  [约束满足: orig={}, rms+cse={}]",
        evaluation.outputs_match, evaluation.original_valid, evaluation.transformed_valid
    );

    println!("\n【4. 电路导出】");
    println!("  JSON: {}", export.json_path);
    println!("  BIN:  {}", export.bin_path);
    println!("  版本: {}", export.version);
    println!("  约束数: {}", export.num_constraints);
    println!("  JSON/BIN 内容一致: {}", export.json_bin_match);
    println!("  前 8 条最终 RMS 约束:");
    let exported_json = load_r1cs_from_json(&export.json_path).expect("读取 JSON 导出文件失败");
    for constraint in exported_json.constraints.iter().take(8) {
        println!(
            "    step {:>2}: ({} ) * ({} ) -> w{}",
            constraint.index,
            terms_to_export_string(&constraint.a_in, "x"),
            terms_to_export_string(&constraint.b_wit, "w"),
            constraint.output_witness
        );
    }

    println!("\n【前 8 条原始约束预览】");
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
    assert!(config.iterations > 0, "PageRank 迭代次数必须大于 0");
    assert!(config.alpha_den > 0, "alpha 的分母必须大于 0");
    assert!(
        config.alpha_num < config.alpha_den,
        "当前实现要求 0 < alpha < 1"
    );
    validate_adjacency(&config.adjacency);
}

fn validate_adjacency(adjacency: &[Vec<u8>]) {
    assert!(!adjacency.is_empty(), "PageRank 图不能为空");
    let num_vertices = adjacency.len();
    for (row_idx, row) in adjacency.iter().enumerate() {
        assert_eq!(
            row.len(),
            num_vertices,
            "邻接矩阵第 {} 行长度与顶点数不一致",
            row_idx
        );
        assert!(
            row.iter().all(|&value| matches!(value, 0 | 1)),
            "邻接矩阵必须是 0/1 矩阵"
        );
    }
}

fn compile_page_rank(config: &PageRankRunConfig) -> CompiledPageRank {
    let num_vertices = config.adjacency.len();
    let alpha = fr_fraction(config.alpha_num, config.alpha_den);
    let one_minus_alpha = Fr::one() - alpha;
    let alpha_approx = config.alpha_num as f64 / config.alpha_den as f64;
    let teleport = vec![fr_fraction(1, num_vertices as u64); num_vertices];
    let teleport_approx = vec![1.0 / num_vertices as f64; num_vertices];
    let out_degrees = config
        .adjacency
        .iter()
        .map(|row| row.iter().map(|&value| usize::from(value)).sum())
        .collect::<Vec<_>>();
    let dangling_vertices = out_degrees
        .iter()
        .enumerate()
        .filter_map(|(vertex, &degree)| (degree == 0).then_some(vertex))
        .collect::<Vec<_>>();

    let mut source_weights = vec![None; num_vertices];
    let mut source_weights_approx = vec![None; num_vertices];
    for source in 0..num_vertices {
        let degree = out_degrees[source];
        if degree == 0 {
            continue;
        }
        source_weights[source] = Some(alpha * fr_inverse_u64(degree as u64));
        source_weights_approx[source] = Some(alpha_approx / degree as f64);
    }

    let mut incoming_sources = vec![Vec::new(); num_vertices];
    for source in 0..num_vertices {
        for target in 0..num_vertices {
            if config.adjacency[source][target] == 1 {
                incoming_sources[target].push(source);
            }
        }
    }

    CompiledPageRank {
        num_vertices,
        iterations: config.iterations,
        adjacency: config.adjacency.clone(),
        alpha,
        one_minus_alpha,
        alpha_approx,
        teleport,
        teleport_approx,
        out_degrees,
        dangling_vertices,
        source_weights,
        source_weights_approx,
        incoming_sources,
    }
}

fn build_uniform_rank_vector(num_vertices: usize) -> (Vec<Fr>, Vec<f64>) {
    let rank = fr_fraction(1, num_vertices as u64);
    let rank_approx = 1.0 / num_vertices as f64;
    (vec![rank; num_vertices], vec![rank_approx; num_vertices])
}

fn build_initial_rank_inputs(indices: &[usize], values: &[Fr]) -> Vec<(usize, Fr)> {
    indices
        .iter()
        .zip(values.iter())
        .map(|(&index, &value)| (index, value))
        .collect()
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
        let total_mass = current
            .iter()
            .copied()
            .fold(Fr::zero(), |acc, value| acc + value);
        let dangling_mass = compiled
            .dangling_vertices
            .iter()
            .copied()
            .map(|vertex| current[vertex])
            .fold(Fr::zero(), |acc, value| acc + value);
        let teleport_scalar =
            compiled.one_minus_alpha * total_mass + compiled.alpha * dangling_mass;

        let mut next = vec![Fr::zero(); compiled.num_vertices];
        for target in 0..compiled.num_vertices {
            for &source in &compiled.incoming_sources[target] {
                let weight =
                    compiled.source_weights[source].expect("非 dangling 顶点必须具有稀疏传播权重");
                next[target] += weight * current[source];
            }
            next[target] += compiled.teleport[target] * teleport_scalar;
        }
        current = next;
    }

    current
}

fn simulate_sparse_f64(compiled: &CompiledPageRank, initial_rank: &[f64]) -> Vec<f64> {
    let mut current = initial_rank.to_vec();

    for _ in 0..compiled.iterations {
        let total_mass = current.iter().sum::<f64>();
        let dangling_mass = compiled
            .dangling_vertices
            .iter()
            .copied()
            .map(|vertex| current[vertex])
            .sum::<f64>();
        let teleport_scalar =
            (1.0 - compiled.alpha_approx) * total_mass + compiled.alpha_approx * dangling_mass;

        let mut next = vec![0.0; compiled.num_vertices];
        for target in 0..compiled.num_vertices {
            for &source in &compiled.incoming_sources[target] {
                let weight = compiled.source_weights_approx[source]
                    .expect("非 dangling 顶点必须具有稀疏传播权重");
                next[target] += weight * current[source];
            }
            next[target] += compiled.teleport_approx[target] * teleport_scalar;
        }
        current = next;
    }

    current
}

fn build_google_matrix_approx(
    adjacency: &[Vec<u8>],
    alpha: f64,
    teleport: &[f64],
    out_degrees: &[usize],
) -> Vec<Vec<f64>> {
    let num_vertices = adjacency.len();
    let mut google = vec![vec![0.0; num_vertices]; num_vertices];

    for source in 0..num_vertices {
        if out_degrees[source] == 0 {
            google[source] = teleport.to_vec();
            continue;
        }

        let inv_degree = 1.0 / out_degrees[source] as f64;
        for target in 0..num_vertices {
            google[source][target] = (1.0 - alpha) * teleport[target]
                + alpha * f64::from(adjacency[source][target]) * inv_degree;
        }
    }

    google
}

#[cfg(test)]
fn build_google_matrix_field(compiled: &CompiledPageRank) -> Vec<Vec<Fr>> {
    let mut google = vec![vec![Fr::zero(); compiled.num_vertices]; compiled.num_vertices];

    for source in 0..compiled.num_vertices {
        if compiled.out_degrees[source] == 0 {
            google[source] = compiled.teleport.clone();
            continue;
        }

        let inv_degree = fr_inverse_u64(compiled.out_degrees[source] as u64);
        for target in 0..compiled.num_vertices {
            google[source][target] = compiled.one_minus_alpha * compiled.teleport[target]
                + compiled.alpha
                    * Fr::from(u64::from(compiled.adjacency[source][target]))
                    * inv_degree;
        }
    }

    google
}

#[cfg(test)]
fn simulate_dense_field(
    google_matrix: &[Vec<Fr>],
    initial_rank: &[Fr],
    iterations: usize,
) -> Vec<Fr> {
    let mut current = initial_rank.to_vec();
    let num_vertices = current.len();

    for _ in 0..iterations {
        let mut next = vec![Fr::zero(); num_vertices];
        for target in 0..num_vertices {
            for source in 0..num_vertices {
                next[target] += google_matrix[source][target] * current[source];
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
    for row in adjacency {
        let formatted = row
            .iter()
            .map(|value| format!("{:>2}", value))
            .collect::<Vec<_>>()
            .join(", ");
        println!("      [{}]", formatted);
    }
}

fn print_source_weights(out_degrees: &[usize], source_weights_approx: &[Option<f64>]) {
    for (source, (degree, weight)) in out_degrees
        .iter()
        .zip(source_weights_approx.iter())
        .enumerate()
    {
        match weight {
            Some(weight) => println!(
                "    v{}: out-degree={}, alpha/d_i≈{:.6}",
                source, degree, weight
            ),
            None => println!("    v{}: out-degree=0, dangling", source),
        }
    }
}

fn print_approx_matrix(name: &str, matrix: &[Vec<f64>]) {
    println!("    {} =", name);
    for row in matrix {
        println!("      {}", format_approx_vector(row));
    }
}

fn format_approx_vector(values: &[f64]) -> String {
    let formatted = values
        .iter()
        .map(|value| format!("{:>8.6}", value))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{}]", formatted)
}

fn format_vertex_list(vertices: &[usize]) -> String {
    if vertices.is_empty() {
        return "none".to_string();
    }

    vertices
        .iter()
        .map(|vertex| format!("v{}", vertex))
        .collect::<Vec<_>>()
        .join(", ")
}

fn parse_positive_usize_arg(name: &str, raw: &str) -> Result<usize, String> {
    let value = raw
        .parse::<usize>()
        .map_err(|err| format!("{name} 必须是非负整数，收到 {raw:?}: {err}"))?;
    if value == 0 {
        return Err(format!("{name} 必须大于 0"));
    }
    Ok(value)
}

fn fr_fraction(num: u64, den: u64) -> Fr {
    assert!(den > 0, "分母必须大于 0");
    Fr::from(num) * fr_inverse_u64(den)
}

fn fr_inverse_u64(value: u64) -> Fr {
    Fr::from(value).inverse().expect("分母必须在当前域中可逆")
}

fn usage_text() -> &'static str {
    "\
用法:
  cargo run -- page_rank
  cargo run -- page_rank <iterations>

说明:
  默认图: 4 个顶点，其中包含 1 个 dangling 顶点。
  默认参数: alpha=17/20, teleport=uniform, iterations=5。
  电路按稀疏传播项、dangling mass 和 teleportation 分开编译，不显式展开稠密 Google 矩阵。"
}

#[cfg(test)]
mod circuit_tests {
    use super::*;

    #[test]
    fn sparse_page_rank_matches_dense_google_matrix_semantics() {
        let config = PageRankRunConfig::demo_with_iterations(3);
        let compiled = compile_page_rank(&config);
        let (initial_rank, _) = build_uniform_rank_vector(compiled.num_vertices);
        let dense_google = build_google_matrix_field(&compiled);
        let sparse_output = simulate_sparse_field(&compiled, &initial_rank);
        let dense_output = simulate_dense_field(&dense_google, &initial_rank, compiled.iterations);

        assert_eq!(sparse_output, dense_output);
    }

    #[test]
    fn page_rank_circuit_is_rms_and_preserves_output() {
        let generated = generate_circuit(PageRankRunConfig::demo_with_iterations(3));
        let transformed = transform_circuit(&generated);

        assert!(generated
            .circuit
            .r1cs
            .constraints
            .iter()
            .all(|constraint| constraint.is_rms_compatible()));
        assert!(transformed
            .optimized
            .constraints
            .iter()
            .all(|constraint| constraint.is_rms_compatible()));

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
