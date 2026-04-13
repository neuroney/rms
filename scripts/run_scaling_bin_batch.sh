#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PROFILE="release"
SKIP_EXISTING=0
DRY_RUN=0
ONLY_CSV=""

MVPOLY_NUM_VARS=5

usage() {
    cat <<'EOF'
Usage:
  scripts/run_scaling_bin_batch.sh [--release|--debug] [--skip-existing] [--dry-run] [--only LIST]

Options:
  --release         Build and run the release binary (default).
  --debug           Build and run the debug binary.
  --skip-existing   Skip a case when a matching .bin already exists for its export stem.
  --dry-run         Print the commands without executing them.
  --only LIST       Comma-separated benchmark filter.
                    Supported names: mvpoly, polyev, fixmat, twomat, gt, pir, mimc7
  -h, --help        Show this help message.

Examples:
  scripts/run_scaling_bin_batch.sh
  scripts/run_scaling_bin_batch.sh --debug --only mvpoly,gt,mimc7
  scripts/run_scaling_bin_batch.sh --skip-existing --only fixmat,twomat,pir
EOF
}

normalize_name() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr '-' '_'
}

matches_only_filter() {
    local benchmark
    local token
    local normalized_token

    benchmark="$(normalize_name "$1")"
    if [[ -z "$ONLY_CSV" ]]; then
        return 0
    fi

    IFS=',' read -r -a ONLY_ITEMS <<< "$ONLY_CSV"
    for token in "${ONLY_ITEMS[@]}"; do
        normalized_token="$(normalize_name "${token// /}")"
        case "$benchmark" in
            mvpoly)
                [[ "$normalized_token" == "mvpoly" || "$normalized_token" == "polyev" || "$normalized_token" == "poly" ]] && return 0
                ;;
            fixmat)
                [[ "$normalized_token" == "fixmat" || "$normalized_token" == "fix_mat" ]] && return 0
                ;;
            twomat)
                [[ "$normalized_token" == "twomat" || "$normalized_token" == "two_mat" ]] && return 0
                ;;
            gt)
                [[ "$normalized_token" == "gt" || "$normalized_token" == "greater_than" || "$normalized_token" == "greaterthan" ]] && return 0
                ;;
            pir)
                [[ "$normalized_token" == "pir" ]] && return 0
                ;;
            mimc7)
                [[ "$normalized_token" == "mimc7" || "$normalized_token" == "mimc" ]] && return 0
                ;;
        esac
    done

    return 1
}

latest_artifact_for_stem() {
    local stem="$1"
    local suffix="$2"
    local matches=()

    shopt -s nullglob
    matches=( "${stem}"_c*."${suffix}" )
    shopt -u nullglob

    if [[ "${#matches[@]}" -eq 0 ]]; then
        return 1
    fi

    ls -1t "${matches[@]}" | head -n 1
}

join_command() {
    local out=""
    local arg

    for arg in "$@"; do
        if [[ -n "$out" ]]; then
            out+=" "
        fi
        out+="$(printf '%q' "$arg")"
    done

    printf '%s\n' "$out"
}

append_manifest_row() {
    local manifest_path="$1"
    local benchmark="$2"
    local parameter_name="$3"
    local parameter_value="$4"
    local status="$5"
    local command_string="$6"
    local bin_path="$7"
    local json_path="$8"

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$benchmark" \
        "$parameter_name" \
        "$parameter_value" \
        "$PROFILE" \
        "$status" \
        "$command_string" \
        "$bin_path" \
        "$json_path" >> "$manifest_path"
}

run_case() {
    local manifest_path="$1"
    local benchmark="$2"
    local parameter_name="$3"
    local parameter_value="$4"
    local export_stem="$5"
    shift 5

    local command=( "$BINARY_PATH" "$@" )
    local command_string
    local bin_path=""
    local json_path=""

    if ! matches_only_filter "$benchmark"; then
        return 0
    fi

    command_string="$(join_command "${command[@]}")"

    if [[ "$SKIP_EXISTING" -eq 1 ]]; then
        bin_path="$(latest_artifact_for_stem "$export_stem" "bin" || true)"
        json_path="$(latest_artifact_for_stem "$export_stem" "json" || true)"
        if [[ -n "$bin_path" ]]; then
            printf '[skip] %s %s=%s -> %s\n' "$benchmark" "$parameter_name" "$parameter_value" "$bin_path"
            append_manifest_row "$manifest_path" "$benchmark" "$parameter_name" "$parameter_value" "skipped_existing" "$command_string" "$bin_path" "$json_path"
            return 0
        fi
    fi

    printf '[run ] %s %s=%s\n' "$benchmark" "$parameter_name" "$parameter_value"
    printf '       %s\n' "$command_string"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        append_manifest_row "$manifest_path" "$benchmark" "$parameter_name" "$parameter_value" "dry_run" "$command_string" "" ""
        return 0
    fi

    "${command[@]}"

    bin_path="$(latest_artifact_for_stem "$export_stem" "bin" || true)"
    json_path="$(latest_artifact_for_stem "$export_stem" "json" || true)"

    if [[ -z "$bin_path" ]]; then
        printf '[fail] %s %s=%s: expected %s_c*.bin was not produced\n' "$benchmark" "$parameter_name" "$parameter_value" "$export_stem" >&2
        exit 1
    fi

    printf '[done] %s\n' "$bin_path"
    append_manifest_row "$manifest_path" "$benchmark" "$parameter_name" "$parameter_value" "generated" "$command_string" "$bin_path" "$json_path"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --release)
            PROFILE="release"
            ;;
        --debug)
            PROFILE="debug"
            ;;
        --skip-existing)
            SKIP_EXISTING=1
            ;;
        --dry-run)
            DRY_RUN=1
            ;;
        --only)
            if [[ $# -lt 2 ]]; then
                echo "missing value for --only" >&2
                exit 1
            fi
            ONLY_CSV="$2"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
    shift
done

cd "$REPO_ROOT"
mkdir -p data

if [[ "$PROFILE" == "release" ]]; then
    BINARY_PATH="${REPO_ROOT}/target/release/rmsgen"
    BUILD_COMMAND=( cargo build --release )
else
    BINARY_PATH="${REPO_ROOT}/target/debug/rmsgen"
    BUILD_COMMAND=( cargo build )
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
    MANIFEST_PATH="/dev/null"
else
    MANIFEST_PATH="${REPO_ROOT}/data/scaling_bins_manifest_${PROFILE}.tsv"
    printf 'benchmark\tparameter_name\tparameter_value\tprofile\tstatus\tcommand\tbin_path\tjson_path\n' > "$MANIFEST_PATH"
fi

if [[ "$DRY_RUN" -eq 0 ]]; then
    printf '[build] %s\n' "$(join_command "${BUILD_COMMAND[@]}")"
    "${BUILD_COMMAND[@]}"
else
    printf '[dry ] %s\n' "$(join_command "${BUILD_COMMAND[@]}")"
fi

for degree in 6 7 8 9 10; do
    run_case "$MANIFEST_PATH" "mvpoly" "degree" "$degree" \
        "data/polyev_n${MVPOLY_NUM_VARS}_d${degree}" \
        polyev "$MVPOLY_NUM_VARS" "$degree"
done

for n in 200 400 600 800 1000; do
    run_case "$MANIFEST_PATH" "fixmat" "matrix_size" "$n" \
        "data/fix_mat_${n}x${n}" \
        fixmat "$n"
done

for n in 10 20 30 40 50; do
    run_case "$MANIFEST_PATH" "twomat" "matrix_size" "$n" \
        "data/two_mat_${n}x${n}" \
        twomat "$n"
done

for bits in 16 32 64 128 256; do
    run_case "$MANIFEST_PATH" "gt" "bit_length" "$bits" \
        "data/greater_than_${bits}bit" \
        greater_than "$bits"
done

for exponent in 8 10 12 14 16; do
    run_case "$MANIFEST_PATH" "pir" "database_size" "2^${exponent}" \
        "data/pir_db_n$((1 << exponent))" \
        pir "$exponent"
done

for rounds in 2 3 4 5 6; do
    run_case "$MANIFEST_PATH" "mimc7" "round_count" "$rounds" \
        "data/mimc7_r${rounds}" \
        mimc7 "$rounds"
done

if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '[ok  ] dry-run completed\n'
else
    printf '[ok  ] manifest written to %s\n' "$MANIFEST_PATH"
fi
