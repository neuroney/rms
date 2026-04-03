#!/usr/bin/env python3
"""Analyze RMS export artifacts from `.bin` or `.json`.

The current repository exports `RmsLinearExport` with `bincode` v1.3 using
fixed-width little-endian integers on 64-bit targets. This script parses the
export in a streaming way so large `.bin` files do not need to be fully loaded
into memory.
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO


U64 = struct.Struct("<Q")


class DecodeError(RuntimeError):
    pass


class BinReader:
    def __init__(self, fh: BinaryIO) -> None:
        self.fh = fh

    def read_exact(self, size: int) -> bytes:
        data = self.fh.read(size)
        if len(data) != size:
            raise DecodeError(f"unexpected EOF while reading {size} bytes")
        return data

    def read_u64(self) -> int:
        return U64.unpack(self.read_exact(U64.size))[0]

    def read_string(self) -> str:
        size = self.read_u64()
        return self.read_exact(size).decode("utf-8")

    def skip_usize_vec(self) -> int:
        count = self.read_u64()
        for _ in range(count):
            self.read_u64()
        return count


@dataclass
class ConstraintStats:
    total_constraints: int = 0
    constant_only: int = 0
    public_only: int = 0
    private_only: int = 0
    mixed_inputs: int = 0
    empty_input: int = 0
    total_a_terms: int = 0
    total_b_terms: int = 0
    max_a_terms: int = 0
    max_b_terms: int = 0
    unknown_input_constraints: int = 0
    unknown_input_slots: set[int] = field(default_factory=set)

    def ingest_constraint(
        self,
        a_indices: set[int],
        b_width: int,
        public_inputs: set[int],
        private_inputs: set[int],
    ) -> None:
        self.total_constraints += 1
        self.total_a_terms += len(a_indices)
        self.total_b_terms += b_width
        self.max_a_terms = max(self.max_a_terms, len(a_indices))
        self.max_b_terms = max(self.max_b_terms, b_width)

        if not a_indices:
            self.empty_input += 1
            return

        unknown = a_indices - public_inputs - private_inputs
        if unknown:
            self.unknown_input_constraints += 1
            self.unknown_input_slots.update(unknown)

        all_public = a_indices.issubset(public_inputs)
        all_private = a_indices.issubset(private_inputs)

        if all_public and a_indices == {0}:
            self.constant_only += 1
        elif all_public:
            self.public_only += 1
        elif all_private:
            self.private_only += 1
        else:
            self.mixed_inputs += 1

    def as_dict(self) -> dict:
        avg_a = self.total_a_terms / self.total_constraints if self.total_constraints else 0.0
        avg_b = self.total_b_terms / self.total_constraints if self.total_constraints else 0.0
        return {
            "total_constraints": self.total_constraints,
            "constraint_classes": {
                "constant_x0_times_memory": self.constant_only,
                "public_only_times_memory": self.public_only,
                "private_only_times_memory": self.private_only,
                "mixed_input_times_memory": self.mixed_inputs,
                "empty_input_times_memory": self.empty_input,
            },
            "fanin": {
                "avg_input_terms": avg_a,
                "avg_memory_terms": avg_b,
                "max_input_terms": self.max_a_terms,
                "max_memory_terms": self.max_b_terms,
            },
            "unknown_input_constraints": self.unknown_input_constraints,
            "unknown_input_slots": sorted(self.unknown_input_slots),
        }


@dataclass
class ExportSummary:
    path: str
    version: str
    num_inputs: int
    num_public_inputs: int
    num_private_inputs: int
    public_input_slots: list[int]
    private_input_slots: list[int]
    num_witnesses: int
    execution_order_len: int
    constraint_stats: ConstraintStats

    @property
    def external_public_inputs(self) -> int:
        return self.num_public_inputs - (1 if 0 in self.public_input_slots else 0)

    def as_dict(self) -> dict:
        return {
            "path": self.path,
            "version": self.version,
            "inputs": {
                "total_input_slots": self.num_inputs,
                "public_inputs_including_x0": self.num_public_inputs,
                "external_public_inputs": self.external_public_inputs,
                "private_inputs": self.num_private_inputs,
                "public_input_slots": self.public_input_slots,
                "private_input_slots": self.private_input_slots,
            },
            "witnesses": self.num_witnesses,
            "execution_order_len": self.execution_order_len,
            **self.constraint_stats.as_dict(),
        }


def read_term(reader: BinReader) -> tuple[int, str]:
    index = reader.read_u64()
    coeff = reader.read_string()
    return index, coeff


def skip_term_vec(reader: BinReader) -> tuple[set[int], int]:
    count = reader.read_u64()
    active_indices: set[int] = set()
    width = 0
    for _ in range(count):
        index, coeff = read_term(reader)
        if coeff != "0":
            active_indices.add(index)
            width += 1
    return active_indices, width


def summarize_v2_bin(path: Path) -> ExportSummary:
    with path.open("rb") as fh:
        reader = BinReader(fh)
        version = reader.read_string()
        if version != "rms-linear-v2":
            raise DecodeError(f"unsupported RMS version {version!r}")

        num_inputs = reader.read_u64()
        num_public_inputs = reader.read_u64()
        num_private_inputs = reader.read_u64()

        public_inputs_len = reader.read_u64()
        public_input_slots: list[int] = []
        for _ in range(public_inputs_len):
            index = reader.read_u64()
            _ = reader.read_string()
            public_input_slots.append(index)

        private_inputs_len = reader.read_u64()
        private_input_slots = [reader.read_u64() for _ in range(private_inputs_len)]

        num_witnesses = reader.read_u64()
        execution_order_len = reader.skip_usize_vec()
        constraint_count = reader.read_u64()

        stats = ConstraintStats()
        public_input_set = set(public_input_slots)
        private_input_set = set(private_input_slots)

        for _ in range(constraint_count):
            _ = reader.read_u64()  # constraint index
            a_indices, _ = skip_term_vec(reader)
            _, b_width = skip_term_vec(reader)
            _ = reader.read_u64()  # output witness
            stats.ingest_constraint(a_indices, b_width, public_input_set, private_input_set)

        if num_public_inputs != len(public_input_slots):
            raise DecodeError(
                f"header/public_inputs mismatch: {num_public_inputs} != {len(public_input_slots)}"
            )
        if num_private_inputs != len(private_input_slots):
            raise DecodeError(
                f"header/private_inputs mismatch: {num_private_inputs} != {len(private_input_slots)}"
            )

        return ExportSummary(
            path=str(path),
            version=version,
            num_inputs=num_inputs,
            num_public_inputs=num_public_inputs,
            num_private_inputs=num_private_inputs,
            public_input_slots=public_input_slots,
            private_input_slots=private_input_slots,
            num_witnesses=num_witnesses,
            execution_order_len=execution_order_len,
            constraint_stats=stats,
        )


def summarize_v1_bin(path: Path) -> ExportSummary:
    with path.open("rb") as fh:
        reader = BinReader(fh)
        version = reader.read_string()
        num_inputs = reader.read_u64()
        num_witnesses = reader.read_u64()
        execution_order_len = reader.skip_usize_vec()
        constraint_count = reader.read_u64()

        public_input_slots = [0] if num_inputs > 0 else []
        private_input_slots = list(range(1, num_inputs))
        public_input_set = set(public_input_slots)
        private_input_set = set(private_input_slots)

        stats = ConstraintStats()
        for _ in range(constraint_count):
            _ = reader.read_u64()  # constraint index
            a_indices, _ = skip_term_vec(reader)
            _, b_width = skip_term_vec(reader)
            _ = reader.read_u64()  # output witness
            stats.ingest_constraint(a_indices, b_width, public_input_set, private_input_set)

        return ExportSummary(
            path=str(path),
            version=version,
            num_inputs=num_inputs,
            num_public_inputs=len(public_input_slots),
            num_private_inputs=len(private_input_slots),
            public_input_slots=public_input_slots,
            private_input_slots=private_input_slots,
            num_witnesses=num_witnesses,
            execution_order_len=execution_order_len,
            constraint_stats=stats,
        )


def summarize_json_export(path: Path) -> ExportSummary:
    with path.open() as fh:
        data = json.load(fh)

    version = data["version"]
    num_inputs = int(data["num_inputs"])

    if version == "rms-linear-v2":
        public_input_slots = [int(item["index"]) for item in data.get("public_inputs", [])]
        private_input_slots = [int(index) for index in data.get("private_inputs", [])]
        num_public_inputs = int(data.get("num_public_inputs", len(public_input_slots)))
        num_private_inputs = int(data.get("num_private_inputs", len(private_input_slots)))
        num_witnesses = int(data["num_witnesses"])
        execution_order_len = len(data.get("execution_order", []))
    else:
        public_input_slots = [0] if num_inputs > 0 else []
        private_input_slots = list(range(1, num_inputs))
        num_public_inputs = len(public_input_slots)
        num_private_inputs = len(private_input_slots)
        num_witnesses = int(data["num_witnesses"])
        execution_order_len = len(data.get("execution_order", []))

    public_input_set = set(public_input_slots)
    private_input_set = set(private_input_slots)
    stats = ConstraintStats()

    for constraint in data["constraints"]:
        a_indices = {
            int(term["index"])
            for term in constraint.get("a_in", [])
            if term.get("coeff") != "0"
        }
        b_width = sum(1 for term in constraint.get("b_wit", []) if term.get("coeff") != "0")
        stats.ingest_constraint(a_indices, b_width, public_input_set, private_input_set)

    return ExportSummary(
        path=str(path),
        version=version,
        num_inputs=num_inputs,
        num_public_inputs=num_public_inputs,
        num_private_inputs=num_private_inputs,
        public_input_slots=public_input_slots,
        private_input_slots=private_input_slots,
        num_witnesses=num_witnesses,
        execution_order_len=execution_order_len,
        constraint_stats=stats,
    )


def summarize_export(path: Path) -> ExportSummary:
    if path.suffix == ".json":
        return summarize_json_export(path)

    with path.open("rb") as fh:
        reader = BinReader(fh)
        version = reader.read_string()

    if version == "rms-linear-v2":
        return summarize_v2_bin(path)

    return summarize_v1_bin(path)


def format_percent(count: int, total: int) -> str:
    if total == 0:
        return "0.00%"
    return f"{count / total * 100:.2f}%"


def print_human_summary(summary: ExportSummary) -> None:
    stats = summary.constraint_stats
    total = stats.total_constraints

    print(f"File: {summary.path}")
    print(f"Version: {summary.version}")
    print()
    print("Inputs")
    print(f"  public inputs (incl. x0): {summary.num_public_inputs}")
    print(f"  external public inputs:   {summary.external_public_inputs}")
    print(f"  private inputs:           {summary.num_private_inputs}")
    print(f"  total input slots:        {summary.num_inputs}")
    print()
    print("Circuit")
    print(f"  witnesses:                {summary.num_witnesses}")
    print(f"  execution order len:      {summary.execution_order_len}")
    print(f"  total constraints:        {total}")
    print()
    print("Constraint Classes (input side × memory side)")
    print(
        f"  constant(x0) * memory:    {stats.constant_only} ({format_percent(stats.constant_only, total)})"
    )
    print(
        f"  public-only * memory:     {stats.public_only} ({format_percent(stats.public_only, total)})"
    )
    print(
        f"  private-only * memory:    {stats.private_only} ({format_percent(stats.private_only, total)})"
    )
    print(
        f"  mixed-input * memory:     {stats.mixed_inputs} ({format_percent(stats.mixed_inputs, total)})"
    )
    if stats.empty_input:
        print(
            f"  empty-input * memory:     {stats.empty_input} ({format_percent(stats.empty_input, total)})"
        )
    print()
    print("Fan-In")
    if total == 0:
        print("  avg input terms:          0.00")
        print("  avg memory terms:         0.00")
    else:
        print(f"  avg input terms:          {stats.total_a_terms / total:.2f}")
        print(f"  avg memory terms:         {stats.total_b_terms / total:.2f}")
    print(f"  max input terms:          {stats.max_a_terms}")
    print(f"  max memory terms:         {stats.max_b_terms}")

    if stats.unknown_input_constraints:
        print()
        print("Warnings")
        print(f"  constraints with unknown input slots: {stats.unknown_input_constraints}")
        print(f"  unknown input slots: {sorted(stats.unknown_input_slots)}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze RMS export artifacts and summarize input/memory gate structure."
    )
    parser.add_argument("artifact", help="Path to an RMS export `.bin` or `.json` file")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the summary as JSON instead of human-readable text",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    path = Path(args.artifact)
    if not path.exists():
        print(f"error: file not found: {path}", file=sys.stderr)
        return 1

    try:
        summary = summarize_export(path)
    except (DecodeError, OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        print(f"error: failed to analyze {path}: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(summary.as_dict(), indent=2, sort_keys=True))
    else:
        print_human_summary(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
