#!/usr/bin/env python3
"""Analyze RMS export artifacts from `.bin` or `.json`.

Binary exports are zstd-compressed `rms-linear-v3` payloads. The analyzer keeps
the original streaming behavior: it decompresses and parses the binary format
incrementally so large artifacts do not need to be fully materialized in memory.
"""

from __future__ import annotations

import argparse
import json
import shutil
import struct
import subprocess
import sys
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Iterator


MAGIC = b"RMS3"
U32 = struct.Struct("<I")
FIELD_BYTES = 32

PRIVATE_INPUTS_EXPLICIT = 0
PRIVATE_INPUTS_RANGE = 1
PRIVATE_INPUTS_BITSET = 2

EXECUTION_ORDER_SEQUENTIAL = 0
EXECUTION_ORDER_EXPLICIT = 1

CONSTRAINT_INDEX_SEQUENTIAL = 0
CONSTRAINT_INDEX_EXPLICIT = 1


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

    def read_u8(self) -> int:
        return self.read_exact(1)[0]

    def read_u32(self) -> int:
        return U32.unpack(self.read_exact(U32.size))[0]

    def read_field_is_nonzero(self) -> bool:
        return any(self.read_exact(FIELD_BYTES))


@contextmanager
def open_zstd_stream(path: Path) -> Iterator[BinaryIO]:
    try:
        import zstandard as zstd  # type: ignore
    except ImportError:
        zstd_bin = shutil.which("zstd")
        if zstd_bin is None:
            raise DecodeError(
                "zstd support unavailable; install python-zstandard or make the `zstd` CLI available"
            )

        process = subprocess.Popen(
            [zstd_bin, "-d", "-q", "-c", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert process.stdout is not None
        assert process.stderr is not None
        try:
            yield process.stdout
        finally:
            process.stdout.close()
            stderr = process.stderr.read().decode("utf-8", errors="replace").strip()
            process.stderr.close()
            return_code = process.wait()
            if return_code != 0:
                raise DecodeError(stderr or f"zstd exited with status {return_code}")
    else:
        with path.open("rb") as compressed:
            decompressor = zstd.ZstdDecompressor()
            with decompressor.stream_reader(compressed) as stream:
                yield stream


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
    private_inputs_encoding: str
    execution_order_encoding: str
    constraint_index_encoding: str
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
            "encodings": {
                "private_inputs": self.private_inputs_encoding,
                "execution_order": self.execution_order_encoding,
                "constraint_indices": self.constraint_index_encoding,
            },
            **self.constraint_stats.as_dict(),
        }


def read_term(reader: BinReader) -> tuple[int, bool]:
    index = reader.read_u32()
    nonzero = reader.read_field_is_nonzero()
    return index, nonzero


def skip_term_vec(reader: BinReader) -> tuple[set[int], int]:
    count = reader.read_u32()
    active_indices: set[int] = set()
    width = 0
    for _ in range(count):
        index, nonzero = read_term(reader)
        if nonzero:
            active_indices.add(index)
            width += 1
    return active_indices, width


def read_private_inputs(
    reader: BinReader, layout: int, count: int, num_inputs: int
) -> tuple[list[int], str]:
    if layout == PRIVATE_INPUTS_EXPLICIT:
        return [reader.read_u32() for _ in range(count)], "explicit"

    if layout == PRIVATE_INPUTS_RANGE:
        if count == 0:
            return [], "range"
        start = reader.read_u32()
        return list(range(start, start + count)), "range"

    if layout == PRIVATE_INPUTS_BITSET:
        bitset = reader.read_exact((num_inputs + 7) // 8)
        indices = [
            index
            for index in range(num_inputs)
            if (bitset[index // 8] >> (index % 8)) & 1 == 1
        ]
        return indices, "bitset"

    raise DecodeError(f"unsupported private input encoding tag {layout}")


def summarize_v3_bin(path: Path) -> ExportSummary:
    with open_zstd_stream(path) as fh:
        reader = BinReader(fh)
        magic = reader.read_exact(len(MAGIC))
        if magic != MAGIC:
            raise DecodeError(f"unexpected RMS binary magic {magic!r}")

        num_inputs = reader.read_u32()
        num_witnesses = reader.read_u32()

        public_inputs_len = reader.read_u32()
        public_input_slots = []
        for _ in range(public_inputs_len):
            public_input_slots.append(reader.read_u32())
            reader.read_exact(FIELD_BYTES)

        private_layout = reader.read_u8()
        num_private_inputs = reader.read_u32()
        private_input_slots, private_encoding = read_private_inputs(
            reader, private_layout, num_private_inputs, num_inputs
        )

        output_witnesses_len = reader.read_u32()
        for _ in range(output_witnesses_len):
            reader.read_u32()

        constraint_count = reader.read_u32()

        execution_layout = reader.read_u8()
        if execution_layout == EXECUTION_ORDER_SEQUENTIAL:
            execution_order_len = constraint_count
            execution_encoding = "sequential"
        elif execution_layout == EXECUTION_ORDER_EXPLICIT:
            execution_order_len = reader.read_u32()
            for _ in range(execution_order_len):
                reader.read_u32()
            execution_encoding = "explicit"
        else:
            raise DecodeError(f"unsupported execution order encoding tag {execution_layout}")

        constraint_index_layout = reader.read_u8()
        if constraint_index_layout == CONSTRAINT_INDEX_SEQUENTIAL:
            constraint_index_encoding = "implicit-sequential"
        elif constraint_index_layout == CONSTRAINT_INDEX_EXPLICIT:
            constraint_index_encoding = "explicit"
        else:
            raise DecodeError(
                f"unsupported constraint index encoding tag {constraint_index_layout}"
            )

        stats = ConstraintStats()
        public_input_set = set(public_input_slots)
        private_input_set = set(private_input_slots)

        for constraint_index in range(constraint_count):
            if constraint_index_layout == CONSTRAINT_INDEX_EXPLICIT:
                _ = reader.read_u32()
            else:
                _ = constraint_index

            a_indices, _ = skip_term_vec(reader)
            _, b_width = skip_term_vec(reader)
            _ = reader.read_u32()
            stats.ingest_constraint(a_indices, b_width, public_input_set, private_input_set)

        if num_private_inputs != len(private_input_slots):
            raise DecodeError(
                f"header/private_inputs mismatch: {num_private_inputs} != {len(private_input_slots)}"
            )

        return ExportSummary(
            path=str(path),
            version="rms-linear-v3",
            num_inputs=num_inputs,
            num_public_inputs=len(public_input_slots),
            num_private_inputs=len(private_input_slots),
            public_input_slots=public_input_slots,
            private_input_slots=private_input_slots,
            num_witnesses=num_witnesses,
            execution_order_len=execution_order_len,
            private_inputs_encoding=private_encoding,
            execution_order_encoding=execution_encoding,
            constraint_index_encoding=constraint_index_encoding,
            constraint_stats=stats,
        )


def summarize_json_export(path: Path) -> ExportSummary:
    with path.open() as fh:
        data = json.load(fh)

    version = data["version"]
    if version != "rms-linear-v3":
        raise DecodeError(f"unsupported JSON export version {version!r}")

    num_inputs = int(data["num_inputs"])
    public_input_slots = [int(item["index"]) for item in data.get("public_inputs", [])]
    private_input_slots = [int(index) for index in data.get("private_inputs", [])]
    num_public_inputs = int(data.get("num_public_inputs", len(public_input_slots)))
    num_private_inputs = int(data.get("num_private_inputs", len(private_input_slots)))
    num_witnesses = int(data["num_witnesses"])
    execution_order = data.get("execution_order", [])

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
        execution_order_len=len(execution_order),
        private_inputs_encoding="json-list",
        execution_order_encoding="json-list",
        constraint_index_encoding="json-inline",
        constraint_stats=stats,
    )


def summarize_export(path: Path) -> ExportSummary:
    if path.suffix == ".json":
        return summarize_json_export(path)
    return summarize_v3_bin(path)


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
    print("Encodings")
    print(f"  private inputs:           {summary.private_inputs_encoding}")
    print(f"  execution order:          {summary.execution_order_encoding}")
    print(f"  constraint indices:       {summary.constraint_index_encoding}")
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
