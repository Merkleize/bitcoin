#!/usr/bin/env python3
"""Parse filtered CCV logs into a compact JSON summary per raw transaction."""

from __future__ import annotations

import argparse
import json
import re
from collections import OrderedDict
from pathlib import Path

NODE_RE = re.compile(
    r"^\s*(?P<source>\S+)\s+"
    r"(?P<timestamp>\S+)\s+"
    r"\[(?P<thread>[^\]]+)\]\s+"
    r"\[(?P<location>[^\]]+)\]\s+"
    r"\[(?P<function>[^\]]+)\]\s+"
    r"(?P<event>OP_CHECKCONTRACTVERIFY)\s+"
    r"txid=(?P<txid>[0-9a-f]{64})\s+"
    r"input=(?P<input>\d+)\s+"
    r"data=(?P<data>.*?)\s+"
    r"index=(?P<index>.*?)\s+"
    r"pk=(?P<pk>.*?)\s+"
    r"taptree=(?P<taptree>.*?)\s+"
    r"flags=(?P<flags>.*?)"
    r"(?:\s+rawtx=(?P<rawtx>[0-9a-f]*))?\s*$"
)

BROADCAST_RE = re.compile(
    r"^\s*(?P<source>\S+)\s+"
    r"(?P<timestamp>\S+)\s+"
    r"TestFramework\s+\((?P<level>[A-Z]+)\):\s+"
    r"(?P<event>Broadcast)\s+"
    r"txid=(?P<txid>[0-9a-f]{64})\s+"
    r"success=(?P<success>True|False)"
    r"(?:\s+prevouts=(?P<prevouts>\[.*?\]))?"
    r"(?:\s+rawtx=(?P<rawtx>[0-9a-f]+))?"
    r'(?:\s+error="(?P<error>.*)")?\s*$'
)

PREVOUT_TUPLE_RE = re.compile(
    r'\((?P<nvalue>-?\d+), "(?P<script_pubkey>[0-9a-f]*)"\)'
)


def optional_text(value: str) -> str | None:
    return value if value else None


def compact_text(value: str | None) -> str:
    return value if value is not None else ""


def parse_prevouts(prevouts_text: str | None) -> list[tuple[int, str]]:
    if not prevouts_text:
        return []

    stripped = prevouts_text.strip()
    if stripped == "[]":
        return []
    if not (stripped.startswith("[") and stripped.endswith("]")):
        raise ValueError(f"Invalid prevouts list: {prevouts_text}")

    inner = stripped[1:-1].strip()
    if not inner:
        return []

    prevouts = []
    position = 0
    while position < len(inner):
        match = PREVOUT_TUPLE_RE.match(inner, position)
        if match is None:
            raise ValueError(f"Invalid prevout entry: {inner[position:]}")

        prevouts.append((
            int(match.group("nvalue")),
            match.group("script_pubkey"),
        ))

        position = match.end()
        if position == len(inner):
            break
        if inner.startswith(", ", position):
            position += 2
            continue
        raise ValueError(f"Invalid prevout separator in: {prevouts_text}")

    return prevouts


def parse_node_line(line: str) -> dict[str, object] | None:
    match = NODE_RE.match(line)
    if not match:
        return None

    details = match.groupdict()
    return {
        "line_type": "node_ccv_execution",
        "txid": details["txid"],
        "ccv_execution": {
            "input_index": int(details["input"]),
            "data": compact_text(optional_text(details["data"])),
            "index": compact_text(optional_text(details["index"])),
            "pk": compact_text(optional_text(details["pk"])),
            "taptree": compact_text(optional_text(details["taptree"])),
            "flags": compact_text(optional_text(details["flags"])),
        },
        "rawtx": compact_text(optional_text(details["rawtx"] or "")),
    }


def parse_broadcast_line(line: str) -> dict[str, object] | None:
    match = BROADCAST_RE.match(line)
    if not match:
        return None

    details = match.groupdict()
    return {
        "line_type": "test_broadcast",
        "txid": details["txid"],
        "success": details["success"] == "True",
        "prevouts": parse_prevouts(details["prevouts"]),
        "rawtx": compact_text(optional_text(details["rawtx"] or "")),
        "error": compact_text(optional_text(details["error"] or "")),
    }

def transaction_key(txid: str, rawtx: str) -> str:
    # Segwit transactions can share a txid while differing in witness data.
    return f"rawtx:{rawtx}" if rawtx else f"txid:{txid}"


def ccv_execution_key(ccv_execution: dict[str, object]) -> tuple[object, ...]:
    return (
        ccv_execution["input_index"],
        ccv_execution["data"],
        ccv_execution["index"],
        ccv_execution["pk"],
        ccv_execution["taptree"],
        ccv_execution["flags"],
    )


def normalize_broadcast_error(error: str) -> str | None:
    if not error:
        return None
    return error.split(",", 1)[0]


def new_transaction_entry(txid: str, rawtx: str = "") -> dict[str, object]:
    return {
        "txid": txid,
        "rawtx": rawtx,
        "prevouts": [],
        "ccv_executions": [],
        "_broadcast_error": None,
    }


def replace_transaction_key(
    transactions: OrderedDict[str, dict[str, object]],
    old_key: str,
    new_key: str,
) -> None:
    if old_key == new_key:
        return

    updated: OrderedDict[str, dict[str, object]] = OrderedDict()
    for key, value in transactions.items():
        updated[new_key if key == old_key else key] = value
    transactions.clear()
    transactions.update(updated)


def get_transaction_entry(
    transactions: OrderedDict[str, dict[str, object]],
    transaction_keys_by_txid: dict[str, list[str]],
    record: dict[str, object],
) -> dict[str, object]:
    txid = str(record["txid"])
    rawtx = str(record["rawtx"])
    known_keys = transaction_keys_by_txid.setdefault(txid, [])
    fallback_key = transaction_key(txid, "")

    if rawtx:
        rawtx_key = transaction_key(txid, rawtx)
        entry = transactions.get(rawtx_key)
        if entry is not None:
            return entry

        # Preserve older rawtx-less records when there is still only one
        # possible transaction for this txid.
        if known_keys == [fallback_key]:
            entry = transactions[fallback_key]
            replace_transaction_key(transactions, fallback_key, rawtx_key)
            known_keys[0] = rawtx_key
            return entry

        entry = new_transaction_entry(txid, rawtx)
        transactions[rawtx_key] = entry
        if rawtx_key not in known_keys:
            known_keys.append(rawtx_key)
        return entry

    if len(known_keys) == 1:
        return transactions[known_keys[0]]

    entry = transactions.get(fallback_key)
    if entry is None:
        entry = new_transaction_entry(txid)
        transactions[fallback_key] = entry
        if fallback_key not in known_keys:
            known_keys.append(fallback_key)
    return entry


def update_transaction(entry: dict[str, object], record: dict[str, object]) -> None:
    txid = str(record["txid"])
    if str(entry["txid"]) != txid:
        raise ValueError(f"Conflicting txid values for rawtx={entry['rawtx']}")

    rawtx = str(record["rawtx"])
    if rawtx:
        existing_rawtx = str(entry["rawtx"])
        if existing_rawtx and existing_rawtx != rawtx:
            raise ValueError(f"Conflicting rawtx values for rawtx={existing_rawtx}")
        entry["rawtx"] = rawtx

    record_prevouts = list(record.get("prevouts", []))
    if record_prevouts:
        existing_prevouts = list(entry["prevouts"])
        if existing_prevouts and existing_prevouts != record_prevouts:
            raise ValueError(f"Conflicting prevouts values for rawtx={entry['rawtx']}")
        entry["prevouts"] = record_prevouts

    if record["line_type"] == "node_ccv_execution":
        entry["ccv_executions"].append(record["ccv_execution"])
        return

    entry["_broadcast_error"] = None if bool(record["success"]) else normalize_broadcast_error(
        str(record["error"])
    )


def finalize_transactions(transactions: OrderedDict[str, dict[str, object]]) -> list[dict[str, object]]:
    result = []
    for entry in transactions.values():
        unique_ccv_executions = []
        seen_ccv_execution_keys = set()
        for ccv_execution in entry["ccv_executions"]:
            key = ccv_execution_key(ccv_execution)
            if key in seen_ccv_execution_keys:
                continue
            seen_ccv_execution_keys.add(key)
            unique_ccv_executions.append(ccv_execution)

        if not unique_ccv_executions:
            continue

        result.append({
            "txid": entry["txid"],
            "rawtx": entry["rawtx"],
            "prevouts": entry["prevouts"],
            "ccv_executions": unique_ccv_executions,
            "broadcast_error": entry["_broadcast_error"],
        })
    return result


def parse_log(path: Path) -> list[dict[str, object]]:
    transactions: OrderedDict[str, dict[str, object]] = OrderedDict()
    transaction_keys_by_txid: dict[str, list[str]] = {}
    unparsed_lines: list[dict[str, object]] = []

    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw_line.strip():
            continue

        record = parse_node_line(raw_line)
        if record is None:
            record = parse_broadcast_line(raw_line)

        if record is None:
            unparsed_lines.append({"line_number": line_number, "raw_line": raw_line})
            continue

        entry = get_transaction_entry(transactions, transaction_keys_by_txid, record)
        update_transaction(entry, record)

    if unparsed_lines:
        preview = ", ".join(str(item["line_number"]) for item in unparsed_lines[:5])
        raise ValueError(
            f"Unable to parse {len(unparsed_lines)} line(s) from {path}. "
            f"First unparsed line numbers: {preview}."
        )

    return finalize_transactions(transactions)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Parse OP_CHECKCONTRACTVERIFY logs into compact per-raw-transaction JSON."
    )
    parser.add_argument(
        "input",
        nargs="?",
        default="ccv_logs_filtered.txt",
        help="Filtered CCV log file to parse.",
    )
    parser.add_argument(
        "output",
        nargs="?",
        help="Destination JSON file. Defaults to ccv-testvectors.json.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output) if args.output else Path("ccv-testvectors.json")

    parsed = parse_log(input_path)
    output_path.write_text(json.dumps(parsed, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
