from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
import statistics
import sys
import time
from datetime import datetime
from pathlib import Path

from . import __version__

MISSING = {"", "na", "n/a", "nan", "null", "none", ".", "..", "-"}
SENSITIVE = re.compile(
    r"(password|passwd|secret|token|api[_ -]?key|private[_ -]?key|email|phone|address|patient|subject|sequence|protein|peptide|dna|rna)",
    re.I,
)
SECRET_VALUE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bsk-[A-Za-z0-9_-]{20,}\b|\bBearer\s+\S+|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    re.I,
)


def missing(value: str) -> bool:
    return value.strip().lower() in MISSING


def number(value: str) -> float | None:
    value = value.strip().replace(",", "")
    if not value or value.lower() in MISSING:
        return None
    try:
        result = float(value)
    except ValueError:
        return None
    return result if math.isfinite(result) else None


def read_csv(path: Path) -> tuple[list[str], list[list[str]], str, str, list[str]]:
    raw = path.read_bytes()[:65536]
    encoding = "utf-8-sig"
    try:
        raw.decode(encoding)
    except UnicodeDecodeError:
        encoding = "gb18030"
    sample = raw.decode(encoding, errors="strict")
    try:
        delimiter = csv.Sniffer().sniff(sample, delimiters=",;\t|").delimiter
    except csv.Error:
        delimiter = ","
    with path.open("r", encoding=encoding, newline="") as handle:
        rows = list(csv.reader(handle, delimiter=delimiter))
    header = rows[0] if rows else []
    body = rows[1:] if rows else []
    warnings = []
    if any(len(row) != len(header) for row in body):
        warnings.append("irregular_row_width")
    if len(set(header)) != len(header):
        warnings.append("duplicate_header_labels")
    return header, body, encoding, delimiter, warnings


def inspect(path: Path) -> tuple[dict, list[str]]:
    before = path.stat()
    data = path.read_bytes()
    if SECRET_VALUE.search(data.decode("utf-8", errors="ignore")):
        raise ValueError("sensitive_value_signal")
    header, rows, encoding, delimiter, warnings = read_csv(path)
    if any(SENSITIVE.search(name or "") for name in header):
        raise ValueError("sensitive_header_signal")
    width = len(header)
    padded = [row + [""] * max(0, width - len(row)) for row in rows]
    padded = [row[:width] for row in padded]
    columns = []
    for index, name in enumerate(header):
        values = [row[index] for row in padded]
        clean = [value.strip() for value in values if not missing(value)]
        nums = [number(value) for value in clean]
        numeric = bool(clean) and all(value is not None for value in nums)
        item = {
            "column": f"column_{index + 1:02d}",
            "type": "numeric" if numeric else "categorical_or_text",
            "missing_count": sum(missing(value) for value in values),
            "unique_count": len(set(clean)),
            "warnings": [],
        }
        if numeric:
            values_num = [value for value in nums if value is not None]
            item["numeric"] = {
                "count": len(values_num),
                "min": min(values_num),
                "max": max(values_num),
                "mean": statistics.fmean(values_num),
                "median": statistics.median(values_num),
            }
            if len(values_num) >= 4:
                q1, _, q3 = statistics.quantiles(values_num, n=4, method="inclusive")
                iqr = q3 - q1
                outliers = sum(value < q1 - 1.5 * iqr or value > q3 + 1.5 * iqr for value in values_num)
                item["numeric"]["iqr_outlier_count"] = outliers
                if outliers:
                    item["warnings"].append("possible_iqr_outliers")
        else:
            if clean and len(set(clean)) > max(20, len(clean) * 0.2):
                item["warnings"].append("non_numeric_or_mixed_values")
        columns.append(item)
    duplicate_rows = len(padded) - len({tuple(row) for row in padded})
    blank_rows = sum(all(missing(value) for value in row) for row in padded)
    after = path.stat()
    summary = {
        "tool": "LabBench Lite",
        "version": __version__,
        "source": {"name": path.name, "size_bytes": before.st_size, "sha256": hashlib.sha256(data).hexdigest()},
        "analysis": {
            "rows": len(rows),
            "columns": len(header),
            "encoding": encoding,
            "delimiter": delimiter,
            "duplicate_rows": duplicate_rows,
            "blank_rows": blank_rows,
            "warnings": sorted(set(warnings + [warning for column in columns for warning in column["warnings"]])),
            "column_profiles": columns,
        },
        "source_unchanged": before.st_size == after.st_size and before.st_mtime_ns == after.st_mtime_ns,
        "limitations": ["No rows deleted", "No missing values imputed", "No values overwritten", "No scientific conclusions generated"],
    }
    return summary, warnings


def write_outputs(summary: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    analysis = summary["analysis"]
    lines = ["# LabBench Lite 报告", "", f"- 输入文件：`{summary['source']['name']}`", f"- 工具版本：`{summary['version']}`", f"- 行数：**{analysis['rows']}**", f"- 列数：**{analysis['columns']}**", f"- 编码：`{analysis['encoding']}`", f"- 分隔符：`{repr(analysis['delimiter'])}`", f"- 重复行：**{analysis['duplicate_rows']}**", f"- 空行：**{analysis['blank_rows']}**", f"- 原始文件未改变：**{summary['source_unchanged']}**", "", "## 列概览", "", "| 列 | 类型 | 缺失数 | 唯一值数 | 警告 |", "|---|---|---:|---:|---|"]
    for column in analysis["column_profiles"]:
        lines.append(f"| {column['column']} | {column['type']} | {column['missing_count']} | {column['unique_count']} | {', '.join(column['warnings']) or '-'} |")
    lines += ["", "## 工具限制", ""] + [f"- {item}" for item in summary["limitations"]]
    (out / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (out / "run.log").write_text(f"[{datetime.now().astimezone().isoformat(timespec='seconds')}] status=success\n", encoding="utf-8")


def write_figures(source: Path, summary: dict, out: Path) -> list[str]:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return []
    header, rows, _, delimiter, _ = read_csv(source)
    width = len(header)
    data = [(row + [""] * max(0, width - len(row)))[:width] for row in rows]
    figure_dir = out / "figures"
    figure_dir.mkdir(parents=True, exist_ok=True)
    profiles = summary["analysis"]["column_profiles"]
    labels = [item["column"] for item in profiles]
    missing_values = [item["missing_count"] / max(1, len(rows)) * 100 for item in profiles]
    result = []
    fig, ax = plt.subplots(figsize=(max(7, len(labels) * 0.55), 4.2))
    ax.bar(labels, missing_values, color="#4C78A8")
    ax.set_ylabel("Missing values (%)")
    ax.set_title("Missingness by masked column label")
    ax.tick_params(axis="x", rotation=45)
    fig.tight_layout()
    target = figure_dir / "missingness.png"
    fig.savefig(target, dpi=160)
    plt.close(fig)
    result.append(str(target.relative_to(out)).replace("\\", "/"))
    values, numeric_labels = [], []
    for item in profiles:
        if item["type"] != "numeric":
            continue
        index = int(item["column"].split("_")[1]) - 1
        nums = [number(row[index]) for row in data]
        nums = [value for value in nums if value is not None]
        if nums:
            values.append(nums); numeric_labels.append(item["column"])
    if values:
        fig, ax = plt.subplots(figsize=(max(7, len(values) * 0.65), 4.5))
        try:
            ax.boxplot(values, tick_labels=numeric_labels, showfliers=True)
        except TypeError:
            ax.boxplot(values, labels=numeric_labels, showfliers=True)
        ax.set_ylabel("Observed numeric values")
        ax.set_title("Numeric distributions (read-only)")
        ax.tick_params(axis="x", rotation=45)
        fig.tight_layout()
        target = figure_dir / "numeric_distributions.png"
        fig.savefig(target, dpi=160)
        plt.close(fig)
        result.append(str(target.relative_to(out)).replace("\\", "/"))
    return result


def transform_rows(header: list[str], rows: list[list[str]], operations: dict) -> tuple[list[list[str]], list[str]]:
    width = len(header)
    data = [(row + [""] * max(0, width - len(row)))[:width] for row in rows]
    changes = []
    if operations.get("trim_text"):
        count = sum(value != value.strip() for row in data for value in row)
        data = [[value.strip() for value in row] for row in data]
        changes.append(f"trim_text={count}")
    if operations.get("drop_empty_rows"):
        before = len(data); data = [row for row in data if not all(missing(v) for v in row)]
        changes.append(f"drop_empty_rows={before - len(data)}")
    if operations.get("drop_duplicates"):
        before = len(data); seen = set(); unique = []
        for row in data:
            key = tuple(row)
            if key not in seen: seen.add(key); unique.append(row)
        data = unique; changes.append(f"drop_duplicates={before - len(data)}")
    cfg = operations.get("fill_missing", {})
    if cfg.get("strategy") in {"mean", "median"}:
        targets = cfg.get("columns", []) or [f"column_{i + 1:02d}" for i in range(width)]
        for i, name in enumerate(header):
            if name not in targets and f"column_{i + 1:02d}" not in targets: continue
            nums = [number(row[i]) for row in data]; nums = [v for v in nums if v is not None]
            if not nums: continue
            replacement = statistics.fmean(nums) if cfg["strategy"] == "mean" else statistics.median(nums)
            count = 0
            for row in data:
                if missing(row[i]): row[i] = str(replacement); count += 1
            changes.append(f"fill_missing_column_{i + 1:02d}={count}")
    return data, changes


def write_csv(path: Path, header: list[str], rows: list[list[str]], delimiter: str = ",") -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter=delimiter); writer.writerow(header); writer.writerows(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit-first local CSV analysis and confirmed cleaning")
    sub = parser.add_subparsers(dest="command")
    for command in ("audit", "clean"):
        child = sub.add_parser(command); child.add_argument("csv", type=Path, nargs="+"); child.add_argument("--out", type=Path, default=Path("labbench-output")); child.add_argument("--figures", action="store_true")
        if command == "clean":
            child.add_argument("--trim-text", action="store_true"); child.add_argument("--drop-empty-rows", action="store_true"); child.add_argument("--drop-duplicates", action="store_true"); child.add_argument("--fill-missing", choices=("none", "mean", "median"), default="none"); child.add_argument("--column", action="append", default=[])
    apply_parser = sub.add_parser("apply"); apply_parser.add_argument("plan", type=Path); apply_parser.add_argument("--source", type=Path, required=True); apply_parser.add_argument("--out", type=Path, required=True)
    raw = list(argv if argv is not None else sys.argv[1:])
    if raw and raw[0] not in {"audit", "clean", "apply", "-h", "--help"}: raw.insert(0, "audit")
    args = parser.parse_args(raw)
    if args.command == "apply":
        plan = json.loads(args.plan.read_text(encoding="utf-8")); source = args.source
        if not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest() != plan["source_sha256"]: print(json.dumps({"status": "stopped", "reason": "source_changed_or_missing"}), file=sys.stderr); return 3
        header, rows, _, delimiter, _ = read_csv(source); cleaned, changes = transform_rows(header, rows, plan["operations"]); args.out.mkdir(parents=True, exist_ok=True); target = args.out / f"{source.stem}.cleaned.csv"; write_csv(target, header, cleaned, delimiter); (args.out / "apply_report.json").write_text(json.dumps({"source": source.name, "changes": changes, "rows_before": len(rows), "rows_after": len(cleaned)}, ensure_ascii=False, indent=2), encoding="utf-8"); print(json.dumps({"status": "success", "out": str(target), "rows": len(cleaned)}, ensure_ascii=False)); return 0
    if args.command is None: parser.print_help(); return 2
    operations = {"trim_text": getattr(args, "trim_text", False), "drop_empty_rows": getattr(args, "drop_empty_rows", False), "drop_duplicates": getattr(args, "drop_duplicates", False), "fill_missing": {"strategy": getattr(args, "fill_missing", "none"), "columns": getattr(args, "column", [])}}
    results = []
    for source in args.csv:
        if not source.is_file(): parser.error(f"CSV not found: {source}")
        out = args.out if len(args.csv) == 1 else args.out / source.stem
        try:
            summary, _ = inspect(source); write_outputs(summary, out)
            figures = write_figures(source, summary, out) if getattr(args, "figures", False) else []
            if args.command == "clean": (out / "cleaning_plan.json").write_text(json.dumps({"version": 1, "source_name": source.name, "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(), "operations": operations, "preview_only": True}, ensure_ascii=False, indent=2), encoding="utf-8")
        except (OSError, UnicodeError, csv.Error, ValueError) as exc: print(json.dumps({"status": "stopped", "file": source.name, "reason": str(exc)}, ensure_ascii=False), file=sys.stderr); return 3
        results.append({"status": "success", "file": source.name, "rows": summary["analysis"]["rows"], "columns": summary["analysis"]["columns"], "out": str(out), "figures": figures})
    print(json.dumps(results[0] if len(results) == 1 else {"status": "success", "files": results}, ensure_ascii=False)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
