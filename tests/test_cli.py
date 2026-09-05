import json
from pathlib import Path

from labbench.cli import inspect, write_outputs


def test_inspect_and_write(tmp_path: Path):
    source = tmp_path / "demo.csv"
    source.write_text("group,value\na,1\nb,2\n", encoding="utf-8")
    before = source.read_bytes()
    summary, _ = inspect(source)
    out = tmp_path / "out"
    write_outputs(summary, out)
    assert summary["analysis"]["rows"] == 2
    assert summary["source_unchanged"]
    assert source.read_bytes() == before
    assert json.loads((out / "summary.json").read_text(encoding="utf-8"))["analysis"]["columns"] == 2
