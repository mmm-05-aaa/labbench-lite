import json
import tempfile
import unittest
from pathlib import Path

from labbench.cli import inspect, write_outputs


class CliTests(unittest.TestCase):
    def test_inspect_and_write(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            source = tmp_path / "demo.csv"
            source.write_text("group,value\na,1\nb,2\n", encoding="utf-8")
            before = source.read_bytes()
            summary, _ = inspect(source)
            out = tmp_path / "out"
            write_outputs(summary, out)
            self.assertEqual(summary["analysis"]["rows"], 2)
            self.assertTrue(summary["source_unchanged"])
            self.assertEqual(summary["source"], {"name": "demo.csv", "size_bytes": len(before)})
            self.assertEqual(source.read_bytes(), before)
            written = json.loads((out / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(written["analysis"]["columns"], 2)


if __name__ == "__main__":
    unittest.main()
