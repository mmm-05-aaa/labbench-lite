# LabBench Lite

Local-first, read-only CSV quality checks and Markdown reports for scientific-style tabular data.

## Quick start

```bash
python -m labbench.cli audit examples/demo.csv --out outputs/demo --figures
```

The command writes `summary.json`, `report.md`, and `run.log`; `--figures` additionally writes local PNG plots for missingness and numeric distributions. It never uploads data, overwrites the input, imputes missing values, removes outliers, or generates scientific conclusions.

## Confirmed cleaning

Create a preview plan without changing the input:

```bash
python -m labbench.cli clean data.csv --trim-text --drop-empty-rows --out preview
```

After reviewing `preview/cleaning_plan.json`, explicitly apply it to a new directory:

```bash
python -m labbench.cli apply preview/cleaning_plan.json --source data.csv --out cleaned
```

The plan stores only the source filename and SHA-256, not an absolute local path.

The repository contains only synthetic example data. Real research CSV files should remain outside Git and be reviewed by the data owner before local testing.
