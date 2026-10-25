# Repository Guidelines

## Project Overview

This repository implements an end-to-end provenance-based intrusion detection pipeline reproducing the method of **ProvDetector** (*You Are What You Do: Hunting Stealthy Malware via Data Provenance Analysis*, NDSS 2020) on public simulated APT traces (**PKU-ASAL Simulated-Data** Windows 10 & Windows Server 2012, plus Ubuntu Sysdig and ProvNinja cross-checks).

> **Academic integrity constraint**: This is an algorithmic reproduction on a substitute dataset, **not** a numeric reproduction of the paper's proprietary enterprise F1 score ($0.974$). Never claim numerical parity with the paper.

---

## Architecture & Data Flow

The system processes system audit logs into process-rooted provenance subgraphs, selects the most improbable causal chains, embeds them using doc2vec, and flags novelty using Local Outlier Factor (LOF).

```
Raw Telemetry (Windows ETW JSONL / Sysdig JSONL / ProvNinja CSV)
  │
  ├─► [src/ingest/parse_pku.py | parse_sysdig.py]
  │     ├─ Two-pass memory-bounded ingestion (Lifecycle intervals ──► NodeTable)
  │     └─ Path/endpoint normalization (normalize.py: abstract_path, socket_endpoint)
  │
  ▼ Normalized Storage (`data/clean/{dataset}_{scenario}_{events|nodes|instances}.parquet`)
  │
  ├─► [Trace.load() in src/graph/build.py]
  │     ├─ Chronologically sorted events; O(1) interval slicing via numpy bounds
  │     └─ Subgraph construction via BFS descendant expansion (depth=2, cap=40,000)
  │
  ├─► [FrequencyDB.build() in src/graph/build.py]
  │     └─ Smoothed log-rarity database fitted strictly on benign training instances
  │
  ├─► [select_paths() in src/select/paths.py]
  │     ├─ Time-respecting beam search (beam=300, max_len=5, top-K=20)
  │     └─ Terminal/continuing edge splitting; cached via pickle (`cache/{tag}_{split}.pkl`)
  │
  ├─► [PathEncoder in src/embed/doc2vec.py]
  │     ├─ Benign train paths tokenized into sentences (`P:proc REL F:path ...`)
  │     └─ PV-DM Doc2Vec (vector_size=100, dm=1, epochs=100, workers=1 for determinism)
  │
  ├─► [NoveltyDetector in src/detect/detectors.py | lof.py]
  │     ├─ LOF fitted on benign train embeddings (novelty=True, k=20)
  │     └─ Quantile search calibration on validation paths to enforce val instance FPR ≤ 5%
  │
  └─► [Evaluation in src/experiment.py]
        ├─ Instance flagged malicious if ≥ t outlier paths (default primary t=3)
        ├─ Baselines: Rule heuristic, Whitelist, Frequency-only score, Anomaly score
        └─ Metrics: Full & balanced P/R/F1/FPR, AUROC/AUPRC, t-sweep (1..5)
```

---

## Key Directories

| Directory | Purpose |
|---|---|
| `src/ingest/` | Telemetry parsing, schema definition, entity normalization, process lifecycle reconstruction. |
| `src/graph/` | Parquet trace loading (`Trace`), subgraph extraction, frequency/rarity database (`FrequencyDB`), graph visualization (`viz.py`). |
| `src/select/` | Causal path enumeration with strict time ordering, rareness scoring, and random walk baselines. |
| `src/embed/` | Sentence representation and deterministic PV-DM Doc2Vec path embedding (`PathEncoder`). |
| `src/detect/` | Novelty detection (`LOFDetector`, `NoveltyDetector` supporting LOF, OCSVM, IsolationForest, RobustCovariance) and instance aggregation. |
| `src/baseline/` | Baseline models: rule-based UI spawn detection, edge whitelist, and anomaly scoring. |
| `src/util/` | Binary metrics (`precision`, `recall`, `f1`, `fpr`), data leakage assertions. |
| `tests/` | Unit tests for parser normalization, Sysdig ingestion, ProvNinja grammar, pipeline execution, leakage checks, and noise injection. |
| `scripts/` | Shell helpers: environment checks, deterministic seed exports, batch ingestion, leakage audits. |
| `experiments/` | Experiment scripts, protocol specifications, error analysis, ProvNinja cross-check, signal/noise audits. |
| `experiments/results/` | Output JSON result summaries, instance prediction CSVs, Markdown benchmark tables. |
| `data/manifest.csv` | Cryptographic SHA-256 and byte-count ledger for all raw archives and uncompressed datasets. |

---

## Development Commands

All development tasks should run through `make` inside the dedicated Python 3.12 virtual environment:

```bash
# Environment setup
make setup          # Creates .venv (Python 3.12 via uv) and installs pinned requirements
make env            # Validates exact pinned versions against scripts/check_env.py

# Quality Assurance & Testing
make test           # Runs all unit tests via pytest (-q)
make check          # Validates zero train/validation instance leakage across path caches
uvx ruff check .    # Lints codebase (strict compliance, zero warnings allowed)

# Ingestion
make ingest         # Parses raw WS12 and W10 Windows ETW logs into data/clean/*.parquet
make ubuntu         # Unpacks and parses Ubuntu Sysdig trace with UTC+8 attack annotations

# Running Experiments
make ws12           # In-dataset experiment on WS12 (train WS12 benign -> test WS12 anomaly)
make w10            # In-dataset experiment on W10 (train W10 benign -> test W10 anomaly)
make cross          # Bidirectional cross-dataset runs (W10 -> WS12 and WS12 -> W10)
make clean-cache    # Purges experiments/results/cache/ pickle files
```

### Custom Experiment Invocations

`src.experiment` accepts fine-grained configuration for ablation studies:

```bash
# Temporal split (chronological instance ordering by start timestamp)
.venv/bin/python -m src.experiment --train WS12 --test WS12 --split temporal

# Noise injection (replaces % of malicious paths with random benign paths)
.venv/bin/python -m src.experiment --train WS12 --test WS12 --noise 0.50

# Path sampling ablation (uniform random walks instead of top-K rarest)
.venv/bin/python -m src.experiment --train WS12 --test WS12 --path-mode random

# Alternative novelty detectors
.venv/bin/python -m src.experiment --train WS12 --test WS12 --detector ocsvm  # or iforest, robustcov
```

---

## Code Conventions & Common Patterns

### Architecture & Data Management Invariants

1. **Edge Source Invariant**: Only process entities can be edge sources. Relations follow `Rel(IntEnum)`:
   - `START = 0` (process $\to$ process)
   - `READ = 1` (process $\to$ file)
   - `WRITE = 2` (process $\to$ file)
   - `EXECUTE = 3` (process $\to$ file/library)
   - `CONNECT = 4` (process $\to$ socket)
   - `Process/Stop` events define lifetimes; they are **never** stored as graph edges.
2. **`START` Edge Ownership**: A `START` edge is owned by the **parent** instance's event stream. The child instance owns its subsequent execution (`READ`, `WRITE`, `CONNECT`). The child process is evaluated as an independent instance.
3. **Instance ID Namespacing**: Instance IDs in raw traces start at `0` for each dataset scenario. When combining benign test instances and anomaly instances in `src/experiment.py`, anomaly IDs **MUST** be namespaced using `offset = 1_000_000` (`int(instance) + offset`) to prevent dictionary key collisions.
4. **Isolated Noise RNG**: In `src/experiment.py`, benign path noise injection uses an independent random generator (`noise_rng = np.random.default_rng(seed + 1_000_003)`). Never use the main `rng` for noise injection; consuming random state alters balanced test negative sampling.
5. **Path Selection Beam & Terminal Splitting**: `src/select/paths.py` differentiates between:
   - *Terminal edges* (destination has no outgoing edges; files/sockets): directly scored and added to top-K heap.
   - *Continuing edges* (destination is a process): queued for beam search expansion (beam width = 300, max hop length = 5).
6. **Determinism**:
   - Always run with `workers=1` in `Doc2Vec` to avoid multithreading non-determinism.
   - Always re-seed `model.random.seed(self.seed)` immediately prior to each `model.infer_vector()`.

### Error Handling & Typing
- Codebases target modern Python 3.12: include `from __future__ import annotations` at the top of every file.
- Strict static typing everywhere: use standard collections (`list[str]`, `dict[str, int]`, `tuple[...]`).
- Ingestion pipelines must be resilient: use `json.loads` within `try...except json.JSONDecodeError: continue` and sanitize timestamps and PIDs via helper methods `_ts()` and `_int()`.

---

## Important Files

### Entry Points
- `src/experiment.py`: Main execution engine handling splits, path caching, embedding, detection, baselines, and metrics.
- `src/ingest/parse_pku.py`: Ingestion driver for Windows ETW logs.
- `src/ingest/parse_sysdig.py`: Ingestion driver for Linux Sysdig logs with UTC+8 timestamp alignment.
- `experiments/frequency_baseline.py`: Post-hoc continuous edge-frequency scoring baseline.
- `experiments/analyze_errors.py`: Process ancestry climber computing spawn-chain recall and FP/FN taxonomies.
- `experiments/format_results.py`: Generator for Markdown benchmark summary tables.

### Configuration & Schemas
- `config.yaml`: Central specification for paths, hyperparameters ($K=20$, $L=5$, $t=3$), split ratios ($0.7/0.15/0.15$), and Doc2Vec/LOF settings.
- `src/ingest/schema.py`: Canonical definitions of `Rel`, `NodeType`, `Scenario`, and PyArrow table schemas (`EVENT_SCHEMA`, `NODE_SCHEMA`, `INSTANCE_SCHEMA`).
- `requirements.txt`: 11 pinned production dependencies.
- `environment.lock`: Full 29-package lockfile.

### Artifacts & Ground Truth
- `data/manifest.csv`: Cryptographic source of truth for raw archive integrity.
- `docs/data-card.md`: Dataset source, collection environment, schema mapping, duplicate audits, and bias disclosures.
- `docs/threat-model.md`: Attacker profile, observation surface, TTP provenance mappings, and Mermaid concept map.
- `docs/limitations.md`: Comprehensive technical analysis of single-host degradation, cross-dataset distribution shift, and baseline comparisons.

---

## Runtime & Tooling Preferences

- **Required Runtime**: Python 3.12 (`cpython-3.12.*`).
- **Package Manager**: `uv` is required. Never use system `pip` or global Python environments.
- **Why Python 3.14 is Prohibited**:
  1. `numpy==1.26.4` lacks Python 3.14 wheels and cannot build against NumPy 2.x C-API.
  2. `gensim==4.4.0` Cython C-extensions (`FAST_VERSION=1`) break under Python 3.13+, causing extreme slowdowns or build crashes.
  3. Embedding vectors drift across Python minor releases, invalidating published benchmarks in `experiments/results/seed-variance.md`.
- **Git Tracking Rules**:
  - Raw datasets (`data/raw/`, `data/raw-provninja/`) and parquet tables (`data/clean/`) are git-ignored.
  - Intermediate experiment path caches (`experiments/results/cache/`, `*.pkl`) are git-ignored.
  - Result JSON summaries (`experiments/results/*.json`) and prediction CSVs (`*_predictions.csv`) **MUST** be tracked in git.

---

## Testing & QA

- **Framework**: `pytest` (`.venv/bin/python -m pytest tests/ -q`).
- **Fixtures & Testing Strategy**:
  - Tests rely on `tmp_path` to build synthetic newline-delimited JSON logs using `_proc()`, `_stop()`, `_file()`, and `_event()`.
  - No integration test depends on network access or full 10GB raw traces.
- **Coverage Invariants**:
  - `tests/test_parse_pku.py`: Normalization wildcards (`*:/users/*/`), symmetric socket resolution, and START edge ownership.
  - `tests/test_parse_sysdig.py`: Sysdig syscall mapping, UTC+8 annotation window matching, and benign defaults.
  - `tests/test_parse_provninja.py`: Space-delimited token triples validation.
  - `tests/test_pipeline.py`: Rarest path prioritization over frequent edges, Doc2Vec/LOF determinism across runs, metric computation.
  - `tests/test_leakage.py`: Instance disjointness assertions (`assert_disjoint`) and signature overlap accounting.
  - `tests/test_experiment.py`: Chronological ordering in temporal split and malicious-only targeting in noise replacement.
- **Pre-commit Checklist**:
  1. `make test` passes (14/14 tests).
  2. `make env` returns `ENV OK`.
  3. `uvx ruff check .` returns `All checks passed!`.
  4. `make check` confirms zero instance leakage between train and validation caches.
