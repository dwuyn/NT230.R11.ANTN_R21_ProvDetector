# R21 experiment protocol (locked)

## Unit of analysis

- **Process instance** = one `Process/Start` … `Process/Stop` interval, keyed by
  PID inside the trace and paired by Windows' `UniqueProcessKey`. An implicit
  instance is created for a PID whose events precede the first start record.
- Instances, not events or paths, are split. Every path selected from an
  instance stays on that instance's side.

## Data

| Trace | Benign | Anomaly | Malicious starts |
|---|---|---|---|
| WS12 (Windows Server 2012) | 5,033 instances / 7,191,156 edges | 3,180 / 1,083,898 | 43 |
| W10 (Windows 10) | 6,201 / 6,015,438 | 2,472 / 1,876,355 | 136 |

Labels come from the `is_warn` field of `Process/Start`. All events owned by a
labelled process inherit the label. A child start edge is owned by the parent
graph, so a benign parent can contain a malicious child; the child is evaluated
as its own instance.

## Split

- In-dataset: benign instances shuffled with the run seed, 70% train, 15%
  validation, 15% test. All anomaly instances are test, labelled by `is_warn`.
- Cross-dataset: 85% of the source benign trace trains and 15% validates; the
  target benign trace is test-only. No target labels enter training.
- Training uses benign data only. Validation is benign-only for calibrating the
  LOF path threshold (5th percentile) and the whitelist cutoff (benign FPR ≤ 5%).

## Pipeline

1. Build per-instance provenance graph: root process, its own edges, and
   descendants up to depth 2 (chain `victim → shell → payload`).
2. Regularity database from benign train instances:
   `R(e) = freq_instances(e) × OUT(src_label) × IN(dst_label)`, all smoothed by
   `(count+1)/(N+2)`. This replaces host frequency (single-host traces) and is
   recorded as an adaptation.
3. Enumerate time-respecting paths from the root (max 5 edges, beam 2,000),
   keep top K=20 lowest `∏R(e)`.
4. Path → token sentence `P:exe REL F:path …`; PV-DM doc2vec, 100 dims, 100
   epochs, trained on benign train paths only.
5. LOF (`n_neighbors=20`, novelty) fitted on benign train path vectors; path
   outlier if score < 5th percentile of benign validation path scores.
6. Instance malicious if at least `t` of its selected paths are outliers
   (primary t=3, sweep 1…5).

## Baselines

- **Rule:** UI-heavy root spawning a script interpreter in its family.
- **Whitelist:** edge support < cutoff in benign train; cutoff calibrated on
  benign validation.
- **Anomaly-score:** instance flagged if its rarest path log-regularity is below
  the benign validation 5th percentile.

## Metrics

- Instance-level P/R/F1/FPR and confusion matrix, on the full test set and on a
  seed-matched balanced set (all positives + equal negatives).
- Path-level P/R/F1 over selected test paths (path inherits instance label).
- Coverage (instances with ≥1 selected path) reported alongside.
- Overhead: wall time per stage.

## Reproduction

```bash
source scripts/seed.sh
.venv/bin/python -m src.experiment --train WS12 --test WS12
.venv/bin/python -m src.experiment --train W10  --test W10
.venv/bin/python -m src.experiment --train W10  --test WS12
.venv/bin/python -m src.experiment --train WS12 --test W10
```

The reported numbers are a **method reproduction on a different dataset**, not
a reproduction of the paper's F1=0.974 on its private enterprise traces.
