# Ubuntu (Sysdig) — heuristic-label result

- Parser: `src/ingest/parse_sysdig.py`.
- No `proc.pid` in the release; instance = `(proc.cmdline, 60 s bucket)`.
- Labels: published `attack_annotation/A*.txt` (UTC+8) matched by command token
  inside the annotated window. **19 malicious instances** matched; all other
  instances are treated as benign.
- Benign trace: 15,342,095 lines → 8,999,638 edges, 69,300 instances.
- Anomaly trace: 3,832,342 lines → 1,278,792 edges, 9,541 instances.

| Method | Balanced P | R | F1 | FPR | AUROC |
|---|---|---|---|---|---|
| ProvDetector (LOF, t=3) | 0.500 | 0.105 | 0.174 | 0.105 | 0.747 |
| Frequency-only | 0.769 | 0.526 | 0.625 | 0.158 | 0.692 |
| Anomaly-score | 0.750 | 0.632 | 0.686 | 0.211 | 0.710 |
| Rule / whitelist | 0.000 | 0.000 | 0.000 | 0.000 | 0.500 / 0.735 |

Coverage: 136,248 train paths, 28,787 benign test paths, 26,186 anomaly paths;
runtime 960.9 s.

**Interpretation:** the Ubuntu labels are heuristic and only 19 positives, so
these numbers are **indicative, not a Linux claim**. The low t=3 recall shows
that a small, heavily-merged instance definition (no PID) makes the
graph-level threshold too strict. The result is reported for completeness and
as future work; the Windows WS12/W10 results are the primary evaluation.
