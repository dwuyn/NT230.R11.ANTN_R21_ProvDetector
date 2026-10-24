# Signal and noise analysis — WS12

Malicious instances: 43; benign test: 754.

## Single-feature separation

| Feature | Malicious median | Benign median | AUROC |
|---|---|---|---|
| n_paths | 19.000 | 3.000 | 0.969 |
| min_log | -24.497 | -9.000 | 0.987 |
| mean_log | -21.463 | -9.000 | 0.970 |
| start_edges | 0.000 | 0.000 | 0.655 |
| sockets | 0.000 | 0.000 | 0.568 |
| file_edges | 18.000 | 3.000 | 0.969 |
| mean_len | 1.000 | 1.000 | 0.655 |

## Relation mix in selected paths

| Relation | Malicious share | Benign share |
|---|---|---|
| start_edges | 0.304 | 0.069 |
| sockets | 0.012 | 0.003 |
| file_edges | 0.684 | 0.928 |

## Noise level (edges already seen in ≥3% of benign training instances)

- Malicious graphs: median 0.000 common edges (IQR 0.000–0.000).
- Benign graphs: median 1.000 common edges (IQR 1.000–1.000).

`n_paths` is a coverage artifact (malicious graphs are larger), not a deployable feature. Malicious graphs are dominated by rare edges; the signal is not a single relation but the *combination* of a rare process chain (START) and rare file/socket sinks. Benign graphs retain a substantial common-edge core, which is why frequency-only baselines also work well.

## Path overlap

- Malicious selected paths with a signature also present in benign train: 0 (see `path-sanity.md`).
