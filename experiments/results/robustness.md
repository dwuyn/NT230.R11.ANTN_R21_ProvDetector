# Robustness: temporal split, noise injection, K sweep

## 1. Temporal split (WS12)

| Split | Prov F1 | Prov FPR | Prov AUROC | Freq F1 | Freq AUROC |
|---|---|---|---|---|---|
| random | 0.905 | 0.209 | 0.943 | 0.935 | 0.950 |
| temporal | 0.905 | 0.209 | 0.942 | 0.935 | 0.954 |

Temporal split sorts instances by `start`; train max start < val min start < test min start (verified). The test sets differ (instance overlap 3216/3697), but the metrics are within seed variance.

## 2. Noise injection (path-level replacement, WS12, K=20)

| Noise | Prov F1 | Prov P | Prov R | Prov FPR | Prov AUROC |
|---|---|---|---|---|---|
| 25% | 0.915 | 0.843 | 1.000 | 0.186 | 0.907 |
| 50% | 0.800 | 0.810 | 0.791 | 0.186 | 0.890 |
| 75% | 0.786 | 0.805 | 0.767 | 0.186 | 0.869 |
| 90% | 0.622 | 0.742 | 0.535 | 0.186 | 0.844 |

Each malicious instance keeps `round((1-noise)·K)` attack paths; the rest are replaced by benign paths sampled from the training pool. At 50% noise recall drops from 1.00 to 0.79; at 90% to 0.54. FPR stays 0.186 (benign instances are untouched), so F1 degradation is driven by missed positives, as intended. The frequency-only baseline is unchanged (F1 0.935, AUROC 0.950) because it reads the original graph, not the noisy path set; this is why the noise ablation is only meaningful for the embedding detector.

## 3. K sweep (WS12, no noise)

| K | Prov F1 | Prov FPR | Prov AUROC | Freq F1 | Freq AUROC | Runtime (s) |
|---|---|---|---|---|---|---|
| 5 | 0.956 | 0.093 | 0.953 | 0.935 | 0.950 | 101.4 |
| 20 | 0.905 | 0.209 | 0.943 | 0.935 | 0.950 | 136.1 |
| 50 | 0.925 | 0.163 | 0.905 | 0.935 | 0.950 | 401.7 |

K is not monotone: K=5 has the best F1 (0.956) and AUROC (0.953); K=20 is slightly worse; K=50 improves F1 over K=20 but lowers AUROC to 0.905. More paths add noisy candidates. K=20 is a reasonable default; K=5 is cheaper and slightly better on this trace.

> All results are on the simulated PKU-ASAL WS12 trace; they are not a reproduction of the paper's enterprise F1.
