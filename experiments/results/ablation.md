# Ablation — WS12 (seed 20261025)

| Path mode | Detector | K | P | R | F1 | FPR | AUROC | AUPRC |
|---|---|---|---|---|---|---|---|---|
| rare | lof | 5 | 0.915 | 1.000 | 0.956 | 0.093 | 0.953 | 0.105 |
| rare | lof | 20 | 0.827 | 1.000 | 0.905 | 0.209 | 0.943 | 0.102 |
| random | lof | 20 | 0.896 | 1.000 | 0.945 | 0.116 | 0.903 | 0.067 |
| rare | ocsvm | 20 | 0.848 | 0.907 | 0.876 | 0.163 | 0.928 | 0.118 |
| rare | iforest | 20 | 0.843 | 1.000 | 0.915 | 0.186 | 0.942 | 0.094 |
| rare | robustcov | 20 | 0.000 | 0.000 | 0.000 | 0.000 | 0.498 | 0.011 |

- `rare+lof K=20` is the main configuration. K=5 is slightly better on this trace (F1 0.956 vs 0.905, FPR 0.093 vs 0.209); K=50 was stopped because the doc2vec run exceeded the iteration budget.
- **Random paths do not hurt** (F1 0.945, AUROC 0.903 vs 0.943 for rare paths). Because the label is the attack process itself, nearly every path from it is attack-related; the paper labels a mostly-benign victim program instead. This is a methodological limitation of the simulated-data evaluation, not evidence that path selection is useless.
- RobustCovariance collapses (AUROC 0.498): the 100-d embeddings are not elliptically distributed.
- Noise injection was not run.
