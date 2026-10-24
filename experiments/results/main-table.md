# R21 main results

Method reproduction on PKU-ASAL Simulated-Data; **not** a reproduction of the paper's private-enterprise F1=0.974.

> `frequency_score` is the continuous frequency-only baseline used because the
> binary whitelist degenerates on file-heavy traces (see `docs/limitations.md`).


## Train `WS12` → test `WS12` (seed 20261025, K=20, t=3)

Coverage: train paths 13516, anomaly instances with paths 3176/3176; benign test with paths 754/754.


### Instance level (balanced test set)

| Method | P | R | F1 | FPR | TP/FP/TN/FN |
|---|---|---|---|---|---|
| provdetector | 0.827 | 1.000 | 0.905 | 0.209 | 43/9/34/0 |
| rule_heuristic | 0.000 | 0.000 | 0.000 | 0.000 | 0/0/43/43 |
| whitelist | 0.768 | 1.000 | 0.869 | 0.302 | 43/13/30/0 |
| anomaly_score | 0.768 | 1.000 | 0.869 | 0.302 | 43/13/30/0 |
| frequency_score | 0.878 | 1.000 | 0.935 | 0.140 | 43/6/37/0 |

### Instance level (full test set)

| Method | P | R | F1 | FPR | TP/FP/TN/FN |
|---|---|---|---|---|---|
| provdetector | 0.062 | 1.000 | 0.118 | 0.166 | 43/645/3242/0 |
| rule_heuristic | 0.000 | 0.000 | 0.000 | 0.000 | 0/0/3887/43 |
| whitelist | 0.054 | 1.000 | 0.102 | 0.194 | 43/756/3131/0 |
| anomaly_score | 0.053 | 1.000 | 0.101 | 0.197 | 43/765/3122/0 |
| frequency_score | 0.054 | 1.000 | 0.102 | 0.194 | 43/756/3131/0 |

Path level (LOF threshold 0.5000): P=0.075 R=0.984 F1=0.140 (TP/FP/FN 605/7443/10).

Path level (balanced): P=0.729 R=0.984 F1=0.837 FPR=0.366; path AUROC=0.830, AUPRC=0.094.


### Ranking (full test set)

| Method | AUROC | AUPRC |
|---|---|---|
| provdetector | 0.943 | 0.102 |
| whitelist | 0.903 | 0.054 |
| anomaly_score | 0.954 | 0.130 |
| frequency_score | 0.950 | 0.114 |

LOF calibration: quantile 0.1, benign-val instance FPR 0.029; whitelist support 0.03 fraction threshold 0.076.


### t sweep (ProvDetector, full test)

| t | P | R | F1 | FPR |
|---|---|---|---|---|
| 1 | 0.056 | 1.000 | 0.107 | 0.185 |
| 2 | 0.058 | 1.000 | 0.110 | 0.180 |
| 3 | 0.062 | 1.000 | 0.118 | 0.166 |
| 4 | 0.066 | 1.000 | 0.124 | 0.156 |
| 5 | 0.088 | 1.000 | 0.161 | 0.115 |

Runtime: 136.1s.


## Train `W10` → test `W10` (seed 20261025, K=20, t=3)

Coverage: train paths 58434, anomaly instances with paths 2448/2448; benign test with paths 926/926.


### Instance level (balanced test set)

| Method | P | R | F1 | FPR | TP/FP/TN/FN |
|---|---|---|---|---|---|
| provdetector | 0.782 | 0.765 | 0.773 | 0.213 | 104/29/107/32 |
| rule_heuristic | 0.000 | 0.000 | 0.000 | 0.000 | 0/0/136/136 |
| whitelist | 0.000 | 0.000 | 0.000 | 0.000 | 0/0/136/136 |
| anomaly_score | 0.765 | 0.956 | 0.850 | 0.294 | 130/40/96/6 |
| frequency_score | 0.763 | 0.971 | 0.854 | 0.301 | 132/41/95/4 |

### Instance level (full test set)

| Method | P | R | F1 | FPR | TP/FP/TN/FN |
|---|---|---|---|---|---|
| provdetector | 0.155 | 0.765 | 0.257 | 0.175 | 104/568/2670/32 |
| rule_heuristic | 0.000 | 0.000 | 0.000 | 0.000 | 0/0/3238/136 |
| whitelist | 0.000 | 0.000 | 0.000 | 0.000 | 0/0/3238/136 |
| anomaly_score | 0.132 | 0.956 | 0.232 | 0.263 | 130/853/2385/6 |
| frequency_score | 0.131 | 0.971 | 0.232 | 0.269 | 132/872/2366/4 |

Path level (LOF threshold -10.8606): P=0.150 R=0.340 F1=0.208 (TP/FP/FN 777/4411/1508).

Path level (balanced): P=0.773 R=0.340 F1=0.472 FPR=0.100; path AUROC=0.848, AUPRC=0.151.


### Ranking (full test set)

| Method | AUROC | AUPRC |
|---|---|---|
| provdetector | 0.798 | 0.164 |
| whitelist | 0.703 | 0.066 |
| anomaly_score | 0.889 | 0.331 |
| frequency_score | 0.863 | 0.134 |

LOF calibration: quantile 0.03, benign-val instance FPR 0.046; whitelist support 0.03 fraction threshold 1.000.


### t sweep (ProvDetector, full test)

| t | P | R | F1 | FPR |
|---|---|---|---|---|
| 1 | 0.099 | 0.765 | 0.175 | 0.292 |
| 2 | 0.128 | 0.765 | 0.219 | 0.219 |
| 3 | 0.155 | 0.765 | 0.257 | 0.175 |
| 4 | 0.169 | 0.757 | 0.277 | 0.156 |
| 5 | 0.176 | 0.699 | 0.281 | 0.138 |

Runtime: 531.6s.


## Train `W10` → test `WS12` (seed 20261025, K=20, t=3)

Coverage: train paths 58434, anomaly instances with paths 3176/3176; benign test with paths 5023/5023.


### Instance level (balanced test set)

| Method | P | R | F1 | FPR | TP/FP/TN/FN |
|---|---|---|---|---|---|
| provdetector | 0.950 | 0.442 | 0.603 | 0.023 | 19/1/42/24 |
| rule_heuristic | 0.000 | 0.000 | 0.000 | 0.000 | 0/0/43/43 |
| whitelist | 0.000 | 0.000 | 0.000 | 0.000 | 0/0/43/43 |
| anomaly_score | 0.440 | 0.767 | 0.559 | 0.977 | 33/42/1/10 |
| frequency_score | 0.446 | 0.767 | 0.564 | 0.953 | 33/41/2/10 |

### Instance level (full test set)

| Method | P | R | F1 | FPR | TP/FP/TN/FN |
|---|---|---|---|---|---|
| provdetector | 0.033 | 0.442 | 0.062 | 0.067 | 19/550/7606/24 |
| rule_heuristic | 0.000 | 0.000 | 0.000 | 0.000 | 0/0/8156/43 |
| whitelist | 0.000 | 0.000 | 0.000 | 0.000 | 0/0/8156/43 |
| anomaly_score | 0.004 | 0.767 | 0.009 | 0.910 | 33/7426/730/10 |
| frequency_score | 0.004 | 0.767 | 0.009 | 0.932 | 33/7605/551/10 |

Path level (LOF threshold -6.8516): P=0.035 R=0.237 F1=0.060 (TP/FP/FN 147/4102/473).

Path level (balanced): P=0.907 R=0.237 F1=0.376 FPR=0.024; path AUROC=0.348, AUPRC=0.018.


### Ranking (full test set)

| Method | AUROC | AUPRC |
|---|---|---|
| provdetector | 0.725 | 0.024 |
| whitelist | 0.500 | 0.005 |
| anomaly_score | 0.559 | 0.037 |
| frequency_score | 0.209 | 0.003 |

LOF calibration: quantile 0.03, benign-val instance FPR 0.049; whitelist support 0.0 fraction threshold 0.000.


### t sweep (ProvDetector, full test)

| t | P | R | F1 | FPR |
|---|---|---|---|---|
| 1 | 0.029 | 0.535 | 0.055 | 0.094 |
| 2 | 0.033 | 0.488 | 0.062 | 0.076 |
| 3 | 0.033 | 0.442 | 0.062 | 0.067 |
| 4 | 0.031 | 0.349 | 0.057 | 0.057 |
| 5 | 0.043 | 0.349 | 0.077 | 0.041 |

Runtime: 706.5s.


## Train `WS12` → test `W10` (seed 20261025, K=20, t=3)

Coverage: train paths 13516, anomaly instances with paths 2448/2448; benign test with paths 6167/6167.


### Instance level (balanced test set)

| Method | P | R | F1 | FPR | TP/FP/TN/FN |
|---|---|---|---|---|---|
| provdetector | 0.509 | 1.000 | 0.675 | 0.963 | 136/131/5/0 |
| rule_heuristic | 0.000 | 0.000 | 0.000 | 0.000 | 0/0/136/136 |
| whitelist | 0.500 | 1.000 | 0.667 | 1.000 | 136/136/0/0 |
| anomaly_score | 0.500 | 1.000 | 0.667 | 1.000 | 136/136/0/0 |
| frequency_score | 0.500 | 1.000 | 0.667 | 1.000 | 136/136/0/0 |

### Instance level (full test set)

| Method | P | R | F1 | FPR | TP/FP/TN/FN |
|---|---|---|---|---|---|
| provdetector | 0.016 | 1.000 | 0.032 | 0.963 | 136/8168/311/0 |
| rule_heuristic | 0.000 | 0.000 | 0.000 | 0.000 | 0/0/8479/136 |
| whitelist | 0.016 | 1.000 | 0.031 | 1.000 | 136/8479/0/0 |
| anomaly_score | 0.016 | 1.000 | 0.031 | 1.000 | 136/8479/0/0 |
| frequency_score | 0.016 | 1.000 | 0.031 | 1.000 | 136/8479/0/0 |

Path level (LOF threshold 0.5000): P=0.017 R=0.993 F1=0.033 (TP/FP/FN 2280/133215/16).

Path level (balanced): P=0.507 R=0.993 F1=0.672 FPR=0.964; path AUROC=0.419, AUPRC=0.013.


### Ranking (full test set)

| Method | AUROC | AUPRC |
|---|---|---|
| provdetector | 0.572 | 0.020 |
| whitelist | 0.500 | 0.016 |
| anomaly_score | 0.739 | 0.188 |
| frequency_score | 0.488 | 0.015 |

LOF calibration: quantile 0.1, benign-val instance FPR 0.028; whitelist support 0.03 fraction threshold 0.076.


### t sweep (ProvDetector, full test)

| t | P | R | F1 | FPR |
|---|---|---|---|---|
| 1 | 0.016 | 1.000 | 0.031 | 1.000 |
| 2 | 0.016 | 1.000 | 0.031 | 0.992 |
| 3 | 0.016 | 1.000 | 0.032 | 0.963 |
| 4 | 0.016 | 1.000 | 0.032 | 0.962 |
| 5 | 0.016 | 1.000 | 0.032 | 0.959 |

Runtime: 499.0s.

