# Overhead measurements

Measured on the lab machine (16 vCPU, 14 GB RAM, Linux 6.18, Python 3.12.13,
gensim 4.4.0, sklearn 1.5.2). Times are wall-clock for the whole experiment
config, not per stage (per-stage timers are a known gap).

| Stage | Measurement |
|---|---|
| Ingest all four traces (WS12 + W10 benign/anomaly) | 218 s total (parser log, 17.1M events) |
| Storage, raw archives + extracted JSON | 6.5 GB (`data/raw`) |
| Storage, normalised Parquet | 79 MB (`data/clean`, 4 event/node/instance sets) |
| Path caches (K=20, rare) | 75 MB (`experiments/results/cache`) |
| Figures | 2.5 MB |

| Train → Test | Runtime (s) | Train paths | Test benign paths | Anomaly paths |
|---|---|---|---|---|
| WS12 → WS12 | 136.1 | 13,516 | 2,806 | 17,132 |
| W10 → W10 | 531.6 | 58,434 | 12,668 | 34,456 |
| W10 → WS12 | 706.5 | 58,434 | 99,185 | 58,731 |
| WS12 → W10 | 499.0 | 13,516 | 99,951 | 40,165 |

Runtime covers path selection, doc2vec training, inference (100 epochs/path) and
LOF. Ingest is excluded because it runs once per dataset. The W10→WS12 and
WS12→W10 configurations are slower because the target benign trace has 5–6k
instances and ~100k paths.

Reference points from the paper (different hardware and dataset, not directly
comparable): graph build ~5 s + path selection ~2 s per instance; doc2vec
training 94 s for 30k paths; LOF 39 s.
