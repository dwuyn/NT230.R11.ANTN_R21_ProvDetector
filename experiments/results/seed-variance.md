# Seed variance — WS12→WS12, K=20, t=3

Ba seed thay đổi split instance (train/val/test) và seed doc2vec/LOF.

| Seed | Prov F1 | Prov FPR | Prov full F1 | Prov AUROC | Freq F1 | Freq FPR | Freq AUROC |
|---|---|---|---|---|---|---|---|
| 20261025 | 0.905 | 0.209 | 0.118 | 0.943 | 0.935 | 0.140 | 0.950 |
| 1 | 0.945 | 0.116 | 0.133 | 0.942 | 0.905 | 0.209 | 0.950 |
| 2 | 0.935 | 0.140 | 0.140 | 0.955 | 0.935 | 0.140 | 0.951 |

| Metric | Mean | Std (sample) |
|---|---|---|
| Prov F1 | 0.928 | 0.021 |
| Prov FPR | 0.155 | 0.048 |
| Prov full F1 | 0.130 | 0.011 |
| Prov AUROC | 0.947 | 0.007 |
| Freq F1 | 0.925 | 0.017 |
| Freq FPR | 0.163 | 0.040 |
| Freq AUROC | 0.950 | 0.001 |

- Các seed: 20261025, 1, 2. Std là độ lệch chuẩn mẫu (n=3), không phải CI 95%.
- ProvDetector dao động F1 0.933–0.966; frequency-only 0.905–0.935. Chênh lệch giữa hai phương pháp nhỏ hơn độ dao động seed, nên **không thể kết luận phương pháp nào hơn** trên trace này.
