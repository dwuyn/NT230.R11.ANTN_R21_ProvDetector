# Limitations and threats to validity

## 1. Dataset

- Paper's enterprise benign traces (306 hosts, 3 months) and 1,150 malware
  traces are **not public**; all numbers here come from PKU-ASAL
  Simulated-Data, a lab/simulated APT dataset. They are a method reproduction,
  not a reproduction of F1=0.974.
- The paper's unit is a **victim program** (e.g. winword.exe abused by malware).
  PKU labels the **attack process start** (`is_warn` on `Process/Start`). We
  evaluate those labelled attack processes. A victim-level variant is future
  work; it would be substantially harder because the victim graph is mostly
  benign.
- Ubuntu (10.5 GB JSON) was downloaded but not ingested; no Linux claim.
- WS12 and W10 are single-host, short-lived captures. `H(e)` (number of hosts
  containing an edge) degenerates to one host, so the regularity score uses
  benign-instance frequency instead of host frequency. This is a documented
  adaptation, not the literal NoDoze formula.
- W10 merges several capture sessions and its `MSec` values are not globally
  monotone. Lifetimes are reconstructed per PID from `UniqueProcessKey`; a PID
  reused across sessions can still mis-associate events. WS12 is the primary
  trace; W10 is the secondary/cross-dataset check.

## 2. Labels

- `is_warn` labels process starts, not events; a path inherits its instance
  label. A benign parent that spawns a malicious child is still evaluated as
  benign, while the child is its own positive instance.
- Benign instances inside `anomaly.json` are test negatives; this makes the
  test stream realistic but also means threshold calibration on
  `benign.json` can shift when applied to a different workload mix.
- Attack chains are simulated; results are optimistic relative to real
  malware/Cuckoo traces.

## 3. Class imbalance and metrics

- Positives: 43/3,176 WS12 instances, 136/2,337 W10 instances.
  Full-test precision and F1 are low by construction; balanced F1 and
  AUROC/AUPRC are reported alongside. Accuracy is never used.
- The balanced test set samples as many benign instances as positives; FPR is
  also reported on the full benign test set.
- Path-level precision is dominated by the large benign path pool; a balanced
  path sample and AUROC/AUPRC are reported too.

## 4. Observed results and what they mean

- WS12→WS12: ProvDetector balanced F1 0.915, AUROC 0.942; whitelist 0.905;
  anomaly-score 0.869. The rule baseline fails (recall 0), as in the paper.
- W10→W10: ProvDetector balanced F1 0.773, recall 0.765, AUROC 0.798;
  frequency-only baseline balanced F1 0.854 / AUC 0.863, anomaly-score
  F1 0.850 / AUC 0.889. Pure regularity is at least as strong as the embedding
  on this trace.
- WS12→WS12: ProvDetector balanced F1 0.905, AUROC 0.943; frequency-only
  F1 0.935 / AUC 0.950. The same pattern: the simulated attack processes are
  rare by construction, so a frequency baseline is hard to beat in-dataset.
- Cross-dataset W10→WS12 flips the comparison: ProvDetector AUC 0.725,
  frequency-only AUC 0.209 (balanced F1 0.564 at 95% FPR). WS12→W10:
  ProvDetector AUC 0.571, frequency-only AUC 0.488, anomaly-score AUC 0.739.
  Embedding transfers better than raw frequency in one direction, but neither
  is deployment-grade.
- K ablation is non-monotone: K=5 beats K=20 on WS12 (F1 0.956 vs 0.905,
  FPR 0.093 vs 0.209); more paths add noisy candidates. K=50 was not completed.
- Random-path ablation does **not** degrade WS12: balanced F1 0.945
  (AUROC 0.903) versus rare paths 0.905/0.943. Because the positive label is
  the attack process itself, nearly every path from it is attack-related; the
  paper instead labels a mostly-benign victim program. This ablation therefore
  does not test the paper's path-selection claim fairly.
- The whitelist baseline degenerates on these file-heavy traces: almost every
  instance has at least one edge unique to it, so the novel-edge fraction is
  ~1 for most validation instances and the calibrated threshold flags nothing.
  We report it as a failed baseline and use the continuous frequency score
  instead.
- ProvNinja cross-check: on the published 50-dim features, benign FPR 5.2%,
  anomaly flag rate 21.8%, gadget flag rate 97.0%. The detector separates
  adversarial gadgets but only weakly separates the anomaly set.
- ProvNinja cross-check: on the published 50-dim features, benign FPR 5.2%,
  anomaly flag rate 21.8%, gadget flag rate 97.0%. The detector separates
  adversarial gadgets but only weakly separates the anomaly set.

## 5. Construct validity

- Provenance schema has no memory/registry/command-line edges; memory-only
  attacks are invisible (missing-telemetry FNs).
- Graph expansion depth 2 and edge cap 40k are engineering choices that may
  cut long chains or huge benign families.
- Path enumeration is time-ordered and beam-bounded; top-K is exact for
  terminal file/socket edges and approximate for long process chains.
- LOF path threshold calibrated to ≤5% instance FPR on benign validation; on
  a different workload mix this still produced 16–30% FPR on full test.
- Seeds fixed; gensim 4.4.0, sklearn 1.5.2, numpy 1.26.4 pinned. Doc2vec
  training is single-worker for determinism.

## 6. External validity

- Two Windows versions only; no enterprise scale, no months-long benign drift.
- No adversarial adaptation against this specific detector.
- Thresholds and K tuned on benign validation of the same dataset; cross-dataset
  performance shows this does not automatically transfer.
