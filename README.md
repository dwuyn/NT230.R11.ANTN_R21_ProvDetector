# NT230.R11.ANTN_R21_ProvDetector

Đồ án Research Track NT230 — đề tài **R21: Hunting stealthy malware bằng data provenance**.
Paper neo: *You Are What You Do: Hunting Stealthy Malware via Data Provenance Analysis*,
NDSS 2020 (DOI 10.14722/ndss.2020.24167).

> Đây là **tái lập phương pháp** trên trace công bố (PKU-ASAL Simulated-Data),
> **không** phải tái lập con số F1=0.974 trên dataset enterprise riêng của paper
> (dataset gốc không public).

## Trạng thái

- [x] T00 môi trường Python 3.12 + pin dependency (`requirements.txt`, `environment.lock`)
- [x] T03 tải + checksum PKU-ASAL W10/WS12, ProvNinja sample; data card
- [x] T04 parser ETW + ProvNinja paragraph → schema provenance, có test
- [x] T05 graph theo process instance + hình mẫu
- [x] T06 regularity score + top-K path hiếm
- [x] T07 baseline rule / whitelist / anomaly-score
- [x] T08 doc2vec PV-DM + LOF + cross-check ProvNinja
- [x] T09 protocol + leakage check
- [x] T10 chạy in-dataset WS12/W10 + cross-dataset + 3-seed variance + temporal/noise/K ablation
- [x] T11 ablation một phần: random paths, detector LOF/OCSVM/IF/RobustCov, K=5/20 (noise + K=50 chưa chạy)
- [x] T12 error analysis sơ bộ
- [x] T13 overhead (runtime từng run)
- [x] T14 case study (`docs/case-studies.md`, 4 case)
- [x] T15 README/env/checksum/vm-notes
- [ ] T16 báo cáo + slide

## Quick start

```bash
make setup          # uv venv 3.12 + pip install -r requirements.txt
make env            # in phiên bản, kiểm tra pin
make test           # 8 unit test
make ingest         # parse 4 Windows JSONL -> data/clean/*.parquet
make ubuntu         # parse Ubuntu Sysdig (10.5 GB, ~4 phút)
make ws12           # experiment WS12 -> WS12
make w10            # experiment W10  -> W10
make cross          # W10 -> WS12 và WS12 -> W10
make check          # leakage check trên cache
```

Hoặc chạy một cấu hình:

```bash
.venv/bin/python -m src.experiment --train WS12 --test WS12 --seed 20261025
```

Kết quả: `experiments/results/*.json`, `*_predictions.csv`;
bảng tổng hợp: `python experiments/format_results.py experiments/results/*_k20_*.json`.
Hình: `experiments/figs/`.

## Pipeline

```mermaid
flowchart LR
    A[ETW JSONL] --> B[src/ingest<br/>lifecycle + normalize]
    B --> C[src/graph<br/>G(p): process/file/socket]
    C --> D[src/select<br/>regularity score + top-K paths]
    D --> E[src/embed<br/>doc2vec PV-DM 100d]
    E --> F[src/detect<br/>LOF + threshold t]
    C --> G[src/baseline<br/>rule / whitelist / score]
    F --> H[experiments/results]
    G --> H
```

- **Instance** = một `Process/Start`…`Process/Stop`, ghép bằng `UniqueProcessKey`;
  graph mở rộng tới con/cháu depth 2 để bắt chain `victim → shell → payload`.
- **Regularity** `R(e)=freq_instances(e)·OUT(src)·IN(dst)` (thích nghi cho
  single-host; ghi rõ trong `experiments/protocol.md`).
- **Split** theo instance: 70/15/15 benign, anomaly chỉ test.
- **Threshold** LOF calibrate trên benign validation để FPR instance ≤ 5%;
  t=3 (quét 1…5).

## Kết quả chính (seed 20261025, K=20, t=3)

| Train → Test | ProvDetector F1 (balanced) | AUROC | Frequency-only F1 | Frequency AUROC |
|---|---|---|---|---|
| WS12 → WS12 | 0.905 | 0.943 | 0.935 | 0.950 |
| W10 → W10 | 0.773 | 0.798 | 0.854 | 0.863 |
| W10 → WS12 | 0.603 | 0.725 | 0.564 | 0.209 |
| WS12 → W10 | 0.675 (FPR 0.96) | 0.572 | 0.667 (FPR 1.0) | 0.488 |

Đọc đúng: qua 3 seed, ProvDetector F1 = **0.928 ± 0.021**, frequency-only
**0.925 ± 0.017** — chênh lệch nhỏ hơn dao động seed, nên **không thể kết luận
phương pháp nào hơn** in-dataset. Embedding chỉ chuyển tốt hơn ở chiều
W10→WS12. Random-path ablation cũng không giảm F1 vì nhãn là chính attack
process (xem `ablation.md`, `seed-variance.md`). Đây là kết quả âm tính trung
thực, không phải tái lập F1=0.974.

- Bảng đầy đủ: `experiments/results/main-table.md`, `ablation.md`,
  `robustness.md` (temporal/noise/K), `ubuntu.md` (heuristic-label Linux).
- Cross-check ProvNinja: `experiments/results/provninja-check.json`.
- Error analysis: `docs/error-analysis.md`.

## Dữ liệu

| Trace | Benign | Anomaly | Malicious starts |
|---|---|---|---|
| WS12 | 5,033 inst / 7.19M edges | 3,180 / 1.08M | 43 |
| W10 | 6,201 / 6.02M | 2,472 / 1.88M | 136 |
| Ubuntu (Sysdig, heuristic labels) | 69,300 / 9.0M | 9,541 / 1.28M | 19 |

Xem `docs/data-card.md`, checksum `data/manifest.csv`.
Ubuntu đã parse với nhãn heuristic từ annotation gốc; chưa dùng cho metric chính.

## Tài liệu

- `docs/R21-research-synthesis.md` — phân tích paper, dữ liệu, rubric.
- `docs/R21-work-plan.md` — kế hoạch T00–T16.
- `docs/threat-model.md`, `docs/label-book.md` — hạng mục 1.
- `docs/data-card.md`, `docs/checksums.md` — hạng mục 3.
- `experiments/protocol.md` — protocol khóa.
- `docs/limitations.md`, `docs/error-analysis.md`, `experiments/results/error-analysis-*.md` — hạng mục 4.
- `experiments/results/main-table.md`, `ablation.md`, `robustness.md`, `confusion-matrices.md`, `seed-variance.md`, `signal-noise.md`, `path-sanity.md` — bảng kết quả.
- `docs/requirements-audit.md` — đối chiếu đề bài/rubric và danh sách gap.
- `docs/venue-note.md` — NDSS 2020 vs đề "NDSS 2025".

## An toàn

Chỉ ingest trace công bố; **không tải/chạy mẫu malware**, không C2, không payload.
ProvNinja (BSD-3-Clause) và PKU-ASAL (research-only MIT) dùng cho mục đích học thuật.
