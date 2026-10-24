# Requirements audit — R21 vs đề bài và rubric

> Nguồn: `docs/source/NT230-FinaL-topics-final-v22.sept2026.xlsm`,
> sheet `Research Track` dòng 25 (R21) và sheet `Research Track - Rubric`.
> Audit ngày 2026-10-25, đối chiếu trực tiếp với artifact trong repo.
> Kết luận ngắn: **kỹ thuật đã đạt mức "Đạt" cho HM1–HM4; HM5 chưa đủ vì thiếu
> báo cáo + slide; chưa nên nộp.**

## 1. Yêu cầu đề tài R21

Đề yêu cầu: tái lập data-provenance hunting trên trace công bố/workload mô
phỏng; so sánh stealthy vs benign theo **lineage, tần suất, chuỗi hoạt động,
mức nhiễu**; sản phẩm gồm mã thu thập/chuẩn hóa provenance, schema, kịch bản
lặp lại, baseline, kết quả detection/overhead, case study trace, đánh giá FP từ
ứng dụng bình thường, giới hạn telemetry/privacy/drift/giả định stealth.

| Yêu cầu | Minh chứng | Trạng thái |
|---|---|---|
| Pipeline quan hệ process–file–network | `src/ingest`, `src/graph`, schema 3 entity/5 relation | ✅ |
| Trace công bố / workload mô phỏng | PKU-ASAL WS12 + W10; ProvNinja cross-check | ✅ |
| So sánh lineage | `src/graph` family + case study chain `cmd→agent→powershell` | ✅ |
| So sánh tần suất | `FrequencyDB`, `frequency_score`, whitelist | ✅ |
| So sánh chuỗi hoạt động | top-K causal path + doc2vec | ✅ |
| Mức nhiễu | `experiments/results/signal-noise.md` (common-edge fraction) | ✅ phân tích; chưa có noise-injection ablation |
| Mã **thu thập** provenance | Chỉ có parser/chuẩn hóa trace công bố; **không có collector Sysmon/ETW** | ⚠️ ingest-first, đã ghi rõ |
| Schema | `src/ingest/schema.py`, `docs/data-card.md` | ✅ |
| Kịch bản lặp lại | `experiments/protocol.md`, `Makefile`, `scripts/ingest_all.sh`, seed | ✅ |
| Baseline | rule, whitelist, frequency, anomaly-score, 3 detector phụ | ✅ |
| Kết quả detection | `main-table.md`, `confusion-matrices.md` | ✅ |
| Overhead | `experiments/results/overhead.md` (runtime + storage) | ✅ mức tổng; chưa per-stage |
| Case study trace | `docs/case-studies.md` + 4 hình graph | ✅ |
| FP từ ứng dụng bình thường | `docs/error-analysis.md` (NGenTask, svchost, pgAdmin, Chrome) | ✅ |
| Giới hạn telemetry | `docs/threat-model.md` §2, `docs/limitations.md` §5 | ✅ |
| Privacy | `docs/data-card.md` §8, `docs/limitations.md` | ✅ mức mô tả |
| Workload drift | `docs/limitations.md` §6, cross-dataset kết quả | ✅ |
| Giả định stealth | `docs/threat-model.md` §4 | ✅ |
| Venue | Đề ghi NDSS 2025; paper thực tế NDSS 2020 — đã verify và ghi `docs/venue-note.md` | ⚠️ cần GV xác nhận |

## 2. Rubric 5 hạng mục

### HM1 — Hiểu đối tượng mã độc và câu hỏi NC (2.0)

- Có: threat model, concept map, bảng TTP→provenance, label book, 4 RQ,
  benign/malicious/rare-but-benign/missing-telemetry.
- Thiếu so với mức khá/giỏi: **family/variant** và **điều kiện kích hoạt**
  không có trong dataset (nhãn chỉ là `is_warn` trên process start); không thể
  phân tích family như paper.
- Kết luận: **Đạt**; chưa đủ "khá/giỏi" ở mục family/trigger.

### HM2 — Tái lập phương pháp (3.0)

- Có: pipeline đầy đủ, config, seed, env lock, protocol, leakage check, 4 cấu
  hình, baseline, ablation random/detector/K, bảng so sánh paper (ghi rõ khác
  dataset).
- Thiếu: K=50, noise injection; chưa có notebook (thay bằng script + JSON log).
- Đã có 3-seed variance (`experiments/results/seed-variance.md`): ProvDetector
  F1 0.928±0.021, frequency 0.925±0.017.
- Kết luận: **Đạt**; "khá/giỏi" gần đủ, còn ablation noise/K=50.

### HM3 — Dataset và chất lượng dữ liệu (2.0)

- Có: manifest + SHA-256, data card, schema, label guide, duplicate audit,
  leakage control, cross-dataset split, license/ethics.
- Thiếu: không đóng góp dataset mới (đề cho phép optional); **temporal split**
  chưa làm (chỉ cross-dataset); Ubuntu chưa parse.
- Kết luận: **Đạt**; temporal split là gap rõ.

### HM4 — Thực nghiệm, phân tích, phản biện (2.5)

- Có: P/R/F1/FPR, confusion matrix, error taxonomy, FP/FN cụ thể, limitations,
  threats-to-validity, cross-dataset, case study, signal/noise analysis.
- Đã có seed variance (3 seed) và cross-dataset; thiếu temporal evaluation và
  case study chưa đưa hết vào báo cáo.
- Kết luận: **Đạt**; "khá/giỏi" còn temporal + báo cáo.

### HM5 — Tái lập, đạo đức, trình bày (0.5)

- Có: README, env lock, checksum, VM notes, test, hình, repo public, không
  malware.
- Thiếu: **`docs/report.md` và `slides/` chưa có**; không có container
  (chỉ venv); chưa có người thứ 2 chạy lại.
- Kết luận: **CHƯA ĐẠT ĐẦY ĐỦ** — đây là việc bắt buộc trước khi nộp.

## 3. Các tuyên bố cần tránh

- **Không** nói "tái lập F1=0.974" hoặc "tái lập kết quả paper": dataset khác,
  nhãn khác, kết quả khác.
- **Không** nói frequency-only thua ProvDetector: qua 3 seed nó ngang
  (0.925 ± 0.017 vs 0.928 ± 0.021, chênh lệch trong sai số); embedding chỉ
  chuyển tốt hơn ở W10→WS12.
- **Không** nói random paths kém: ablation cho thấy không giảm F1, vì nhãn là
  attack process.
- **Không** nói cross-dataset hoạt động: WS12→W10 FPR 96%.

## 4. Việc bắt buộc còn lại

1. `docs/report.md` theo đúng 5 hạng mục + bảng cross-ref artifact.
2. `slides/` 12–15 slide + demo.
3. Container (Dockerfile) hoặc hướng dẫn venv đủ rõ; đã có venv.
4. (Khuyến nghị) temporal split, noise injection, K=50, parse Ubuntu.

## 5. Kết luận

Đồ án đã có **pipeline thật, dữ liệu thật, kết quả thật, phân tích lỗi thật**.
Phần kỹ thuật đủ để bảo vệ ở mức Đạt; phần trình bày (report/slide) và một số
kiểm chứng thống kê vẫn còn thiếu. Không có artifact nguy hiểm hoặc dữ liệu
cá nhân trong repo.
