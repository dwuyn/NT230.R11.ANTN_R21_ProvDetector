# R21 Work Plan

> Kế hoạch làm việc cho **nhóm sinh viên** làm đồ án R21 — Research Track NT230 (NT230.R11.ANTN, Học kỳ I 2026–2027).
> Paper neo: ProvDetector — *You Are What You Do*, **NDSS 2020** (DOI 10.14722/ndss.2020.24167; file đề ghi "NDSS 2025" là sai năm, đã verify — xem synthesis §3.1).
> Nguồn nội dung kỹ thuật: `docs/R21-research-synthesis.md` (dưới đây gọi tắt là **Syn**).

## Goal

Tái lập pipeline phát hiện stealthy malware bằng data provenance theo ProvDetector trên **trace công bố** (dataset chính PKU-ASAL/Simulated-Data, kiểm chứng chéo ProvNinja), với 2 baseline bắt buộc + ablation + error analysis + overhead measurement + case study, báo cáo trung thực theo 5 hạng mục rubric Research Track. **Không claim tái lập F1=0.974** (dataset enterprise của paper không public — Syn §5.1); mục tiêu là chứng minh pipeline hoạt động end-to-end, hiểu tín hiệu nào phân biệt được (lineage/tần suất/chuỗi/nhiễu), và phân tích giới hạn.

## Phạm vi chốt (in / out)

**IN:**
- Ingest trace công bố: PKU-ASAL/Simulated-Data [Syn §5.4] (chính) + ProvNinja sample-enterprise-data (cross-check); phương án B ATLAS / DARPA TC E3 THEIA 1r.
- Pipeline: schema normalize → graph build → rareness path selection (regularity score, K=20) → doc2vec PV-DM (100-dim) → LOF → threshold t.
- Baselines: (1) rule heuristic "UI program không spawn script interpreter"; (2) whole-graph (graph2vec hoặc path ngẫu nhiên) hoặc frequency-only whitelist; (3, nên có) anomaly-score thuần.
- Metric: P/R/F1/FPR (path-level + graph-level), confusion matrix, overhead (storage, runtime), CI theo seed.
- Ablation: bỏ path selection / đổi K / thêm nhiễu / thay detector (OCSVM, IsolationForest, RobustCovariance) / Path Nodes Averaging.
- Error analysis + taxonomy (Syn §7.3); FP từ workload benign (admin script, updater, download); case study 2–3 kịch bản vô hại (Syn §8).
- Overhead measurement trên máy lab.
- README, env lock, checksum, VM notes, báo cáo + slide theo 5 hạng mục.

**OUT (không làm — danh sách đầy đủ cuối file):**
- Chạy/tải mẫu malware thật; viết payload/injection PoC; C2; evasion 3 biến thể (Dev Track); claim SOTA/F1=0.974; collector production; online detection (future work của chính paper).

## Architecture (1 đoạn)

Ingest trace (PKU-ASAL JSON / ProvNinja CSV) → parser chuẩn hóa về schema đồ án (entity: process/file/socket; edge: src→dst, rel, time; chỉ process là src) → xây provenance graph theo process instance → chấm regularity score từng edge bằng frequency database của tập benign (công thức NoDoze/ProvDetector, Syn §3.3) → chọn top-K=20 causal path hiếm nhất (K longest path trên DAG) → mỗi path thành "câu" (node=noun, edge=verb) → doc2vec PV-DM 100-dim (train chỉ trên benign) → LOF chấm từng path → ≥ t path lạ thì instance malicious. Baselines dùng chung khối graph/path: rule heuristic trên graph; whole-graph embedding (graph2vec) và frequency whitelist song song để đối chiếu.

```mermaid
flowchart LR
    subgraph DATA[Data]
        P1[(PKU-ASAL<br/>JSON lines)] --> IG[src/ingest<br/>parser chuẩn hóa]
        P2[(ProvNinja<br/>causal paragraphs)] --> IG
    end
    IG --> SCH[(event stream chuẩn hóa<br/>src,dst,rel,time)]
    SCH --> GB[src/graph<br/>build G(p) theo instance]
    GB --> SEL[src/select<br/>regularity score<br/>top-K=20 path hiếm]
    GB --> BL1[src/baseline<br/>rule heuristic<br/>whole-graph / whitelist]
    SEL --> EMB[src/embed<br/>doc2vec PV-DM 100-dim]
    EMB --> DET[src/detect<br/>LOF + threshold t]
    BL1 --> MET
    DET --> MET[(P/R/F1/FPR<br/>overhead, CI)]
    MET --> REP[báo cáo 5 hạng mục<br/>+ error analysis]
```

## Map rubric → artifact

Điểm hạng mục lấy từ sheet "Research Track - Rubric": 1→2.0; 2→3.0; 3→2.0; 4→**2.5**; 5→0.5. (Ô điểm hạng mục 4 trong Excel bị lệch format serial `46144`; tổng 4 hạng mục còn lại = 7.5 → hạng mục 4 lấy 2.5 cho đủ 10 — ghi chú này phải có trong báo cáo.)

| Hạng mục (điểm) | Artifact file | Tiêu chí ĐẠT | Tiêu chí KHÁ/GIỎI |
|---|---|---|---|
| 1. Hiểu đối tượng mã độc & câu hỏi NC (2.0) | `docs/threat-model.md`; concept map + bảng TTP→provenance + định nghĩa nhãn (mục 2 trong Syn) | Mô tả đúng stealthy malware (fileless/LOLBin/injection), mục tiêu, hành vi, bề mặt quan sát (process/file/socket; KHÔNG memory/registry), threat model, 4 câu hỏi NC đo được | Phân biệt benign/malicious, TTP map đúng ATT&CK (T1059/T1055/T1218/S0160…), chỉ ra điểm nhầm lẫn (admin script, updater, download) |
| 2. Tái lập phương pháp (3.0) | `src/` (ingest, graph, select, embed, detect, baseline) + `experiments/results/main-table.md` + `experiments/protocol.md` | Pipeline end-to-end chạy được: dữ liệu, tiền xử lý, feature/model, baseline, protocol, metric; ghi rõ đâu là tái lập thuật toán vs kết quả khác | Bảng đối chiếu từng con số với paper (path-level 0.974, graph-level t=3 → 0.978, baselines Bảng III–V); ablation K/noise/detector; seed cố định + phiên bản lib |
| 3. Dataset & chất lượng dữ liệu (2.0) | `docs/data-card.md` + `docs/dataset-analysis.md` + `data/manifest.csv` (checksum) | Phân tích sâu dataset thay thế: nguồn, license, schema, nhãn, split theo instance, leakage, bias, imbalance, giới hạn (vì không đóng góp dữ liệu) | Data card đầy đủ, checksum, temporal/cross-scenario split, phân tích label noise (DARPA UUID nếu dùng) |
| 4. Thực nghiệm, phân tích, phản biện (2.5) | `experiments/results/` (bảng, confusion matrix) + `docs/error-analysis.md` + `docs/limitations.md` | Báo P/R/F1/FPR, error taxonomy, FP/FN phân tích, trường hợp hệ thống kém (Syn §7.5) | CI theo seed, cross-dataset (PKU-ASAL vs ProvNinja/ATLAS), threats-to-validity 4 loại |
| 5. Tái lập, đạo đức, trình bày (0.5) | `README.md` + `environment.lock` + `docs/checksums.md` + `docs/vm-notes.md` + `slides/` | Người khác chạy lại được ở mức hợp lý; không mẫu nguy hiểm; license ghi rõ | Container/VM snapshot, README từng bước, demo tái chạy độc lập (run từ đầu tới bảng kết quả) |

## Lịch theo tuần (giả định 8 tuần; chỉnh theo lịch môn)

| Tuần | Task | Mốc (milestone) |
|---|---|---|
| 1 | T01 | Paper + related work freeze; synthesis được GV duyệt hướng |
| 1–2 | T02 | `docs/threat-model.md` v1 |
| 2 | T00, T03 | Env chạy; dataset tải xong + data card v1 |
| 3 | T04, T05 | Parser ingest xong; 1 graph visualized |
| 4 | T06, T07 | Path selection + rareness chạy; 2 baseline có số |
| 5 | T08, T09 | doc2vec+LOF chạy; protocol khóa (split/seed/metric) |
| 6 | T10, T11 | Bảng kết quả chính + đối chiếu paper; ablation xong |
| 7 | T12, T13, T14 | Error analysis, overhead, case study viết xong |
| 8 | T15, T16 | Repo sạch, README/env/checksum; báo cáo + slide; diễn tập |

## Tasks

> Mỗi task: mã, hạng mục rubric, mục tiêu, input, checklist, output, kiểm tra "xong", phụ thuộc, rủi ro + hạ fidelity, effort (S/M/L).
> Người phụ trách gợi ý: **A** = data/pipeline, **B** = model/experiment, **C** = doc/report — nhóm tự gán.

### T00 — Thiết lập môi trường (S)
- **Rubric:** 5.
- **Mục tiêu:** mọi thành viên chạy được cùng môi trường Python, tái lập được từ đầu.
- **Input:** máy cá nhân/VM; quyết định dataset ở T03 chưa cần.
- **Việc cụ thể:**
  - [ ] Tạo repo (private hoặc theo quy định môn), branch `main` + gitignore.
  - [ ] `environment.lock` (conda env export) + `requirements.txt` pin: gensim, scikit-learn, pandas, numpy, networkx, matplotlib (t-SNE), pyarrow/json.
  - [ ] Thư mục `src/{ingest,graph,select,embed,detect,baseline}`, `data/`, `experiments/{protocol.md,results/}`, `docs/`.
  - [ ] Script `scripts/seed.sh`: cố định `PYTHONHASHSEED`, seed numpy/sklearn/gensim; in phiên bản lib.
- **Output:** `environment.lock`, `requirements.txt`, skeleton repo.
- **Xong khi:** thành viên khác chạy `pip install -r requirements.txt` + `python scripts/check_env.py` in đúng phiên bản; không có lỗi.
- **Phụ thuộc:** không.
- **Rủi ro:** trôi phiên bản gensim làm doc2vec khác vector → pin cứng; hạ fidelity: dùng docker image có sẵn python:3.11.

### T01 — Đọc paper + related work freeze (M)
- **Rubric:** 1, 2.
- **Mục tiêu:** toàn nhóm nắm đúng pipeline paper; khóa danh sách related work + baseline sẽ đối chiếu.
- **Input:** PDF `docs/24167-paper.pdf` (đã có trong repo), slides, `docs/R21-research-synthesis.md` §3–§4 (đã viết sẵn).
- **Việc cụ thể:**
  - [ ] Mỗi thành viên đọc paper + trình bày lại 1 stage (graph building / path selection / embedding / detection) trong buổi họp.
  - [ ] Đối chiếu số liệu Bảng II–V của paper với synthesis (path-level P 0.959/R 0.991/F1 0.974; graph-level t=3 0.957/1/0.978; baselines blacklist 0.07 / whitelist 0.78 / anomaly-score 0.50 / graph2vec 0.601 / PathNodesAveraging 0.924 / OCSVM 0.739 / IF 0.627 / RobustCov 0.558).
  - [ ] Freeze: danh sách 11 paper related work (Syn §4) + 3 re-implementation tham chiếu (provninja, PKU-ASAL, eagle-eye) + quyết định dùng regularity score theo NoDoze.
  - [ ] Ghi chú mâu thuẫn venue NDSS 2020 vs đề "NDSS 2025" vào `docs/venue-note.md` (đã có ở Syn §3.1).
- **Output:** biên bản họp `docs/meetings/01-paper-freeze.md`; checklist đã tick ở trên.
- **Xong khi:** cả nhóm trả lời được "vì sao whole-graph thất bại (70% path không phân biệt được) và vì sao LOF thắng OCSVM/IF/RobustCov" mà không nhìn tài liệu.
- **Phụ thuộc:** không.
- **Rủi ro:** hiểu sai công thức regularity score (IN/OUT stable windows) → cross-check với provninja code; hạ fidelity: chấp nhận enumerate path có giới hạn độ dài thay vì Eppstein (Syn §6.3 F2).

### T02 — Threat model + concept map + label book (M)
- **Rubric:** 1.
- **Mục tiêu:** khóa hiểu đối tượng mã độc + câu hỏi NC; thành tài liệu chấm điểm hạng mục 1.
- **Input:** Syn §2 (đã viết: TTP table, concept map, threat model, label book), MITRE ATT&CK verify (Syn §2.6).
- **Việc cụ thể:**
  - [ ] Tạo `docs/threat-model.md`: mục tiêu attacker, điều kiện kích hoạt, bề mặt quan sát, giả định TCB, out-of-scope (traditional file-drop malware, side channel).
  - [ ] Chép/hoàn thiện concept map mermaid + bảng TTP→provenance từ Syn §2.6–2.7 (ghi nguồn ATT&CK từng ID).
  - [ ] `docs/label-book.md`: 4 nhãn benign / rare-but-benign / stealthy-malicious / missing-telemetry + quy tắc gán nhãn khi ingest (vd event thuộc scenario tấn công = malicious theo ground truth file).
  - [ ] Chốt 4 câu hỏi NC (RQ1–RQ4) + hypotheses H1–H5 (Syn §7.1) vào đầu protocol.
- **Output:** `docs/threat-model.md`, `docs/label-book.md`.
- **Xong khi:** GV/nhóm review 1 vòng; mọi TTP trong bảng có ID + URL nguồn.
- **Phụ thuộc:** T01.
- **Rủi ro:** nhầm ATT&CK ID (vd T1093 đã revoke → T1055.012; certutil là S0160 không phải T1218 sub) → dùng đúng bảng Syn §2.6 đã verify; hạ fidelity: không cần thêm TTP ngoài bảng.

### T03 — Chọn và lock dataset; data card; license (M)
- **Rubric:** 3.
- **Mục tiêu:** tải thành công dataset, verify checksum + license, viết data card v1.
- **Input:** Syn §5 (đã khảo sát: PKU-ASAL ~350MB research-only MIT; ProvNinja ~29MB BSD-3; phương án B ATLAS ~733MB Apache-2.0; DARPA TC E3 mirror ~4.8GB public domain).
- **Việc cụ thể:**
  - [ ] Tải PKU-ASAL/Simulated-Data (Git LFS: `SimulatedW10.zip` ~133.7MB, `SimulatedUbuntu.zip` ~105.7MB, `SimulatedWS12.zip` ~84.1MB) về `data/raw/`.
  - [ ] Tải ProvNinja `sample-enterprise-data/` (paragraph CSV + feature vector CSV) về `data/raw-provninja/`.
  - [ ] Tính sha256 → `data/manifest.csv`; ghi license từng nguồn (research-only MIT → KHÔNG dùng thương mại, chỉ đồ án; BSD-3-Clause).
  - [ ] `docs/data-card.md` theo skeleton Syn §5.5: nguồn, ngày tải, checksum, môi trường thu (ETW/Sysdig), schema field thật (đọc 100 dòng đầu mỗi file), nhãn ground truth (A1–A37), split dự kiến, statistics ban đầu.
  - [ ] Kiểm tra an toàn: dataset là trace công bố, không chứa mẫu nhị phân malware; xác nhận không có bước nào phải chạy malware (ghi vào data-card mục ethics).
  - [ ] Nếu PKU-ASAL hỏng: kích hoạt phương án B (ATLAS) và ghi lý do.
- **Output:** `data/raw/` + `data/manifest.csv` + `docs/data-card.md` v1.
- **Xong khi:** `sha256sum -c data/manifest.csv` pass; data-card có đủ 9 mục skeleton; nhóm trả lời được "đơn vị split chống leakage của bộ data này là gì".
- **Phụ thuộc:** T00, T01.
- **Rủi ro:** link đổi/quota (scout xác nhận sống 10/2026 nhưng có thể đổi) → dùng mirror/ATLAS (bảng phương án B cuối file); hạ fidelity: chỉ dùng 1 bộ (W10) thay vì 3 bộ.

### T04 — Schema + parser ingest (L)
- **Rubric:** 2.
- **Mục tiêu:** mọi nguồn trace về đúng 1 schema đồ án (Syn §6.1); đây là phần code lớn nhất.
- **Input:** schema Syn §6.1; data từ T03.
- **Việc cụ thể:**
  - [ ] Định nghĩa schema event JSONL: `{ts, host, src_entity, src_attrs, dst_entity, dst_attrs, rel, scenario_label}` với rel ∈ {START, END, READ, WRITE, EXECUTE, CONNECT}; chỉ process là src.
  - [ ] `src/ingest/parse_pku.py`: JSON lines → schema; map datatype/event_id → rel; giữ cmdline, pid, host.
  - [ ] `src/ingest/parse_provninja.py`: causal paragraph CSV → schema (tách token PROC_CREATE/READ_WRITE → rel).
  - [ ] `src/ingest/normalize.py`: path abstraction (`*:/USERS/*/...`), socket abstraction (bỏ IP nội bộ), chuẩn hóa extension, loại host/PID khỏi nhãn node khi tạo câu path.
  - [ ] Unit test nhỏ: 5 event mẫu mỗi nguồn → output đúng schema.
  - [ ] Ghi số liệu: events/host, phân bố rel — vào data-card (cập nhật).
- **Output:** `src/ingest/` + `data/clean/*.jsonl`.
- **Xong khi:** cả 2 nguồn parse xong không lỗi trên toàn bộ dữ liệu; số event đếm được khớp giữa 2 lần chạy (deterministic).
- **Phụ thuộc:** T03.
- **Rủi ro:** schema thật của PKU-ASAL khác mô tả (field ẩn/thiếu) → đọc mẫu + liên hệ repo issues; hạ fidelity: bỏ nguồn ProvNinja, chỉ PKU-ASAL.

### T05 — Graph build + visualization 1 case (M)
- **Rubric:** 2.
- **Mục tiêu:** dựng provenance graph theo process instance, vẽ được 1 graph có nhãn.
- **Input:** `data/clean/*.jsonl` (T04).
- **Việc cụ thể:**
  - [ ] `src/graph/build.py`: group event theo (host, pid, khung thời gian) → G(p) = <V,E>; node process/file/socket + thuộc tính; edge có rel+time; chỉ giữ liên kết causal (src/dst thuộc V).
  - [ ] `src/graph/viz.py`: export DOT/matplotlib cho 1 instance benign và 1 instance thuộc scenario tấn công (chọn nhỏ < 200 node).
  - [ ] Lưu `experiments/figs/graph-sample-benign.png` + `graph-sample-attack.png` + đối chiếu thủ công với ground truth A1–A37.
- **Output:** `src/graph/` + 2 hình graph.
- **Xong khi:** mắt thường thấy chuỗi tấn công (vd shell spawn chain) hiện diện trong graph attack và vắng mặt ở graph benign; hình cho vào báo cáo hạng mục 2.
- **Phụ thuộc:** T04.
- **Rủi ro:** graph 1 process dài ngày quá to (daemon) → giới hạn khung thời gian ±30 phút quanh ground truth (giống cách TAPAS mô tả segmentation, nhưng đơn giản hơn); hạ fidelity: vẽ bằng networkx thuần, không DOT.

### T06 — Path extraction + rareness scoring (L)
- **Rubric:** 2.
- **Mục tiêu:** tái lập đúng khâu chọn path của paper (regularity score + top-K=20).
- **Input:** Syn §3.3 công thức; graph từ T05.
- **Việc cụ thể:**
  - [ ] `src/select/regularity.py`: frequency database từ **tập benign train** (đếm event theo rel+loại node sau abstraction); IN/OUT stability theo time windows (chọn n windows, ghi tham số).
  - [ ] `src/select/paths.py`: sinh causal path (ràng buộc `dst==next.src` và `time` tăng dần); mức F2: enumerate có giới hạn độ dài ≤ 4–5 hop (Syn §6.3); chấm R(π)=∏R(e); trả top-K=20.
  - [ ] Đối chiếu thử: chạy trên 10 instance, xem top paths có trùng vùng ground truth không (định tính).
  - [ ] (Nếu dư thời gian — F3) implement K longest path trên DAG (split node theo thời gian) — ghi rõ đã làm hay chưa.
- **Output:** `src/select/` + bảng top-K mẫu trong `experiments/results/path-sanity.md`.
- **Xong khi:** top-K của instance attack chứa ≥ 1 path nằm trong ground truth scenario; path của benign instance không trùng ground truth.
- **Phụ thuộc:** T05.
- **Rủi ro:** enumerate bùng nổ trên graph to → chặn độ dài + chỉ mở rộng từ node có in-degree thấp; hạ fidelity: rareness = tần suất path đơn thuần (F1) nếu kẹt.

### T07 — Baseline heuristic + whole-graph/frequency baseline (M)
- **Rubric:** 2, 4.
- **Mục tiêu:** có 2 baseline bắt buộc để chứng minh pipeline chính tốt hơn.
- **Input:** graph từ T05; Syn §6.5.
- **Việc cụ thể:**
  - [ ] `src/baseline/rule_heuristic.py`: "UI-heavy process (theo danh sách app) spawn script interpreter (cmd/powershell/wscript…)" → alert; đo P/R/F1.
  - [ ] `src/baseline/whitelist.py`: event xuất hiện > p% benign instances là whitelist; quét p ∈ {1,2,3,5,10}; báo F1 tốt nhất (paper: 0.78 @ p=3).
  - [ ] `src/baseline/whole_graph.py`: (a) path ngẫu nhiên thay path hiếm (mô phỏng graph2vec failure mode) và/hoặc (b) graph2vec thư viện — chọn 1, ghi rõ.
  - [ ] (Nên) `src/baseline/anomaly_score.py`: regularity score thuần làm detector (paper F1 0.50).
- **Output:** `src/baseline/` + số P/R/F1 từng baseline vào `experiments/results/baselines.md`.
- **Xong khi:** ít nhất 2 baseline có số; baseline rule có recall thấp hơn hẳn pipeline chính (kỳ vọng ≈0.07 như paper).
- **Phụ thuộc:** T06 (dùng chung graph + frequency db).
- **Rủi ro:** baseline mạnh bất ngờ (nếu data dễ) → vẫn giữ, phân tích vì sao trong error analysis; hạ fidelity: bỏ graph2vec, chỉ path ngẫu nhiên.

### T08 — Embedding + novelty detector (M)
- **Rubric:** 2.
- **Mục tiêu:** tái lập doc2vec PV-DM + LOF đúng paper.
- **Input:** top-K path từ T06 (chỉ train trên benign).
- **Việc cụ thể:**
  - [ ] `src/embed/sentence.py`: path → câu `Process:X rel File:Y ...` (đúng Syn §3.3).
  - [ ] `src/embed/doc2vec.py`: gensim Doc2Vec PV-DM, dim=100, epochs 100, window phù hợp (thử 3–5); train trên path benign train.
  - [ ] `src/detect/lof.py`: sklearn LOF (novelty=True) train trên benign embeddings; dự đoán từng path; threshold t ∈ {1..5} quét.
  - [ ] Thêm 3 detector so sánh: OneClassSVM (nu 0.1, rbf, gamma 0.5 — đúng paper), IsolationForest, RobustCovariance (contamination 0.04) — rẻ, nên làm để có Bảng V của riêng mình.
  - [ ] Cross-check: chạy lại `provdetector.py` của ProvNinja trên feature CSV của họ, xác nhận quy trình LOF của nhóm cho output tương đương (sanity, không copy code).
- **Output:** `src/embed/` + `src/detect/` + checkpoint model.
- **Xong khi:** embedding 100-dim sinh được cho mọi path; LOF dự đoán path attack có score bất thường cao hơn path benign trung bình (kiểm định sơ bộ).
- **Phụ thuộc:** T06.
- **Rủi ro:** gensim PV-DM khó tái lập chính xác version 2019 → pin phiên bản + ghi rõ "tái lập khái niệm, không bit-identical"; hạ fidelity: nếu doc2vec không hội tụ trên data nhỏ → dùng Path Nodes Averaging (paper F1 0.924) làm phương án thay.

### T09 — Experiment protocol: split, seed, metric (S–M)
- **Rubric:** 2.
- **Mục tiêu:** khóa protocol chống leakage trước khi chạy thí nghiệm chính.
- **Input:** Syn §6.7; label book T02.
- **Việc cụ thể:**
  - [ ] `experiments/protocol.md`: đơn vị split = **process instance** (mọi path của 1 instance cùng phía); train = benign-only; test = benign + attack; ghi tỷ lệ (vd 70/30), seed cố định, phiên bản lib.
  - [ ] Temporal split phụ: train trên scenario/khoảng thời gian trước, test sau (nếu data cho phép); cross-scenario: train benign scenario A, test attack scenario B.
  - [ ] Metric: P/R/F1 (path-level, graph-level), FPR, confusion matrix; CI bằng 5–10 seed.
  - [ ] Checkpoint leakage: assert không path nào xuất hiện ở cả train lẫn test (script `experiments/check_leakage.py`).
- **Output:** `experiments/protocol.md` + script check leakage.
- **Xong khi:** protocol được cả nhóm ký duyệt; check_leakage pass = 0 trùng lặp.
- **Phụ thuộc:** T02, T06.
- **Rủi ro:** data PKU-ASAL nhãn theo scenario, không theo instance rõ ràng → phải tự định nghĩa instance (pid+khung thời gian) và ghi vào label book; hạ fidelity: bỏ temporal split, giữ instance split.

### T10 — Thí nghiệm chính + bảng đối chiếu paper (L)
- **Rubric:** 2, 4.
- **Mục tiêu:** chạy pipeline end-to-end, ra bảng so sánh với paper, phân biệt rõ tái lập/không tái lập.
- **Input:** T06–T09.
- **Việc cụ thể:**
  - [ ] Script `experiments/run_main.py`: ingest → graph → select → embed → detect theo protocol, ghi log + seed.
  - [ ] Bảng path-level (P/R/F1/FPR) + graph-level (quét t=1..5) trên test set.
  - [ ] `experiments/results/main-table.md`: cột "paper" (path 0.959/0.991/0.974; graph t=3 0.957/1/0.978) vs cột "đồ án"; dòng ghi chú **"khác dataset → đây là tái lập phương pháp, KHÔNG phải tái lập con số"**.
  - [ ] Confusion matrix + ví dụ 5 TP/5 FP/5 FN có ID instance.
- **Output:** `experiments/results/main-table.md` + confusion matrix + log.
- **Xong khi:** pipeline chạy lại được từ đầu bằng 1 lệnh (`make experiment`), bảng có đủ metric và ghi chú trung thực.
- **Phụ thuộc:** T08, T09.
- **Rủi ro:** F1 thấp hơn nhiều paper (data khác, quy mô nhỏ) → không che giấu; đây là input của T12 (rubric 4 chấm trung thực); hạ fidelity: chỉ path-level nếu graph-level kẹt.

### T11 — Ablation: bỏ path selection / đổi K / đổi noise (M)
- **Rubric:** 2, 4.
- **Mục tiêu:** trả lời RQ2 (lineage/tần suất/chuỗi/nhiễu đóng góp gì).
- **Input:** T10.
- **Việc cụ thể:**
  - [ ] Ab-1 bỏ path selection: path ngẫu nhiên thay top-K (kỳ vọng F1 giảm — paper 0.601 vs 0.974).
  - [ ] Ab-2 quét K ∈ {5,10,20,30}: F1 và thời gian theo K.
  - [ ] Ab-3 đổi nhiễu: pha thêm n% path benign vào graph attack (n ∈ {0,25,50,75}) → đo recall sụt.
  - [ ] Ab-4 thay detector (OCSVM/IF/RobustCov — từ T08) và Path Nodes Averaging.
  - [ ] Ab-5 lineage vs frequency: detector chỉ dùng parent-child edge (single-hop) vs path n-hop → so sánh (kỳ vọng single-hop kém, đúng luận điểm blacklist).
- **Output:** `experiments/results/ablation.md` (bảng + kết luận từng câu hỏi RQ).
- **Xong khi:** mỗi ablation có 1 bảng và 1 câu kết luận gắn với RQ2/H1–H4.
- **Phụ thuộc:** T10.
- **Rủi ro:** chạy lâu → chặn số instance mẫu cho ablation; hạ fidelity: Ab-5 bỏ nếu thiếu thời gian (baseline T07 đã phủ phần nào).

### T12 — Error analysis + FP từ ứng dụng bình thường (L)
- **Rubric:** 4.
- **Mục tiêu:** taxonomy lỗi + trả lời RQ3; bắt buộc với ML (rubric).
- **Input:** FP/FN từ T10 + label book.
- **Việc cụ thể:**
  - [ ] `docs/error-analysis.md`: phân loại mọi FP/FN theo taxonomy Syn §7.3 (FP rare-but-benign / FP abstraction / FN missing-telemetry / FN mimicry / FN drift / FN short-trace).
  - [ ] Mổ 5 FP: chỉ ra đây là hành vi benign nào (admin script? updater? download?) + vì sao path hiếm.
  - [ ] Mổ 5 FN: xác định missing-telemetry hay dưới ngưỡng t.
  - [ ] Kết luận RQ3 + trường hợp hệ thống chắc chắn kém (Syn §7.5) kèm bằng chứng thực nghiệm nếu có.
- **Output:** `docs/error-analysis.md` + bảng taxonomy đếm theo nhóm.
- **Xong khi:** 100% FP/FN được gán vào taxonomy (không có "khác"); mỗi nhóm có ≥ 1 ví dụ trace.
- **Phụ thuộc:** T10.
- **Rủi ro:** không đủ FP để phân tích (data sạch) → chủ động sinh FP bằng workload benign đa dạng hơn (scenario khác) hoặc hạ ngưỡng t để lộ FP; hạ fidelity: mổ 3 FP/3 FN thay vì 5.

### T13 — Overhead measurement (S–M)
- **Rubric:** 2, 4.
- **Mục tiêu:** đo storage + runtime từng stage, đối chiếu con số paper (graph build 5s + select 2s; embed 1ms/path; training doc2vec 94s/30k paths; LOF 39s).
- **Input:** pipeline T10 + máy lab.
- **Việc cụ thể:**
  - [ ] `src/util/perf.py`: time từng stage (ingest, build, select, embed, detect) + bytes/event sau chuẩn hóa.
  - [ ] Bảng: trung bình ± std trên ≥ 20 instance; ghi cấu hình máy.
  - [ ] Đối chiếu với paper nhưng ghi rõ khác quy mô data (không so ngang).
- **Output:** `experiments/results/overhead.md`.
- **Xong khi:** mỗi stage có số đo lặp lại được (chạy 2 lần, lệch < 10%).
- **Phụ thuộc:** T10.
- **Rủi ro:** máy yếu làm số xấu → báo cáo đúng máy, không đổ lỗi data; hạ fidelity: chỉ đo select+embed+detect (bỏ ingest I/O).

### T14 — Case study write-up (M)
- **Rubric:** 1, 4.
- **Mục tiêu:** 2–3 case study giải thích được, vô hại, cho báo cáo + slide.
- **Input:** Syn §8 (3 kịch bản đã phác: Word→PowerShell marker, browser download, admin scheduled task).
- **Việc cụ thể:**
  - [ ] Thực hiện kịch bản vô hại trong VM lab (nếu chọn lab traces) HOẶC chọn instance tương ứng từ dataset công bố; ghi lại graph thật.
  - [ ] `docs/case-studies.md`: mỗi case = kịch bản, graph kỳ vọng, path hiếm thực tế, vì sao TP/FP, liên hệ TTP (T1059/T1105/T1047).
  - [ ] Không mô tả bất kỳ cách viết malware/payload nào; chỉ hành vi marker vô hại.
- **Output:** `docs/case-studies.md` + hình graph.
- **Xong khi:** ít nhất 2 case có graph + path thật từ pipeline (không chỉ vẽ tay).
- **Phụ thuộc:** T10, T12.
- **Rủi ro:** VM Windows mất thời gian → dùng case từ PKU-ASAL (đã có ground truth); hạ fidelity: 2 case thay vì 3.

### T15 — README, env lock, checksum, VM notes (M)
- **Rubric:** 5.
- **Mục tiêu:** người khác chạy lại từ đầu trong < 1 ngày.
- **Input:** toàn bộ repo.
- **Việc cụ thể:**
  - [ ] `README.md`: mục tiêu, sơ đồ pipeline, từng bước (tải data → checksum → install → chạy main → bảng), phần "kết quả nào là tái lập, cái nào không", license các nguồn, cảnh báo an toàn.
  - [ ] `docs/checksums.md`: sha256 mọi file data/model/artifact.
  - [ ] `docs/vm-notes.md`: cấu hình VM/snapshot/rollback nếu có lab; nếu không lab thì ghi rõ "chỉ ingest, không chạy malware".
  - [ ] Dọn repo: không có sample/payload nguy hiểm, không có dữ liệu cá nhân; git LFS cho file > 10MB.
  - [ ] Demo tái chạy độc lập: 1 thành viên khác clone từ đầu và chạy tới bảng kết quả.
- **Output:** README + checksums + vm-notes.
- **Xong khi:** người thứ 2 chạy lại thành công không cần hỏi thành viên nào; checksum pass.
- **Phụ thuộc:** T10–T14.
- **Rủi ro:** thiếu giấy phép file lớn trong repo → đặt ngoài repo, chỉ giữ manifest+checksum; hạ fidelity: README tối giản nhưng phải đủ 6 mục trên.

### T16 — Báo cáo + slide theo 5 hạng mục rubric (L)
- **Rubric:** 1–5.
- **Mục tiêu:** đóng gói mọi artifact thành báo cáo/slide ánh xạ 1-1 rubric.
- **Input:** mọi output trên.
- **Việc cụ thể:**
  - [ ] `docs/report.md` (hoặc Overleaf): cấu trúc theo đúng 5 hạng mục rubric + ghi chú điểm hạng mục 4 = 2.5 (serial 46144).
  - [ ] `slides/`: 12–15 slide: đối tượng mã độc → pipeline → dataset → kết quả vs paper → ablation → error analysis → limitations → demo.
  - [ ] Bảng "tái lập được / không tái lập được" bắt buộc (rubric 2 nguyên tắc chấm).
  - [ ] Diễn tập + chỉnh theo feedback GV.
- **Output:** `docs/report.md` + `slides/` + biên bản diễn tập.
- **Xong khi:** mỗi hạng mục rubric chỉ ra đúng artifact tương ứng trong report (bảng cross-ref); GV duyệt.
- **Phụ thuộc:** T15.
- **Rủi ro:** quá tải nội dung → cắt bớt số liệu thô, giữ bảng chính + kết luận; hạ fidelity: slide 10 cái, report dùng trực tiếp synthesis §2–§9 làm khung.

## Phương án B (nếu kẹt dữ liệu)

| Tình huống | Chuyển sang | Hệ quả |
|---|---|---|
| PKU-ASAL không tải được / LFS hỏng | **ATLAS** (~733 MB, Apache 2.0, 10 kịch bản APT Win+Linux, ground truth) [Syn §5.2] | Parser T04 viết lại theo Windows Security events (4688/4663/5156) + auditd |
| ATLAS cũng kẹt | **DARPA TC E3 THEIA run 1r** qua mirror threaTrace (~4.8 GB JSON, public domain, kèm ground truth UUID) [Syn §5.2] | Cần đĩa ≥ 60 GB giải nén; map UUID→path thủ công (label noise, Syn §5.3) |
| Không đủ đĩa/CPU cho mọi nguồn | **ProvNinja-only**: dùng trực tiếp causal paragraphs + feature vector CSV của lab co-author | Chỉ còn khâu embed+detect+ablation (classifier-level), mất ingest/graph → hạng mục 2 xuống mức Đạt |
| Muốn thêm dữ liệu Linux | **UNICORN traces** (Harvard Dataverse CC0, wget-trojan 125 benign/25 trojan) [Syn §5.2] | PROV-JSON parse thêm 1 parser |
| Muốn dataset mới (rubric 3 khá/giỏi) | **Tự thu 20–40 lab traces Sysmon** kịch bản vô hại (Syn §8) trên VM Windows snapshot-rollback | +2–3 buổi; thêm `data/lab/` + data card riêng; vẫn KHÔNG chạy malware |

Nguyên tắc: dù phương án nào, **không tải/chạy mẫu malware thật**, kể cả 1,150 MD5 trong `share-we/malware` (chỉ đọc metadata nếu cần).

## Không làm (danh sách cấm)

- Không kernel exploit, rootkit, driver BYOVD; không vô hiệu AV/EDR trên máy thật.
- Không tải/chạy/đóng gói mẫu malware; không viết payload phá hoại, injection PoC thật, C2 Internet.
- Không credential theft, exfiltration, persistence ngoài VM lab, không phát tán mẫu.
- Không obfuscation/packer payload, không sinh polymorphic malware (dù là toy).
- Không claim "tái lập F1=0.974" hay SOTA — dataset khác, kết quả khác.
- Không công khai script/kịch bản có thể dùng sai mục đích; marker vô hại phải ghi rõ là mô phỏng.
- Không trộn rubric Dev Track (3 biến thể evasion) vào báo cáo Research.

## Definition of Done (rubric-oriented)

Đồ án xong khi **tất cả** đúng:

- [ ] HM1: `docs/threat-model.md` + label book + concept map + bảng TTP có nguồn ATT&CK; 4 RQ đo được; nhóm trình bày được sự khác biệt stealthy vs noisy trên provenance.
- [ ] HM2: pipeline `src/` chạy end-to-end bằng 1 lệnh, có ≥ 2 baseline, protocol chống leakage (check_leakage pass), bảng so sánh với paper kèm dòng "tái lập phương pháp, không tái lập con số".
- [ ] HM3: `docs/data-card.md` + `data/manifest.csv` (checksum pass) + phân tích bias/leakage/imbalance/license; KHÔNG chạy malware ở bất kỳ bước nào.
- [ ] HM4: P/R/F1/FPR + confusion matrix + error taxonomy phủ 100% lỗi + threats-to-validity 4 loại + CI theo seed + ablation (bỏ path selection, đổi K, đổi noise, đổi detector) + ≥ 1 trường hợp hệ thống kém có bằng chứng.
- [ ] HM5: người thứ 2 chạy lại từ README thành công; checksum đầy đủ; không artifact nguy hiểm trên repo; báo cáo + slide ánh xạ 1-1 5 hạng mục; ghi chú venue thật NDSS 2020 vs đề "NDSS 2025".

---
*Plan này đi kèm `docs/R21-research-synthesis.md`; mọi số liệu paper trích từ PDF NDSS 2020 đã đọc, mọi thông tin dataset/related work đã verify 10/2026 (URL trong synthesis §11).*
