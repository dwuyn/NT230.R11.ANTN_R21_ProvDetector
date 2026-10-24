# Error analysis — R21

> Dựa trên predictions của run chính (`experiments/results/*_predictions.csv`) và
> hai báo cáo chi tiết `error-analysis-WS12.md`, `error-analysis-W10.md`.
> Nhãn theo `docs/label-book.md`.

## 1. Tổng hợp

| Run | Positives | ProvDetector FN | FP trên benign trace | FP full test (gồm benign trong anomaly trace) | Chain recall |
|---|---|---|---|---|---|
| WS12→WS12 | 43 | 0 | 27/754 | 645/3,887 | 5/5 = 1.000 |
| W10→W10 | 136 | 32 | 43/926 | 568/3,238 | 37/46 = 0.804 |

Chain recall = tỷ lệ chuỗi spawn (gom theo ancestor) có ít nhất một process bị
bắt. Rule heuristic: 0 recall ở cả hai trace. Frequency/whitelist/score bắt gần
hết positive nhưng FPR cao (xem `main-table.md`).

## 2. False positive — rare-but-benign

| Trace | Instance | Hành vi | Vì sao bị flag |
|---|---|---|---|
| WS12 | `NGenTask.exe /RuntimeWide /StopEvent` | .NET native image maintenance | 20/20 path hiếm; process ít gặp trong benign train |
| WS12 | `svchost.exe -k AppReadiness` | Windows AppReadiness service | path hiếm, graph nhỏ (10 path) |
| WS12 | `postgres` (10 instance) | DB worker đọc file dữ liệu riêng | file path hiếm, lặp lại giữa các instance |
| W10 | `DllHost.exe /Processid:{…}` | COM surrogate | path hiếm, không có mẫu benign tương ứng |
| W10 | `python.exe … pgAdmin4.py` | pgAdmin web server | tool hợp lệ chạy script, giống interpreter abuse |
| W10 | `chrome.exe --type=utility --utility-sub-type=storage` | Chrome storage utility | process con + file cache hiếm |

Đây là các nhóm FP dự kiến trong synthesis §2.5/§7.3: updater/maintenance,
admin/tool hợp lệ, browser download-and-open. Không có FP nào là "file lạ" đơn
thuần; tất cả đều là path hiếm của process hợp lệ.

## 3. False negative — taxonomy

| Nhóm | Ví dụ | Giải thích |
|---|---|---|
| **Short trace / quá ít path** | `cscript.exe /e:VBScript.Encode T1059.007.vbs` (2 path, 0 outlier) | Graph quá nhỏ; top-K=20 không đủ tín hiệu, LOF không có đủ path để vượt t=3 |
| **Mimicry / trùng profile benign** | `python.exe` chạy script trong `AppData\Local\Programs\Python` (20 path, 0 outlier) | Hành vi giống python benign đã thấy; embedding không tách được |
| **Missing telemetry / dual-use** | `rundll32.exe PcaSvc.dll,PcaPatchSdbTask` (10 path, 0 outlier) | DLL load + task giống benign; không có memory/registry edge để phân biệt |
| **Under threshold t** | các process malicious có 1–2 outlier path | t=3 yêu cầu ≥3 path bất thường; early-stop của paper giảm chi phí nhưng bỏ sót |

FN của W10 (32/136) chủ yếu là python/cscript/rundll32; FN của WS12 = 0 vì
attack chain có nhiều process con với path rất hiếm.

## 4. Liên hệ RQ3

- **RQ3:** FP chiếm ưu thế là **rare-but-benign của process hợp lệ** (maintenance,
  DB, browser, COM), không phải nhiễu file đơn lẻ. FN chủ yếu là **short trace**
  và **mimicry/missing-telemetry**, không phải lỗi threshold đơn thuần.
- Hệ quả: hướng cải tiến hợp lý là (a) profile theo *program* thay vì từng
  instance để giảm FP updater, (b) yêu cầu tối thiểu số path trước khi kết luận
  (hoặc hạ t cho graph nhỏ), (c) thêm registry/memory telemetry cho DLL
  sideload/rundll32 — ngoài phạm vi provenance hiện tại.

## 5. Ghi chú trung thực

- Full-test FP lớn hơn benign-trace FP vì `anomaly.json` chứa nhiều process
  benign (label 0) với workload khác `benign.json`; threshold calibrate trên
  `benign.json` không chuyển hoàn toàn.
- Không có FP/FN nào được gán nhãn "khác": mọi trường hợp đều rơi vào 4 nhóm
  của label book.
