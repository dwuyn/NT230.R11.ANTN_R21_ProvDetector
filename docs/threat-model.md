# Threat model — R21 (ProvDetector reproduction)

> Rubric hạng mục 1. Nguồn kỹ thuật: `docs/R21-research-synthesis.md` §2; paper neo
> Wang et al., *You Are What You Do*, NDSS 2020 (DOI 10.14722/ndss.2020.24167).
> Citation `[1, §…]` trỏ tới paper; số không tiền tố trỏ synthesis.

## 1. Đối tượng

**Stealthy malware** = mã độc giả mạo hoặc lạm dụng tiến trình/công cụ tin cậy
để ẩn payload và duy trì hiện diện: memory code injection (remote thread,
reflective DLL, process hollowing), script-based/fileless (Office macro, DDE,
PowerShell), và khai thác lỗ hổng app tin cậy. Khác với malware truyền thống,
nó không thả binary riêng xuống đĩa và chạy bên trong process hợp pháp, nên
file-based AV, static signature và application whitelist đều kém hiệu quả
[1, §I–II].

**Living off the land:** dùng tool có sẵn (`powershell`, `wmic`, `certutil`,
`rundll32`, `mshta`) — hành vi giống admin hợp lệ, không thể chặn trắng-đen.

## 2. Bề mặt quan sát

ProvDetector chỉ dùng 3 entity và 5 quan hệ [1, Table I]:

| Entity | Thuộc tính dùng trong đồ án |
|---|---|
| Process | PID, parent PID, image name, command line (chỉ lưu để error analysis), host |
| File | path đã abstraction (lowercase, `*:/users/*/`, `/home/*/`) |
| Socket | remote `ip:port` (bỏ endpoint nội bộ) |

| Quan hệ | src → dst |
|---|---|
| `START` | process → process |
| `READ` / `WRITE` / `EXECUTE` | process → file |
| `CONNECT` | process → socket |

**Chỉ process là source.** `END` được dùng để đóng lifetime, không tạo edge.

### Không quan sát được

- **Memory**: injection thuần (ghi vào RAM process khác) không sinh edge; chỉ
  lộ gián tiếp qua hành vi sau đó của process nạn nhân [1, §I].
- **Registry**, **command-line arguments**, **DNS**, IPC/shared memory, side
  channel — ngoài schema [1, §IV-A].
- Hệ quả: một số tấn công memory-only là **missing-telemetry** — không thể
  phát hiện về nguyên tắc bởi pipeline này.

## 3. TTP → provenance kỳ vọng

| TTP (ATT&CK) | Chuỗi kỳ vọng | Vì sao phân biệt được | FP điển hình |
|---|---|---|---|
| T1059.001 PowerShell | `winword → cmd → powershell` | chain UI→shell→script hiếm | admin script, CI |
| T1055 / T1055.012 Process Hollowing | không có edge injection; process tin cậy đổi hành vi | thay đổi đột ngột tập path của process | app tự update |
| T1218.005/.010/.011 mshta/regsvr32/rundll32 | `excel → certutil → rundll32 → socket` | LOLBin chain + file mới + egress | installer hợp lệ |
| T1027 Obfuscated Files | `certutil -read-> base64 -write-> exe` | decode→execute sequence | backup/encode hợp lệ |
| T1047 WMI | `wmiprvse → cmd/powershell` | WMI spawn shell hiếm | SCCM/remote admin |
| T1105 Ingress Tool Transfer | `powershell -write-> socket(external)` | tool hệ thống egress bất thường | updater, telemetry |
| T1204 User Execution | `winword -read-> doc` rồi spawn chain | doc→shell→network | macro hợp lệ |
| T1036/T1564 Masquerading | process path lạ nhưng tên giống tool hệ thống | path hiếm | app portable |
| T1574 Hijack Execution Flow | `process -read-> dll` từ vị trí lạ | DLL load bất thường | plugin hợp lệ |

Lưu ý ATT&CK: `certutil.exe` là software **S0160**, không phải sub-technique
T1218; process hollowing trước đây là **T1093** (đã revoke) nay là **T1055.012**.

## 4. Giả định và ngoài phạm vi

- OS + provenance tracker nằm trong TCB; attacker không sửa/xóa log (log
  integrity là bài toán orthogonal) [1, §III].
- Không xét implicit flow/side channel.
- Mỗi chương trình mục tiêu có benign profile (train chỉ trên benign).
- **Ngoài phạm vi:** traditional file-drop malware; phát hiện real-time; thu
  thập malware mới; mẫu thật/C2. Đồ án chỉ ingest trace công bố.
- Attacker có thể mimicry: paper đo trung bình phải sửa ~5 node trong path để
  giống benign [1, §VI-C4]; đồ án không đánh giá evasion chủ động.

## 5. Câu hỏi nghiên cứu

- **RQ1:** Trên trace Windows công bố, top-K path hiếm có tập trung vào vùng
  ground truth của process bị chiếm không?
- **RQ2:** Lineage (chuỗi process), tần suất edge và nhiễu benign đóng góp thế
  nào vào kết quả (ablation bỏ path selection, đổi K, thêm nhiễu)?
- **RQ3:** Loại false positive nào chiếm ưu thế (admin script, updater,
  download-and-open) và false negative nào do missing-telemetry?
- **RQ4:** Pipeline chịu được cross-dataset (train W10 → test WS12 và ngược
  lại) ở mức nào, và overhead ra sao?

## 6. Nhãn

Định nghĩa đầy đủ ở `docs/label-book.md`:
`benign`, `rare-but-benign`, `stealthy-malicious`, `missing-telemetry`.
