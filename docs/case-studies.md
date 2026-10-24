# Case studies — trace thật từ PKU-ASAL

> Mọi path dưới đây lấy từ cache top-K=20 của run WS12→WS12 seed 20261025.
> Không có malware nào được chạy; đây là trace ETW công bố.

## Case 1 — Chuỗi APT trên WS12: `cmd → agent → powershell → netsh`

Instance 1250 (label 1) là `agent`; instance 1388 là `cmd`; instance 409 là `cmd`.

Các path hiếm nhất:

```text
P:agent START P:powershell START P:netsh EXECUTE F:c:/windows/system32/netsh.exe
P:agent START P:powershell START P:reg EXECUTE F:c:/windows/system32/reg.exe
P:cmd START P:agent START P:powershell EXECUTE F:c:/windows/system32/windowspowershell/v1.0/powershell.exe
P:cmd START P:agent START P:powershell WRITE F:*:/users/*/appdata/roaming/microsoft/windows/recent/customdestinations/0m3swyrk54yfwrwsk26v.temp
P:cmd START P:taskkill EXECUTE F:c:/windows/syswow64/wbem/wbemprox.dll
P:cmd START P:certutil EXECUTE F:c:/windows/syswow64/cabinet.dll
```

- Tín hiệu: **lineage** `agent → powershell → netsh/reg` và `cmd → taskkill/certutil`,
  cộng với file sink trong `AppData\Roaming\...\Recent\CustomDestinations`.
- Đây là chain LOLBin/tool hệ thống, không có file payload mới; path-level
  rarity bắt được vì tổ hợp cạnh này không xuất hiện trong benign train.
- LogR của các path khoảng −72 đến −47; benign median khoảng −9
  (`experiments/results/signal-noise.md`).

## Case 2 — Benign FP: `NGenTask.exe` và `svchost.exe -k AppReadiness`

Instance 648 (`ngentask`) và 4176 (`svchost`) bị ProvDetector flag (FP):

```text
P:ngentask START P:ngen EXECUTE F:c:/windows/system32/advapi32.dll
P:ngentask START P:conhost EXECUTE F:c:/windows/system32/conhost.exe
P:svchost EXECUTE F:c:/windows/system32/windows.networking.connectivity.dll
P:svchost READ F:*:/users/*/appdata/local/microsoft/windows/appsfolder.itemdata-ms
```

- Đây là .NET native-image maintenance và Windows AppReadiness service.
- Vì sao FP: process name/path hiếm trong benign train, nhưng hành vi
  (`EXECUTE` DLL hệ thống, đọc file AppData) là hợp lệ. Đúng nhóm
  **rare-but-benign** trong label book.
- Biện pháp giảm: profile theo *program* thay vì instance, hoặc yêu cầu
  tối thiểu số path trước khi kết luận.

## Case 3 — Rule heuristic thất bại

Rule “UI-heavy program → script interpreter” bắt 0/43 positive trên WS12 và
0/136 trên W10. Các process bị chiếm trong trace là `cmd`, `powershell`,
`certutil`, `taskkill`, `reg`, `netsh`; chúng không phải UI-heavy root, nên
rule không kích hoạt. Đây là lý do paper dùng path rarity thay vì rule.

## Case 4 — Cross-dataset thất bại (WS12 → W10)

- Train WS12, test W10: ProvDetector AUROC 0.572, FPR 0.963; frequency-only
  AUROC 0.488, FPR 1.0.
- Nguyên nhân: vocabulary path (tên DLL, đường dẫn, process) và scale
  regularity khác giữa Windows Server 2012 và Windows 10; threshold calibrate
  trên WS12 không chuyển sang W10.
- Chiều ngược lại W10→WS12 tốt hơn (AUROC 0.725, FPR 0.067) nhưng vẫn chưa
  đủ để triển khai.

## Giới hạn của case study

- Đây là trace mô phỏng, không phải malware thật; kết quả lạc quan hơn thực tế.
- Không có memory/registry edge nên injection thuần không thấy được.
- Các path trên là top-K theo regularity, không phải toàn bộ hành vi.
