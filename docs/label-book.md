# Label book — R21

## 1. Đơn vị nhãn

- **Instance** = một khoảng `Process/Start` → `Process/Stop` của một PID, ghép
  bằng `UniqueProcessKey`; implicit instance cho event trước start đầu tiên.
- Nhãn instance lấy từ `is_warn` của `Process/Start` trong `anomaly.json`.
- Event thuộc instance nào thì mang nhãn instance đó.
- `START` edge thuộc graph của **parent**, nên parent benign có thể chứa con
  malicious; con được chấm là instance riêng.

## 2. Bốn nhãn

| Nhãn | Quy tắc gán | Dùng ở đâu |
|---|---|---|
| `benign` | Instance từ `benign.json`; hoặc instance `is_warn != True` trong `anomaly.json` | Train/validation; negative test |
| `stealthy-malicious` | Instance có `Process/Start.is_warn == True` | Positive test |
| `rare-but-benign` | Instance benign nhưng có path log-regularity thấp (dưới ngưỡng benign validation) | Error analysis (FP) |
| `missing-telemetry` | Hành vi tấn công không sinh edge trong schema (memory-only, registry-only) | Error analysis (FN), không gán tự động |

`rare-but-benign` và `missing-telemetry` là nhãn **phân tích**, không dùng để
train hay tính metric.

## 3. Quy tắc loại trừ

- Không dùng nhãn malicious trong bất kỳ bước train/fit nào.
- Không split theo event/path: mọi path của một instance nằm cùng phía.
- Không gán nhãn malicious cho ancestor của process bị chiếm nếu chính ancestor
  không có `is_warn == True`.
- Process/Stop thiếu (trace kết thúc) → lifetime kéo tới cuối capture; ghi nhận
  là giới hạn, không phải nhãn.

## 4. Kiểm tra

`tests/test_leakage.py`, `src/util/leakage.py`: instance disjoint giữa
train/validation/test; báo cáo path-signature overlap (không dùng để chặn vì
path phổ biến có thể lặp tự nhiên giữa các instance benign).
