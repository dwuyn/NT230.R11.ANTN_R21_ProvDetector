# VM / lab notes

- Đồ án **không chạy malware** và không cần VM Windows để tái lập kết quả hiện
  tại: toàn bộ pipeline ingest trace ETW công bố.
- Dữ liệu thô tải về máy Linux (Python 3.12 venv); không có mẫu nhị phân, không
  có kết nối C2.
- Nếu nhóm mở rộng sang tự thu Sysmon (tùy chọn, ngoài phạm vi run này):
  - VM Windows có snapshot/rollback.
  - Chỉ kịch bản marker vô hại; không payload phá hoại.
  - Sysmon Event ID 1/3/7/11/12/13/14/15/22 → map về schema `src/ingest/schema.py`.
- Dung lượng đã dùng: ~2.7 GB JSON đã giải nén cho W10 + WS12; Ubuntu 10.5 GB
  đã tải nhưng chưa giải nén/parse.
- Không đưa `data/`, `.venv/`, `experiments/results/cache/` lên GitHub
  (`.gitignore`).
