# Checksums

`data/manifest.csv` là nguồn chuẩn: mỗi dòng gồm `path,bytes,sha256` cho:

- 3 archive gốc PKU-ASAL (`SimulatedW10.zip`, `SimulatedWS12.zip`,
  `SimulatedUbuntu.zip`);
- 3 archive lồng (`win10.zip`, `hw20.zip`, `hw17.zip`);
- 4 file JSON đã giải nén và dùng để parse (W10/WS12 benign+anomaly);
- 6 CSV ProvNinja (`*-fv.csv`, `*-paragraph.csv`).

Kiểm tra:

```bash
cd data/raw/pku && sha256sum -c ../../manifest.csv 2>/dev/null || true
```

Lưu ý: manifest dùng đường dẫn tương đối từ repo root, nên chạy kiểm tra từ
root bằng script:

```bash
python - <<'PY'
import csv, hashlib
for row in csv.DictReader(open('data/manifest.csv')):
    h = hashlib.sha256()
    with open(row['path'], 'rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            h.update(chunk)
    assert h.hexdigest() == row['sha256'], row['path']
print('all checksums OK')
PY
```

Ubuntu JSON chưa giải nén nên chỉ archive gốc/lồng có checksum.
