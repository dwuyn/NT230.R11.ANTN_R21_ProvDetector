# Data card — PKU-ASAL Simulated-Data (R21 reproduction)

> Filled 2026-10-25 from files actually downloaded and parsed in this repo.
> Checksums: `data/manifest.csv`. This card describes the **substitute**
> dataset; the paper's enterprise traces are not public (synthesis §5.1).

## 1. Dataset identity

| Field | Value |
|---|---|
| Name | PKU-ASAL / Simulated-Data (NODLINK, NDSS 2024) |
| Source | https://github.com/PKU-ASAL/Simulated-Data |
| License | Research-only MIT (see repo `LICENSE`) — coursework/research only, no commercial use |
| Downloaded | 2026-10-25 via Git LFS (`SimulatedW10.zip` 133,716,973 B; `SimulatedWS12.zip` 86,679,853 B; `SimulatedUbuntu.zip` 368,736,464 B) |
| Checksums | SHA-256 in `data/manifest.csv` (outer archives, inner archives, extracted JSON) |
| Used in this run | **WS12** and **W10** (Windows ETW). Ubuntu downloaded but not parsed (10.5 GB JSON; out of scope for the current run) |
| Cross-check | ProvNinja `sample-enterprise-data` (BSD-3-Clause, 14 MB) copied to `data/raw-provninja/` |

## 2. Collection environment

- Windows Server 2012 and Windows 10 virtual machines instrumented with
  Windows ETW kernel providers (process/file/network events), exported as
  JSON lines.
- Ubuntu 20.04 trace uses Sysdig (`evt.type`, `proc.cmdline`, `fd.name`); not
  ingested in this iteration.
- The published data contains **traces only**, no malware binaries. Nothing in
  this repo executes malware.

## 3. Actual schema

Each JSON line is one ETW event. Fields observed in both Windows traces:

| Field group | Fields | Notes |
|---|---|---|
| Common | `MSec`, `PID`, `PName`, `TID`, `EventName` | `MSec` is milliseconds within the capture session; W10 interleaves sessions so it is **not globally monotone** |
| File | `FileName`, `Offset`, `IrpPtr`, `FileObject`, `FileKey`, `IoSize`, `IoFlags` | `EventName` ∈ `FileIO/Read`, `FileIO/Write` |
| Image | `ImageBase`, `ImageSize`, `ImageChecksum`, `TimeDateStamp`, `DefaultBase`, `FileName` | `EventName` = `Image/Load` |
| Process | `ProcessID`, `ParentID`, `ImageFileName`, `DirectoryTableBase`, `Flags`, `SessionID`, `ExitStatus`, `UniqueProcessKey`, `CommandLine`, `is_warn`, `PPName` | `EventName` ∈ `Process/Start`, `Process/Stop` |
| Network | `saddr`, `sport`, `daddr`, `dport`, `size`, `startime`, `endtime`, `seqnum`, `connid` | `EventName` ∈ `TcpIp/Send`, `TcpIp/Recv` |

Normalisation to the project schema (`src/ingest/schema.py`):
`Read/Write → READ/WRITE`, `Image/Load → EXECUTE`, `Process/Start → START`,
`TcpIp/* → CONNECT`; only processes are edge sources. File paths are lowercased,
backslashes normalised, and user/home components wildcarded. Sockets keep the
remote `ip:port`.

## 4. Labels

- Ground truth is the `is_warn` field on `Process/Start` (`True` for attack
  processes in `anomaly.json`; absent/False elsewhere).
- Every event owned by a labelled process inherits the label.
- `anomaly.json` also contains non-attack processes (label 0), so it is a
  realistic mixed test stream, not an all-malicious file.
- Child start edges are owned by the parent graph; a malicious child is scored
  as its own instance.

## 5. Statistics after parsing

| Trace | JSON lines | Edges kept | Start events | Malicious starts | Instances | Abstracted nodes |
|---|---|---|---|---|---|---|
| WS12 benign | 7,196,189 | 7,191,156 | 4,991 | 0 | 5,033 | 8,554 |
| WS12 anomaly | 1,087,311 | 1,083,898 | 3,139 | 43 | 3,180 | 10,006 |
| W10 benign | 6,022,142 | 6,015,438 | 6,021 | 0 | 6,201 | 48,379 |
| W10 anomaly | 1,878,778 | 1,876,355 | 2,365 | 136 | 2,472 | 16,693 |

`Process/Stop` records (4,991 / 3,134 / 6,011 / 2,261) are used for lifetimes, not
kept as edges. Implicit instances capture processes whose events precede the
first start record.

## 6. Splits

- Unit: process instance; all paths of an instance stay on one side.
- In-dataset: benign 70% train / 15% validation / 15% test; all anomaly
  instances test.
- Cross-dataset: 85% of source benign train, 15% validation; target benign
  test-only.
- Seed: 20261025 (`scripts/seed.sh`, `config.yaml`).
- Leakage assertions: `tests/test_leakage.py` + `src/util/leakage.py`.

## 7. Known biases and limitations

- **Single host / session**: `H(e)` (host frequency) degenerates, so the
  regularity database uses benign-instance frequency instead of host frequency.
  This is a documented adaptation, not the literal NoDoze formula.
- **W10 capture interleaving**: events from several sessions are merged and
  `MSec` is not globally ordered; process lifetimes are reconstructed per PID
  from `UniqueProcessKey`, which can still mis-associate events for a PID reused
  across sessions. WS12 is the primary trace; W10 is the cross-dataset check.
- **Label granularity**: `is_warn` labels process starts, not individual events;
  path labels inherit instance labels.
- **Sandbox/simulation bias**: attacks were simulated on lab VMs; behaviour is
  cleaner than real malware, so results should be optimistic relative to the
  paper's enterprise/Cuckoo setup.
- **Class imbalance**: 43/3,180 and 136/2,472 anomaly-trace positives. Report
  P/R/F1 plus FPR and a balanced test sample; accuracy is never used.
- **Ubuntu** trace not ingested; no Linux claim is made.
- **No new malware** was downloaded or executed.

## 8. Ethics / privacy

Published research traces only; no binaries, credentials, or C2 traffic. File
paths contain synthetic user names (`Administrator`, wildcarded by the parser).
No personal data was collected. The `share-we/malware` hash list was not
downloaded.
