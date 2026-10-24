# Error analysis — W10_W10_k20_L5_seed20261025_predictions


## Chain-level recall (at least one malicious process in the spawn chain)

| Method | Chains detected | Chains | Recall |
|---|---|---|---|
| provdetector | 37 | 46 | 0.804 |
| rule | 0 | 46 | 0.000 |
| whitelist | 0 | 46 | 0.000 |
| anomaly_score | 45 | 46 | 0.978 |

## False positives (benign instances flagged)

- **provdetector**: 43/926 benign instances flagged
  - top process names: [('powershell', 2), ('chrome', 2), ('wordpad', 2), ('svchost', 2), ('dllhost', 2), ('msedge', 1), ('backgroundtaskhost', 1), ('whoami', 1)]
- **rule**: 0/926 benign instances flagged
- **whitelist**: 0/926 benign instances flagged
- **anomaly_score**: 54/926 benign instances flagged
  - top process names: [('csc', 3), ('svchost', 2), ('runtimebroker', 2), ('reg', 2), ('backgroundtaskhost', 1), ('whoami', 1), ('chrome', 1), ('notepad', 1)]

## False negatives (malicious instances missed)

- **provdetector**: 32/136 missed
  - names: [('powershell', 10), ('netsh', 5), ('python', 3), ('cscript', 3), ('rundll32', 3), ('py', 3), ('certutil', 2), ('lazagne1', 1)]
- **rule**: 136/136 missed
  - names: [('powershell', 57), ('reg', 17), ('schtasks', 11), ('spolsv', 6), ('netsh', 5), ('net', 4), ('wmic', 4), ('net1', 4)]
- **whitelist**: 136/136 missed
  - names: [('powershell', 57), ('reg', 17), ('schtasks', 11), ('spolsv', 6), ('netsh', 5), ('net', 4), ('wmic', 4), ('net1', 4)]
- **anomaly_score**: 6/136 missed
  - names: [('rundll32', 3), ('spolsv', 2), ('net1', 1)]

## Path coverage

- Malicious instances with 0 selected paths: 0/136
- Benign instances with 0 selected paths: 0/926
