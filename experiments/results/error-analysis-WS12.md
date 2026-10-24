# Error analysis — WS12_WS12_k20_L5_seed20261025_predictions


## Chain-level recall (at least one malicious process in the spawn chain)

| Method | Chains detected | Chains | Recall |
|---|---|---|---|
| provdetector | 5 | 5 | 1.000 |
| rule | 0 | 5 | 0.000 |
| whitelist | 5 | 5 | 1.000 |
| anomaly_score | 5 | 5 | 1.000 |

## False positives (benign instances flagged)

- **provdetector**: 27/754 benign instances flagged
  - top process names: [('postgres', 10), ('conhost', 1), ('netstat', 1), ('notepad', 1), ('cmd', 1), ('wmiprvse', 1)]
- **rule**: 0/754 benign instances flagged
- **whitelist**: 45/754 benign instances flagged
  - top process names: [('postgres', 19), ('cmd', 2), ('conhost', 1), ('netstat', 1), ('notepad', 1), ('wmiprvse', 1)]
- **anomaly_score**: 45/754 benign instances flagged
  - top process names: [('postgres', 19), ('cmd', 2), ('conhost', 1), ('netstat', 1), ('notepad', 1), ('wmiprvse', 1)]

## False negatives (malicious instances missed)

- **provdetector**: 0/43 missed
- **rule**: 43/43 missed
  - names: [('cmd', 17), ('reg', 6), ('powershell', 4), ('ipconfig', 3), ('paexec', 2), ('taskhost', 1), ('arp', 1), ('paexec-2196-win2012-1', 1)]
- **whitelist**: 0/43 missed
- **anomaly_score**: 0/43 missed

## Path coverage

- Malicious instances with 0 selected paths: 0/43
- Benign instances with 0 selected paths: 0/754
