# Confusion matrices (balanced test, t=3)

| Train → Test | Method | TN | FP | FN | TP |
|---|---|---|---|---|---|
| WS12→WS12 | provdetector | 34 | 9 | 0 | 43 |
| WS12→WS12 | rule_heuristic | 43 | 0 | 43 | 0 |
| WS12→WS12 | whitelist | 30 | 13 | 0 | 43 |
| WS12→WS12 | anomaly_score | 30 | 13 | 0 | 43 |
| WS12→WS12 | frequency_score | 37 | 6 | 0 | 43 |
| W10→W10 | provdetector | 107 | 29 | 32 | 104 |
| W10→W10 | rule_heuristic | 136 | 0 | 136 | 0 |
| W10→W10 | whitelist | 136 | 0 | 136 | 0 |
| W10→W10 | anomaly_score | 96 | 40 | 6 | 130 |
| W10→W10 | frequency_score | 95 | 41 | 4 | 132 |
| W10→WS12 | provdetector | 42 | 1 | 24 | 19 |
| W10→WS12 | rule_heuristic | 43 | 0 | 43 | 0 |
| W10→WS12 | whitelist | 43 | 0 | 43 | 0 |
| W10→WS12 | anomaly_score | 1 | 42 | 10 | 33 |
| W10→WS12 | frequency_score | 2 | 41 | 10 | 33 |
| WS12→W10 | provdetector | 5 | 131 | 0 | 136 |
| WS12→W10 | rule_heuristic | 136 | 0 | 136 | 0 |
| WS12→W10 | whitelist | 0 | 136 | 0 | 136 |
| WS12→W10 | anomaly_score | 0 | 136 | 0 | 136 |
| WS12→W10 | frequency_score | 0 | 136 | 0 | 136 |
