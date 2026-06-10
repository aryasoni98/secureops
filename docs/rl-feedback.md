# RL Feedback & Finding Ranking

SecureOps ranks findings using a per-tenant LinUCB contextual bandit
(`secureops-rl`). Analyst decisions become rewards:

| Action | Reward |
| --- | --- |
| `confirm` | `+1.0` |
| `escalate` | `+1.5` |
| `dismiss` | `-1.0` |

Rewards decay at `0.95^hours` - older feedback counts less.

## Feature vector

`severity` + `blast_radius_norm` + `exposed_internet` + `recency_decay` +
one-hot `rule_category` + one-hot `cloud` + bias.

## Posting feedback

```bash
curl -X POST http://127.0.0.1:8080/api/v1/rl/feedback \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{
    "severity": 4,
    "blast_radius_norm": 0.9,
    "exposed": true,
    "rule_category": 0,
    "cloud": 0,
    "recency": 1.0,
    "action": "confirm",
    "finding_id": "abc-123"
  }'
```

## Telemetry

`GET /api/v1/rl/stats` returns the number of online updates, the feature
dimension, and the exploration `alpha`. Surface it on the `/usage` dashboard.

## Math

Online ridge regression via the Sherman-Morrison rank-1 identity, so each
update is `O(d^2)` and the model needs no BLAS/LAPACK dependency.

## Quality metrics

`secureops_rl::ndcg_at_k` and `precision_at_k` are exposed for offline
evaluation. Promote a new model when NDCG@10 improves > 0.02 on the held-out
20% of recent feedback.
