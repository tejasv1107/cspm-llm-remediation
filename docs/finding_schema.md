# Unified finding schema

Every component after ingestion works with `FindingRecord`
([`ingestion/schema.py`](../ingestion/schema.py)) instead of raw ASFF JSON. The mapping from ASFF is in
[`ingestion/finding_normaliser.py`](../ingestion/finding_normaliser.py).

## Fields

| Field | Type | ASFF source | Notes |
|---|---|---|---|
| `finding_id` | `str` | `Id` | Unique finding ARN. Hashed by the anonymiser. |
| `account_id` | `str` | `AwsAccountId` | 12 digits raw; 16-hex SHA-256 pseudonym once anonymised. |
| `severity` | `Severity` | `Severity.Label` | INFORMATIONAL < LOW < MEDIUM < HIGH < CRITICAL. |
| `title` | `str` | `Title` | |
| `resource_type` | `str` | `Resources[0].Type` | e.g. `AwsS3Bucket`; `Other` if absent. |
| `resource_arn` | `str` | `Resources[0].Id` | Replaced by a synthetic ARN when anonymised. |
| `region` | `str` | `Resources[0].Region`, else `Region` | |
| `created_at` | `datetime` (UTC) | `CreatedAt` | Timezone-aware. |
| `updated_at` | `datetime` (UTC) | `UpdatedAt` | Timezone-aware. |
| `workflow_status` | `WorkflowStatus` | `Workflow.Status` | NEW, NOTIFIED, RESOLVED, SUPPRESSED. |
| `account_tier` | `AccountTier` | `ACCOUNT_TIER_MAP`, else resource `Environment` tag | `prod` or `non-prod` (default). |
| `is_internet_exposed` | `bool` | derived | Known exposure control IDs, or exposure wording in title/description. |
| `recurrence_count` | `int >= 1` | derived | Findings sharing (account, control-or-title) in the batch. |
| `source_product` | `str` | `ProductName` | Default `Security Hub`. |
| `recommendation_text` | `str` | `Remediation.Recommendation.Text` | Empty if absent. |
| `control_id` | `str` | `Compliance.SecurityControlId`, else `ProductFields` | **Extra.** Drives module retrieval. |
| `client_id` | `str` | derived | **Extra.** Tenant key; defaults to `account_id`. Namespaces branches and files. |

The two **extra** fields go beyond the fifteen core fields. `control_id` is the strongest retrieval signal;
`client_id` is what keeps tenants apart (TS-05).

## Invariants

- `recurrence_count >= 1`; enum fields accept either the enum or its string value.
- Datetimes are always timezone-aware UTC (naive values are assumed UTC).
- `FindingRecord.from_dict(r.to_dict()) == r` (round-trips through JSON).

## Feature vector

Produced by [`classifier/feature_engineering.py`](../classifier/feature_engineering.py):

| Feature | Definition |
|---|---|
| `severity_num` | `Severity.rank`, 0 (INFORMATIONAL) to 4 (CRITICAL) |
| `is_prod` | 1 if `account_tier == prod` |
| `internet_exposed` | 1 if `is_internet_exposed` |
| `recurrence` | `recurrence_count` |
| `resource_type_encoded` | Index in a fixed vocabulary; unknown maps to `Other` |
| `age_days` | Days from `created_at` to the reference time |
