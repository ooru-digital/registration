# Gaps and further analysis

Use this document with [`../README.md`](../README.md) to plan ETL, schema changes, or product decisions.

## 1. `anonymous_profile` grain

| Gap | Analysis direction |
|-----|-------------------|
| No `reg_id` / `workflow_instance_id` | Cannot SQL-join anonymous metrics to `registration_list` for the same applicant. **Options:** add column in app + migration; or ETL mart with RID. |
| Multiple rows per registration | Workflow saves repeated profiles. **Options:** dedupe policy (e.g. latest `cr_dtimes` per window — still not true RID dedup without key); or mart. |
| Demographic totals ≠ `PROCESSED` counts | Expected if charts mix snapshot counts vs distinct packets. **Options:** separate dashboards or document denominators clearly. |

## 2. Geography

| Gap | Analysis direction |
|-----|-------------------|
| `registration_list.location_code` vs “district” | Confirm with **master data** what level `location_code` represents. |
| `profile.location` JSON array | Order of entries follows **identity mapping** (`LOCATION_HIERARCHY_FOR_PROFILING`). Map index → level (region/province/district) per deployment. |
| Human-readable labels | **`master.location`** is usually another database. **Options:** replicate a small **dim** table into `mosip_regprc`; Metabase second connection for lookup; or show codes only. |

## 3. Coverage percentage

| Gap | Analysis direction |
|-----|-------------------|
| Population not in MOSIP | Load [`population_reference`](../sql/reference/population_reference_ddl.sql) (or national file) with keys aligned to `location_code` or district. |
| Numerator definition | Choose: `PROCESSED` packets, distinct `reg_id`, or UIN count from idrepo — each answers a different question. |

## 4. Biometric exceptions

| Gap | Analysis direction |
|-----|-------------------|
| SQL uses `profile.exceptions` only | Classifier **tags** in packet storage are out of scope here. |
| Duplicate profile rows | Exception counts may **over-count** vs distinct applicants; same mitigations as §1. |

## 5. `mosip_regprc` vs `mosip_idrepo`

| Gap | Analysis direction |
|-----|-------------------|
| No single-SQL join in Metabase | Use **two cards** (regprc + idrepo) or **FDW/ETL** into one DB for reconciled KPIs. |
| `PROCESSED` vs UIN row | Compare **side-by-side**; investigate drift (failures after PROCESSED, corrections, timing). |
| Center-level UIN metrics | **`idrepo.uin`** has no center; use **regprc** for geography or ETL `reg_id` → center. |

## 6. Optional next steps

1. **Schema:** `reg_id` on `regprc.anonymous_profile` (product + DDL migration).
2. **Reporting mart:** nightly job: RID, center, district, demographics, exception flags, status — single star schema for Metabase.
3. **Metabase models:** curated models on top of raw SQL for non-SQL users.
