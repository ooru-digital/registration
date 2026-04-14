# SQL index (`mosip_regprc`)

For **Metabase Saved Question titles**, **SQL files**, **recommended visualizations**, and **Metabase UI steps**, see **[`../README.md`](../README.md)** (“Standard Metabase UI flow” and “Metabase questions to create”).

| File | Metric |
|------|--------|
| **coverage/** | |
| `00_distinct_reg_id_processed.sql` | Distinct `reg_id` count, PROCESSED |
| `01_enrollment_count_processed.sql` | Packet count PROCESSED |
| `02_enrollment_counts_by_status.sql` | Counts by `status_code` |
| `03_enrollment_trend_by_month.sql` | PROCESSED per month |
| `04_coverage_enrollment_rate.sql` | Coverage % — optional pop CTE or `population_reference` table |
| **center_performance/** | |
| `01_registrations_per_center.sql` | Packets per center — `name` decoded from Base64 (UTF-8) |
| `02_registrations_per_center_processed_only.sql` | PROCESSED per center |
| `03_registrations_by_location_code.sql` | Packets per location — `location_code` decoded from Base64 (UTF-8) as `location_label` |
| `04_registrations_by_center_and_status.sql` | Center × status matrix |
| `05_registrations_by_center_location_processed.sql` | PROCESSED by center + location; decoded labels; Metabase filters |
| `06_processing_lag_days_processed.sql` | Avg/median lag days (packet → latest trn) |
| **demographics/** | |
| `01_age_buckets_anonymous_profile.sql` | Age buckets from JSON |
| `02_gender_distribution_anonymous_profile.sql` | Gender from JSON |
| `03_location_hierarchy_elements_anonymous_profile.sql` | Unnested `location` array |
| `04_enrollment_center_id_from_profile.sql` | `enrollmentCenterId` from JSON |
| `05_anonymous_profile_by_process_stage.sql` | Snapshots by `process_stage` |
| **biometric_exceptions/** | |
| `01_count_snapshots_with_exceptions.sql` | Snapshots with non-empty `exceptions` |
| `02_exception_type_breakdown.sql` | By `type` / `subType` |
| `03_snapshots_with_vs_without_exceptions.sql` | With vs without |
| **reference/** | |
| `population_reference_ddl.sql` | Create population table for coverage |

# Optional (`mosip_idrepo`)

| File | Metric |
|------|--------|
| `idrepo_optional/01_uin_total_active_not_deleted.sql` | All UIN rows (not deleted) |
| `idrepo_optional/02_uin_by_status.sql` | Count by `status_code` |
| `idrepo_optional/03_uin_creation_by_month.sql` | UIN creation trend |
| `idrepo_optional/04_anonymous_profile_row_count_idrepo.sql` | `idrepo.anonymous_profile` rows |
| `idrepo_optional/05_uin_count_activated_status.sql` | **ACTIVATED** — distinct `reg_id` / identities stored |

See [`idrepo_optional/README.md`](idrepo_optional/README.md).
