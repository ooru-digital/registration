# Registration dashboard (Metabase + SQL)

This folder contains **native SQL** intended for **Metabase** (or any PostgreSQL client) against **`mosip_regprc`**. Optional queries under `sql/idrepo_optional/` target **`mosip_idrepo`** as a **second database connection** (same dashboard, **no cross-DB join**).

## Layout

| Folder | Purpose |
|--------|---------|
| [`sql/README.md`](sql/README.md) | **Index** of every query file. |
| [`sql/coverage/`](sql/coverage/) | Enrollment counts, status mix, coverage % (needs population reference). |
| [`sql/demographics/`](sql/demographics/) | Age, gender, location, `enrollmentCenterId` from `regprc.anonymous_profile.profile` JSON. |
| [`sql/center_performance/`](sql/center_performance/) | Per–enrollment-center and `location_code` metrics from `registration` + `registration_list`. |
| [`sql/biometric_exceptions/`](sql/biometric_exceptions/) | Counts and breakdowns from `profile.exceptions` JSON. |
| [`sql/reference/`](sql/reference/) | DDL for a **population** table you maintain in the same DB Metabase uses. |
| [`sql/idrepo_optional/`](sql/idrepo_optional/) | Companion KPIs from ID Repository (UIN inventory); **separate Metabase connection**. |
| [`docs/GAPS_AND_ANALYSIS.md`](docs/GAPS_AND_ANALYSIS.md) | Consolidated gaps and follow-ups. |

## Metabase setup

1. Add a PostgreSQL connection to **`mosip_regprc`** (schema `regprc`).
2. Create **Saved Questions** from the `.sql` files (Native query). Replace date/center filters with Metabase **field filters** or **variables** (`{{start_date}}` etc.) as needed.
3. Optionally add a second connection to **`mosip_idrepo`** and use only files under `sql/idrepo_optional/`.

### Standard Metabase UI flow (repeat for each question)

These steps apply every time you turn a SQL file into a chart or KPI. Labels may vary slightly by Metabase version (e.g. **SQL query** vs **Native query**).

1. **New** → **Question** → **Native query** / **SQL query**.
2. Under **Pick your data**, choose the database (**`mosip_regprc`** or **`mosip_idrepo`**).
3. Paste the SQL from the file. Configure **Variables** (top of editor) if you add `{{start_date}}` or `{{center_id}}` — set type (Date, Text, Number) and optional default.
4. Click **Run** ▶ and confirm the result grid looks correct.
5. Click **Visualization** (bottom of the screen, or chart icon) to leave the default **Table** view.
6. Pick a visualization type: **Number**, **Bar**, **Line**, **Pie**, **Row**, **Table**, etc.
7. Open **Settings** (gear on the visualization or right sidebar):
   - **Number:** choose the single metric column under **Which column should be the metric?** (or “Scalar field”).
   - **Bar / Line / Row:** set **X-axis** (usually category or time) and **Y-axis** (count or measure). For horizontal bars, use **Row** chart or swap axes in bar settings.
   - **Pie:** set **Metric** and **Dimension** (slice field).
   - **Table:** reorder or hide columns under **Columns**; enable conditional formatting if needed.
8. **Formatting** (optional): column names, number style (decimals), date format.
9. **Save** → enter the **suggested question title** → choose a **Collection** → **Save**.
10. **Add to dashboard:** **Save** dialog may offer **Add to dashboard**; or open your dashboard → **Edit** → **Add questions** → pick this saved question. Resize the card on the grid.
11. **Dashboard filters** (optional): while editing the dashboard, **Add a filter** (date/category) → **Link to dashboard card** → map to a **Variable** on the question if you defined one in SQL.
12. **Card-level override:** click a card on the dashboard → **Click to change** / pencil → you can change visualization type for that card only without changing the saved question definition.

Use the per-question table below for the recommended visualization type and axis/column choices.

---

## Metabase questions to create (Saved Questions)

**Suggested question title** = name for the Saved Question. **SQL file** = path under this `dashboard/` folder. **Visualization** = recommended starting type. **Metabase UI steps** = what to set after **Run** in the visualization builder.

### Connection: `mosip_regprc`

| Suggested Metabase question title | SQL file | Visualization | Metabase UI steps (after Run) |
|-----------------------------------|----------|-----------------|-------------------------------|
| **Coverage — Distinct reg IDs (PROCESSED)** | [`sql/coverage/00_distinct_reg_id_processed.sql`](sql/coverage/00_distinct_reg_id_processed.sql) | Number | Visualization → **Number** → Settings: metric column **`distinct_reg_id_processed`**. |
| **Coverage — Enrollment count (PROCESSED packets)** | [`sql/coverage/01_enrollment_count_processed.sql`](sql/coverage/01_enrollment_count_processed.sql) | Number | **Number** → metric **`processed_packet_count`**. |
| **Coverage — Enrollment counts by status** | [`sql/coverage/02_enrollment_counts_by_status.sql`](sql/coverage/02_enrollment_counts_by_status.sql) | Bar or Row | **Bar** (vertical): X = **`status_code`**, Y = **`packet_count`**. Or **Row** chart for long labels: Y = **`status_code`**, X = **`packet_count`**. |
| **Coverage — PROCESSED trend by month** | [`sql/coverage/03_enrollment_trend_by_month.sql`](sql/coverage/03_enrollment_trend_by_month.sql) | Line or Area | **Line**: X = **`month_start`** (type: time), Y = **`processed_count`**. Enable points if few months. |
| **Coverage — Enrollment rate vs population (by location)** | [`sql/coverage/04_coverage_enrollment_rate.sql`](sql/coverage/04_coverage_enrollment_rate.sql) | Table or Bar | **Table**: **`location_code`**, **`processed_registrations`**, **`enrollment_rate_percent`** (null until population CTE or **`public.population_reference`** is filled). Or **Bar**: X = **`location_code`**, Y = **`enrollment_rate_percent`**. |
| **Center performance — Registrations per center (all statuses)** | [`sql/center_performance/01_registrations_per_center.sql`](sql/center_performance/01_registrations_per_center.sql) | Bar or Row | **Bar**: X = **`center_name`** (decoded from `registration_list.name` Base64 UTF-8), Y = **`packet_count`**. Limit top N in **Settings** if crowded. See SQL comment if Base64 is URL-safe. |
| **Center performance — PROCESSED per center** | [`sql/center_performance/02_registrations_per_center_processed_only.sql`](sql/center_performance/02_registrations_per_center_processed_only.sql) | Bar or Row | Same as above: X = **`center_id`**, Y = **`processed_packet_count`**. |
| **Center performance — Registrations by location code** | [`sql/center_performance/03_registrations_by_location_code.sql`](sql/center_performance/03_registrations_by_location_code.sql) | Bar or Row | X = **`location_label`** (Base64-decoded `location_code`, same logic as center `name` in `01`), Y = **`packet_count`**. |
| **Center performance — Center × status matrix** | [`sql/center_performance/04_registrations_by_center_and_status.sql`](sql/center_performance/04_registrations_by_center_and_status.sql) | Table or Pivot | **Table** is simplest. For heatmap-style, use **Pivot Table** (if available) with rows = **`center_id`**, columns = **`status_code`**, values = **`packet_count`**. |
| **Center performance — PROCESSED by center and location** | [`sql/center_performance/05_registrations_by_center_location_processed.sql`](sql/center_performance/05_registrations_by_center_location_processed.sql) | Table | **Table**: **`center_label`**, **`location_label`** (Base64-decoded), **`processed_count`**. Metabase variables **`{{center_id}}`**, **`{{center_name}}`**, **`{{location_name}}`** (see SQL header). Sort by **`processed_count`**. |
| **Center performance — Processing lag (avg/median days, PROCESSED)** | [`sql/center_performance/06_processing_lag_days_processed.sql`](sql/center_performance/06_processing_lag_days_processed.sql) | Table or Bar | **Table**: show **`avg_lag_days`**, **`median_lag_days`**, **`processed_count`**. Or **Bar** (two series): X = **`center_id`**, Y = first metric; add second series in **Data** tab if Metabase version supports multi-series from same query. |
| **Demographics — Age buckets (anonymous profile)** | [`sql/demographics/01_age_buckets_anonymous_profile.sql`](sql/demographics/01_age_buckets_anonymous_profile.sql) | Bar or Pie | **Bar**: X = **`age_bucket`**, Y = **`snapshot_count`**. **Pie**: slice = **`age_bucket`**, metric = **`snapshot_count`**. |
| **Demographics — Gender distribution (anonymous profile)** | [`sql/demographics/02_gender_distribution_anonymous_profile.sql`](sql/demographics/02_gender_distribution_anonymous_profile.sql) | Pie or Row | **Pie**: dimension **`gender`**, metric **`snapshot_count`**. |
| **Demographics — Location hierarchy elements (anonymous profile)** | [`sql/demographics/03_location_hierarchy_elements_anonymous_profile.sql`](sql/demographics/03_location_hierarchy_elements_anonymous_profile.sql) | Table or Bar | **Table**: filter/sort by **`hierarchy_index_1_based`** then **`snapshot_count`**. Or **Bar**: X = **`location_value`** (may be long; use **Row** chart). |
| **Demographics — Enrollment center ID from profile JSON** | [`sql/demographics/04_enrollment_center_id_from_profile.sql`](sql/demographics/04_enrollment_center_id_from_profile.sql) | Bar or Row | X = **`enrollment_center_id`**, Y = **`snapshot_count`**. |
| **Demographics — Anonymous profile snapshots by process stage** | [`sql/demographics/05_anonymous_profile_by_process_stage.sql`](sql/demographics/05_anonymous_profile_by_process_stage.sql) | Bar | X = **`process_stage`**, Y = **`snapshot_count`**. |
| **Biometric exceptions — Snapshots with exceptions (count)** | [`sql/biometric_exceptions/01_count_snapshots_with_exceptions.sql`](sql/biometric_exceptions/01_count_snapshots_with_exceptions.sql) | Number | **Number** → metric **`profile_snapshots_with_exception`**. |
| **Biometric exceptions — Breakdown by type / subType** | [`sql/biometric_exceptions/02_exception_type_breakdown.sql`](sql/biometric_exceptions/02_exception_type_breakdown.sql) | Table or Bar | **Table**: sort by **`exception_entry_count`**. Or stacked **Bar** if you combine dimensions; usually **Table** with **`exception_type`**, **`exception_sub_type`**, **`exception_entry_count`**. |
| **Biometric exceptions — With vs without exceptions** | [`sql/biometric_exceptions/03_snapshots_with_vs_without_exceptions.sql`](sql/biometric_exceptions/03_snapshots_with_vs_without_exceptions.sql) | Pie or Bar | **Pie**: **`category`** vs **`snapshot_count`**. **Bar**: X = **`category`**, Y = **`snapshot_count`**. |

**Not a Metabase question — run in DB once (prerequisite for coverage rate):** [`sql/reference/population_reference_ddl.sql`](sql/reference/population_reference_ddl.sql) (creates `public.population_reference`; load population data, then use the coverage enrollment-rate question above).

### Connection: `mosip_idrepo` (optional second database)

| Suggested Metabase question title | SQL file | Visualization | Metabase UI steps (after Run) |
|-----------------------------------|----------|-----------------|-------------------------------|
| **ID Repo — UIN total count (not deleted)** | [`sql/idrepo_optional/01_uin_total_active_not_deleted.sql`](sql/idrepo_optional/01_uin_total_active_not_deleted.sql) | Number | **Number** → metric **`uin_row_count`**. Use **`mosip_idrepo`** when creating the question. |
| **ID Repo — UIN count by status** | [`sql/idrepo_optional/02_uin_by_status.sql`](sql/idrepo_optional/02_uin_by_status.sql) | Bar or Pie | **Bar**: X = **`status_code`**, Y = **`cnt`**. **Pie**: dimension **`status_code`**, metric **`cnt`**. |
| **ID Repo — UIN creation by month** | [`sql/idrepo_optional/03_uin_creation_by_month.sql`](sql/idrepo_optional/03_uin_creation_by_month.sql) | Line or Bar | **Line**: X = **`month_start`** (time), Y = **`uin_created_count`**. |
| **ID Repo — Anonymous profile row count** | [`sql/idrepo_optional/04_anonymous_profile_row_count_idrepo.sql`](sql/idrepo_optional/04_anonymous_profile_row_count_idrepo.sql) | Number | **Number** → metric **`idrepo_anonymous_profile_rows`**. |
| **ID Repo — Activated UIN / unique reg IDs in identity store** | [`sql/idrepo_optional/05_uin_count_activated_status.sql`](sql/idrepo_optional/05_uin_count_activated_status.sql) | Number | **Number** → metric **`activated_identity_reg_id_count`**. One row per identity in `idrepo.uin`; `reg_id` is the latest RID (CREATE or UPDATE). |

These cards sit on the **same dashboard** as `mosip_regprc` questions but use a **separate** Metabase connection; they are **not** joined in SQL to regprc.

## Metric support summary

### Fully supported (relational: `registration` + `registration_list`)

- Counts and trends by **`status_code`** (e.g. `PROCESSED`, `PROCESSING`, `REJECTED`).
- **Registrations per `center_id`**, per **`location_code`**, with date filters.
- Mix of statuses per center / location.

**Tables:** `regprc.registration`, `regprc.registration_list` joined on **`workflow_instance_id`**.

### Partially supported (`regprc.anonymous_profile`)

JSON fields follow MOSIP `AnonymousProfileDTO` (e.g. `yearOfBirth`, `gender`, `location`, `enrollmentCenterId`, `exceptions`).

| Limitation | Impact |
|------------|--------|
| No **`reg_id`** on `anonymous_profile` | Cannot join anonymous rows to `registration_list` on RID. |
| **Multiple rows** per packet (workflow snapshots) | Demographic and exception **counts are not unique applicants**; may exceed packet counts. |
| **`location` array** | Which index is “district” is **deployment-specific** (mapping JSON). |

**Mitigations:** Document chart titles as “anonymous profile snapshots”; use **`enrollmentCenterId`** inside JSON for center-aligned anonymous views; consider ETL or a future **`reg_id`** column for alignment.

### Coverage vs population

- **Numerator:** from `regprc` (e.g. `PROCESSED` or definitions in each SQL file).
- **Denominator:** **not** in MOSIP DDL — load census/population into a table (see [`sql/reference/population_reference_ddl.sql`](sql/reference/population_reference_ddl.sql)).

### Not in SQL (packet store / classifier)

- Packet tags such as **`EXCEPTION_BIOMETRICS`** from classifier metaInfo are **not** in these tables; use **`exceptions`** inside **`anonymous_profile.profile`** instead.

### Optional: `mosip_idrepo` (independent dashboard cards)

- **`idrepo.uin`:** canonical **UIN row counts**, **status_code** distribution, **creation time** trends — **not** broken down by center (no `center_id` on `uin`; use regprc for geography).
- **`uin_data`:** **not used** (encrypted); demographics stay on **`anonymous_profile`**.

## Key business constants (confirm in your environment)

- **`registration.status_code`:** `PROCESSED` = processor completed successfully (often aligned with UIN issuance; final truth for UIN is ID Repo).
- Adjust filters if your deployment uses different codes or soft-delete rules.

## Files and gaps

Each SQL file starts with a short header comment listing **purpose** and **known gaps**. See the [Gaps and further analysis](docs/GAPS_AND_ANALYSIS.md) note for a consolidated list.
