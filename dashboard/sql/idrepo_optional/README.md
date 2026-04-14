# Optional ID Repository SQL (second Metabase connection)

These queries run against **`mosip_idrepo`** only. Add a **separate** PostgreSQL database connection in Metabase pointing at `mosip_idrepo`.

Use on the **same dashboard** as `mosip_regprc` questions **without expecting SQL joins** between connections. Compare KPIs side-by-side in narrative or separate rows.

**Not used:** `uin_data` (encrypted identity JSON).

**Limitation:** `idrepo.uin` has **no** `center_id` — geographic metrics remain on regprc.

| File | Purpose |
|------|---------|
| `01_uin_total_active_not_deleted.sql` | Row count (not deleted) |
| `02_uin_by_status.sql` | Distribution by `status_code` |
| `03_uin_creation_by_month.sql` | UIN creation by month |
| `04_anonymous_profile_row_count_idrepo.sql` | `idrepo.anonymous_profile` rows |
| `05_uin_count_activated_status.sql` | **`ACTIVATED`** — count of stored identities (`COUNT(DISTINCT reg_id)`); latest RID per identity (CREATE/UPDATE agnostic) |
