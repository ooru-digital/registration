-- Purpose: New UIN rows per month (by cr_dtimes in ID Repo).
-- Connection: mosip_idrepo
-- Gap: Clock differs from registration packet dates; use for identity-store trend.

SELECT
  DATE_TRUNC('month', cr_dtimes)::date AS month_start,
  COUNT(*) AS uin_created_count
FROM idrepo.uin
WHERE COALESCE(is_deleted, FALSE) = FALSE
GROUP BY DATE_TRUNC('month', cr_dtimes)
ORDER BY month_start;
