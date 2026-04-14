-- Purpose: PROCESSED registrations per calendar month (by registration_list.registration_date).
-- Connection: mosip_regprc
-- Gap: Uses registration_date from client; alternatively use r.pkt_cr_dtimes for packet-created month.

SELECT
  DATE_TRUNC('month', rl.registration_date)::date AS month_start,
  COUNT(*) AS processed_count
FROM regprc.registration r
INNER JOIN regprc.registration_list rl
  ON rl.workflow_instance_id = r.workflow_instance_id
WHERE COALESCE(r.is_deleted, FALSE) = FALSE
  AND COALESCE(rl.is_deleted, FALSE) = FALSE
  AND COALESCE(r.is_active, TRUE) = TRUE
  AND r.status_code = 'PROCESSED'
  AND rl.registration_date IS NOT NULL
GROUP BY DATE_TRUNC('month', rl.registration_date)
ORDER BY month_start;
