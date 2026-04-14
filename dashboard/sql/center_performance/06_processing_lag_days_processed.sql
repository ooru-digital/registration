-- Purpose: Rough processing duration (days) from packet creation to latest transaction time.
-- Connection: mosip_regprc
-- Gap: latest_trn_dtimes is last stage time, not strictly "UIN issued" moment; null-safe.

SELECT
  COALESCE(rl.center_id, '(null)') AS center_id,
  ROUND(AVG(EXTRACT(EPOCH FROM (r.latest_trn_dtimes - r.pkt_cr_dtimes)) / 86400.0), 2) AS avg_lag_days,
  PERCENTILE_CONT(0.5) WITHIN GROUP (
    ORDER BY EXTRACT(EPOCH FROM (r.latest_trn_dtimes - r.pkt_cr_dtimes)) / 86400.0
  ) AS median_lag_days,
  COUNT(*) AS processed_count
FROM regprc.registration r
INNER JOIN regprc.registration_list rl
  ON rl.workflow_instance_id = r.workflow_instance_id
WHERE COALESCE(r.is_deleted, FALSE) = FALSE
  AND COALESCE(rl.is_deleted, FALSE) = FALSE
  AND COALESCE(r.is_active, TRUE) = TRUE
  AND r.status_code = 'PROCESSED'
  AND r.pkt_cr_dtimes IS NOT NULL
  AND r.latest_trn_dtimes IS NOT NULL
GROUP BY rl.center_id
ORDER BY processed_count DESC;
