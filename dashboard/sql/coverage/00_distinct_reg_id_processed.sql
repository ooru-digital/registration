-- Purpose: Distinct registration IDs (reg_id) in PROCESSED state (packet grain).
-- Connection: mosip_regprc
-- Gap: One person could theoretically have multiple reg_ids over time (updates); usually one row per workflow_instance.

SELECT
  COUNT(DISTINCT r.reg_id) AS distinct_reg_id_processed
FROM regprc.registration r
WHERE COALESCE(r.is_deleted, FALSE) = FALSE
  AND COALESCE(r.is_active, TRUE) = TRUE
  AND r.status_code = 'PROCESSED';
