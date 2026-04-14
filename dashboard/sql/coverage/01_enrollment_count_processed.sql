-- Purpose: Count registrations whose latest workflow outcome is PROCESSED (typical "successfully processed" in reg proc).
-- Connection: mosip_regprc
-- Gap: "PROCESSED" is processor status; canonical UIN issuance is in idrepo (optional companion cards).
-- Parameters (Metabase): replace date range or use {{variables}}.

SELECT
  COUNT(*) AS processed_packet_count
FROM regprc.registration r
INNER JOIN regprc.registration_list rl
  ON rl.workflow_instance_id = r.workflow_instance_id
WHERE COALESCE(r.is_deleted, FALSE) = FALSE
  AND COALESCE(rl.is_deleted, FALSE) = FALSE
  AND COALESCE(r.is_active, TRUE) = TRUE
  AND r.status_code = 'PROCESSED'
  -- Optional time filter:
  -- AND rl.registration_date >= DATE '2025-01-01'
  -- AND rl.registration_date < DATE '2026-01-01'
;
