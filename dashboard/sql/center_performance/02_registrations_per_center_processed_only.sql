-- Purpose: PROCESSED packets per enrollment center.
-- Connection: mosip_regprc

SELECT
  COALESCE(rl.center_id, '(null)') AS center_id,
  COUNT(*) AS processed_packet_count
FROM regprc.registration r
INNER JOIN regprc.registration_list rl
  ON rl.workflow_instance_id = r.workflow_instance_id
WHERE COALESCE(r.is_deleted, FALSE) = FALSE
  AND COALESCE(rl.is_deleted, FALSE) = FALSE
  AND COALESCE(r.is_active, TRUE) = TRUE
  AND r.status_code = 'PROCESSED'
GROUP BY rl.center_id
ORDER BY processed_packet_count DESC;
