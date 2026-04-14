-- Purpose: Matrix: center_id × status_code counts.
-- Connection: mosip_regprc

SELECT
  COALESCE(rl.center_id, '(null)') AS center_id,
  r.status_code,
  COUNT(*) AS packet_count
FROM regprc.registration r
INNER JOIN regprc.registration_list rl
  ON rl.workflow_instance_id = r.workflow_instance_id
WHERE COALESCE(r.is_deleted, FALSE) = FALSE
  AND COALESCE(rl.is_deleted, FALSE) = FALSE
  AND COALESCE(r.is_active, TRUE) = TRUE
GROUP BY rl.center_id, r.status_code
ORDER BY center_id, packet_count DESC;
