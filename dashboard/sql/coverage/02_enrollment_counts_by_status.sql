-- Purpose: Volume by registration.status_code (workflow outcome).
-- Connection: mosip_regprc
-- Gap: Includes non-terminal statuses; interpret as pipeline mix, not unique persons.

SELECT
  r.status_code,
  COUNT(*) AS packet_count
FROM regprc.registration r
INNER JOIN regprc.registration_list rl
  ON rl.workflow_instance_id = r.workflow_instance_id
WHERE COALESCE(r.is_deleted, FALSE) = FALSE
  AND COALESCE(rl.is_deleted, FALSE) = FALSE
  AND COALESCE(r.is_active, TRUE) = TRUE
GROUP BY r.status_code
ORDER BY packet_count DESC, r.status_code;
