-- Purpose: Volume of anonymous profile snapshots by process_stage (workflow stage name when saved).
-- Connection: mosip_regprc
-- Gap: Explains why multiple rows exist per packet (different stages).

SELECT
  process_stage,
  COUNT(*) AS snapshot_count
FROM regprc.anonymous_profile
WHERE COALESCE(is_deleted, FALSE) = FALSE
GROUP BY process_stage
ORDER BY snapshot_count DESC;
