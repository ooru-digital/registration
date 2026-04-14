-- Purpose: Snapshot counts by enrollmentCenterId inside profile JSON (no join to registration_list).
-- Connection: mosip_regprc
-- Gap: Compare to registration_list.center_id in a separate chart; should match if metadata is consistent.

SELECT
  COALESCE(profile::jsonb->>'enrollmentCenterId', '(null)') AS enrollment_center_id,
  COUNT(*) AS snapshot_count
FROM regprc.anonymous_profile
WHERE COALESCE(is_deleted, FALSE) = FALSE
  AND profile IS NOT NULL
GROUP BY profile::jsonb->>'enrollmentCenterId'
ORDER BY snapshot_count DESC;
