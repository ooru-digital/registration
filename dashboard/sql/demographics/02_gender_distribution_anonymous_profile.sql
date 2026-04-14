-- Purpose: Gender distribution from anonymous profile JSON (gender field).
-- Connection: mosip_regprc
-- Gap: Values are language-resolved strings from packet; multiple rows per packet possible.

SELECT
  COALESCE(profile::jsonb->>'gender', '(null)') AS gender,
  COUNT(*) AS snapshot_count
FROM regprc.anonymous_profile
WHERE COALESCE(is_deleted, FALSE) = FALSE
  AND profile IS NOT NULL
GROUP BY profile::jsonb->>'gender'
ORDER BY snapshot_count DESC;
