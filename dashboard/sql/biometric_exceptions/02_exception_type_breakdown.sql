-- Purpose: Break down exception entries by biometric type (and subType) from JSON.
-- Connection: mosip_regprc
-- Gap: One packet may contribute multiple rows; multiple snapshots per packet inflate counts.

SELECT
  COALESCE(ex->>'type', '(null)') AS exception_type,
  COALESCE(ex->>'subType', '(null)') AS exception_sub_type,
  COUNT(*) AS exception_entry_count
FROM regprc.anonymous_profile ap
CROSS JOIN LATERAL jsonb_array_elements(COALESCE(ap.profile::jsonb->'exceptions', '[]'::jsonb)) AS ex
WHERE COALESCE(ap.is_deleted, FALSE) = FALSE
  AND ap.profile IS NOT NULL
GROUP BY ex->>'type', ex->>'subType'
ORDER BY exception_entry_count DESC;
