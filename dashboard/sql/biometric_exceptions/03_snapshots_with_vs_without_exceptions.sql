-- Purpose: Compare snapshot counts with at least one exception vs none.
-- Connection: mosip_regprc

WITH x AS (
  SELECT
    ap.id,
    COALESCE(jsonb_array_length(COALESCE(ap.profile::jsonb->'exceptions', '[]'::jsonb)), 0) AS exc_len
  FROM regprc.anonymous_profile ap
  WHERE COALESCE(ap.is_deleted, FALSE) = FALSE
    AND ap.profile IS NOT NULL
)
SELECT
  CASE WHEN exc_len > 0 THEN 'with_biometric_exception' ELSE 'without_exception' END AS category,
  COUNT(*) AS snapshot_count
FROM x
GROUP BY 1
ORDER BY 1;
