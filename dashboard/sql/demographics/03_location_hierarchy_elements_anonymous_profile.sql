-- Purpose: Explode profile.location JSON array (each element is one hierarchy level value as string).
-- Connection: mosip_regprc
-- Gap: Array index order is deployment-specific (mapping: LOCATION_HIERARCHY_FOR_PROFILING).
--      Use position in result as ordinal level only after you map index -> level name.

SELECT
  loc.ordinality AS hierarchy_index_1_based,
  loc.value::text AS location_value,
  COUNT(*) AS snapshot_count
FROM regprc.anonymous_profile ap
CROSS JOIN LATERAL jsonb_array_elements_text(COALESCE(ap.profile::jsonb->'location', '[]'::jsonb))
  WITH ORDINALITY AS loc(value, ordinality)
WHERE COALESCE(ap.is_deleted, FALSE) = FALSE
  AND ap.profile IS NOT NULL
GROUP BY loc.ordinality, loc.value::text
ORDER BY hierarchy_index_1_based, snapshot_count DESC;
