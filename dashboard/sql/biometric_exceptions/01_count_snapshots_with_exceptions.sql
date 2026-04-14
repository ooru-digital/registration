-- Purpose: Count anonymous_profile rows where exceptions array is non-empty.
-- Connection: mosip_regprc
-- Gap: Snapshots, not unique packets; may over-count vs distinct registrations.

SELECT
  COUNT(*) AS profile_snapshots_with_exception
FROM regprc.anonymous_profile
WHERE COALESCE(is_deleted, FALSE) = FALSE
  AND profile IS NOT NULL
  AND jsonb_typeof(profile::jsonb->'exceptions') = 'array'
  AND jsonb_array_length(COALESCE(profile::jsonb->'exceptions', '[]'::jsonb)) > 0;
