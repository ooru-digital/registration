-- Purpose: Age bucket distribution from anonymous profile snapshots (yearOfBirth in JSON).
-- Connection: mosip_regprc
-- Gap: Multiple anonymous_profile rows per packet possible; counts are NOT unique applicants.
--      Cannot join to registration_list on reg_id (column absent).

WITH p AS (
  SELECT
    profile::jsonb AS j,
    cr_dtimes
  FROM regprc.anonymous_profile
  WHERE COALESCE(is_deleted, FALSE) = FALSE
    AND profile IS NOT NULL
),
ages AS (
  SELECT
    EXTRACT(YEAR FROM CURRENT_DATE)::int - (j->>'yearOfBirth')::int AS age_years
  FROM p
  WHERE (j->>'yearOfBirth') IS NOT NULL
    AND (j->>'yearOfBirth') ~ '^[0-9]+$'
)
SELECT
  s.age_bucket,
  s.snapshot_count
FROM (
  SELECT
    CASE
      WHEN age_years < 0 OR age_years > 120 THEN 'unknown_invalid'
      WHEN age_years <= 5 THEN '0-5'
      WHEN age_years <= 17 THEN '6-17'
      WHEN age_years <= 64 THEN '18-64'
      ELSE '65+'
    END AS age_bucket,
    COUNT(*) AS snapshot_count
  FROM ages
  GROUP BY 1
) s
ORDER BY
  CASE s.age_bucket
    WHEN '0-5' THEN 1
    WHEN '6-17' THEN 2
    WHEN '18-64' THEN 3
    WHEN '65+' THEN 4
    ELSE 5
  END;
