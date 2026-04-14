-- Purpose: Enrollment rate (%): PROCESSED count / population by geography key.
-- Connection: mosip_regprc
-- Gap: Denominator must align with registration_list.location_code (same encoding as sync: often Base64).
--
-- This query runs WITHOUT public.population_reference by default (population side is empty → enrollment_rate_percent is NULL).
-- After you create and load the table (see ../reference/population_reference_ddl.sql), replace the `population_reference` CTE
-- below with the commented SELECT from public.population_reference.

WITH population_reference AS (
  /* --- Default: no rows until you add inline VALUES or switch to the table below --- */
  SELECT *
  FROM (
    VALUES
      /* Example: ('YOUR_LOCATION_CODE_KEY', 'Readable region', 500000::bigint, 2024::smallint, 'Census'::varchar) */
      (NULL::varchar(64), NULL::varchar(256), NULL::bigint, NULL::smallint, NULL::varchar(512))
  ) AS t(location_code, region_name, population_total, reference_year, source)
  WHERE false

  /* --- After DDL + load, replace the whole WITH body above with:
  SELECT location_code, region_name, population_total, reference_year, source
  FROM public.population_reference
  --- */
)
SELECT
  e.location_code,
  p.region_name,
  p.population_total,
  e.processed_registrations,
  ROUND(
    100.0 * e.processed_registrations / NULLIF(p.population_total, 0),
    2
  ) AS enrollment_rate_percent
FROM (
  SELECT
    rl.location_code,
    COUNT(*) AS processed_registrations
  FROM regprc.registration r
  INNER JOIN regprc.registration_list rl
    ON rl.workflow_instance_id = r.workflow_instance_id
  WHERE COALESCE(r.is_deleted, FALSE) = FALSE
    AND COALESCE(rl.is_deleted, FALSE) = FALSE
    AND COALESCE(r.is_active, TRUE) = TRUE
    AND r.status_code = 'PROCESSED'
  GROUP BY rl.location_code
) e
LEFT JOIN population_reference p ON p.location_code = e.location_code
ORDER BY e.location_code;
