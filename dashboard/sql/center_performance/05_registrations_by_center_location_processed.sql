-- Purpose: PROCESSED counts by center + location with Base64-decoded labels (UTF-8).
-- Connection: mosip_regprc
-- Decoding: same as 03_registrations_by_location_code.sql for both center_id and location_code (URL-safe → standard, pad, decode).
--
-- Metabase (Native query → Variables):
--   {{center_id}}       — optional Text; exact match on **stored** encoded rl.center_id (omit to show all).
--   {{center_name}}     — optional Text; ILIKE on decoded center_label (omit to show all).
--   {{location_name}}   — optional Text; ILIKE on decoded location_label (omit to show all).
-- Create three variables in Metabase; use [[ ]] optional clauses (already below). Leave variables empty or unset to disable that filter.

SELECT
  x.center_label,
  x.location_label,
  COUNT(*) AS processed_count
FROM (
  SELECT
    CASE
      WHEN rl.center_id IS NULL OR btrim(rl.center_id) = '' THEN '(no center)'
      WHEN length(dc.b64_clean) % 4 = 1 THEN '(invalid base64 length)'
      ELSE convert_from(decode(dc.b64_padded, 'base64'), 'UTF8')
    END AS center_label,
    CASE
      WHEN rl.location_code IS NULL OR btrim(rl.location_code) = '' THEN '(no location)'
      WHEN length(dl.b64_clean) % 4 = 1 THEN '(invalid base64 length)'
      ELSE convert_from(decode(dl.b64_padded, 'base64'), 'UTF8')
    END AS location_label
  FROM regprc.registration r
  INNER JOIN regprc.registration_list rl
    ON rl.workflow_instance_id = r.workflow_instance_id
  CROSS JOIN LATERAL (
    SELECT
      prep.b64_clean,
      CASE
        WHEN length(prep.b64_clean) % 4 = 0 THEN prep.b64_clean
        ELSE prep.b64_clean || repeat('=', (4 - length(prep.b64_clean) % 4) % 4)
      END AS b64_padded
    FROM (
      SELECT
        regexp_replace(
          translate(btrim(COALESCE(rl.center_id, '')), '-_', '+/'),
          '\s',
          '',
          'g'
        ) AS b64_clean
    ) prep
  ) dc
  CROSS JOIN LATERAL (
    SELECT
      prep.b64_clean,
      CASE
        WHEN length(prep.b64_clean) % 4 = 0 THEN prep.b64_clean
        ELSE prep.b64_clean || repeat('=', (4 - length(prep.b64_clean) % 4) % 4)
      END AS b64_padded
    FROM (
      SELECT
        regexp_replace(
          translate(btrim(COALESCE(rl.location_code, '')), '-_', '+/'),
          '\s',
          '',
          'g'
        ) AS b64_clean
    ) prep
  ) dl
  WHERE COALESCE(r.is_deleted, FALSE) = FALSE
    AND COALESCE(rl.is_deleted, FALSE) = FALSE
    AND COALESCE(r.is_active, TRUE) = TRUE
    AND r.status_code = 'PROCESSED'
    [[AND rl.center_id = {{center_id}}]]
) x
WHERE 1 = 1
  [[AND x.center_label ILIKE '%' || {{center_name}} || '%']]
  [[AND x.location_label ILIKE '%' || {{location_name}} || '%']]
GROUP BY x.center_label, x.location_label
ORDER BY processed_count DESC;
