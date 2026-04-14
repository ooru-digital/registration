-- Purpose: Packet counts by geography key; registration_list.location_code is Base64-encoded, displayed decoded as UTF-8.
-- Connection: mosip_regprc
-- Decoding: same as 01_registrations_per_center.sql (URL-safe → standard, strip whitespace, pad Base64).
-- Gap: Confirm decoded label matches your master hierarchy level (district / other).

SELECT
  d.location_label,
  COUNT(*) AS packet_count
FROM (
  SELECT
    CASE
      WHEN rl.location_code IS NULL OR btrim(rl.location_code) = '' THEN '(no location)'
      WHEN length(dec.b64_clean) % 4 = 1 THEN '(invalid base64 length)'
      ELSE convert_from(decode(dec.b64_padded, 'base64'), 'UTF8')
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
          translate(btrim(COALESCE(rl.location_code, '')), '-_', '+/'),
          '\s',
          '',
          'g'
        ) AS b64_clean
    ) prep
  ) dec
  WHERE COALESCE(r.is_deleted, FALSE) = FALSE
    AND COALESCE(rl.is_deleted, FALSE) = FALSE
    AND COALESCE(r.is_active, TRUE) = TRUE
) d
GROUP BY d.location_label
ORDER BY packet_count DESC;
