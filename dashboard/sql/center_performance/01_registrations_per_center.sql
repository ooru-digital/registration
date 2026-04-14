-- Purpose: Total packets per enrollment center, grouped by registration_list.name (Base64), displayed decoded as UTF-8.
-- Connection: mosip_regprc
-- Decoding: strips whitespace, maps URL-safe Base64 (- _) to standard (+ /), then pads with '=' so length is a multiple of 4
--           (avoids PostgreSQL error: invalid base64 end sequence / missing padding).
-- Gap: Rows that are not Base64 (plain text) may still error — see note at bottom.

SELECT
  d.center_name,
  COUNT(*) AS packet_count
FROM (
  SELECT
    CASE
      WHEN rl.name IS NULL OR btrim(rl.name) = '' THEN '(no name)'
      /* Length mod 4 == 1 is never valid for standard Base64 */
      WHEN length(dec.b64_clean) % 4 = 1 THEN '(invalid base64 length)'
      ELSE convert_from(decode(dec.b64_padded, 'base64'), 'UTF8')
    END AS center_name
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
          translate(btrim(COALESCE(rl.name, '')), '-_', '+/'),
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
GROUP BY d.center_name
ORDER BY packet_count DESC;

-- If decode() still fails on some rows, the value may be plain text or use another encoding.
-- Option: load rows into a staging table and decode in application code, or add a PL/pgSQL function with EXCEPTION WHEN OTHERS.
