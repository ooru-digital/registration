-- Purpose: Count UIN rows in identity store (operational inventory).
-- Connection: mosip_idrepo (NOT mosip_regprc)
-- Gap: Not joinable to center in SQL here; compare total to PROCESSED count from regprc as separate cards.

SELECT
  COUNT(*) AS uin_row_count
FROM idrepo.uin
WHERE COALESCE(is_deleted, FALSE) = FALSE;
