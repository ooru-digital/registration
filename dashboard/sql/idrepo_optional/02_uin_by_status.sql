-- Purpose: Distribution of UIN lifecycle status_code.
-- Connection: mosip_idrepo
-- Gap: status_code values come from master.status_list in MOSIP — confirm codes in your deployment.

SELECT
  status_code,
  COUNT(*) AS cnt
FROM idrepo.uin
WHERE COALESCE(is_deleted, FALSE) = FALSE
GROUP BY status_code
ORDER BY cnt DESC;
