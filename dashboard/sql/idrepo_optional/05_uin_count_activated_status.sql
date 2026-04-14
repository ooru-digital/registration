-- Purpose: Count of idrepo.uin rows with status ACTIVATED — identities successfully stored in ID Repository
--          with an active lifecycle. Each row is one UIN (one stored identity); reg_id is UNIQUE on this table
--          and holds the *latest* registration ID that last updated that identity (CREATE or UPDATE from reg proc).
-- Connection: mosip_idrepo
-- Gap: Confirm status_code value matches master.status_list in your deployment (MOSIP commonly uses ACTIVATED).
--      This is identity count, not regprc packet count; do not SQL-join to mosip_regprc in Metabase.

SELECT
  COUNT(DISTINCT reg_id) AS activated_identity_reg_id_count
FROM idrepo.uin
WHERE COALESCE(is_deleted, FALSE) = FALSE
  AND status_code = 'ACTIVATED'
  AND reg_id IS NOT NULL;
