-- Purpose: Row count in idrepo.anonymous_profile (if populated by ID Repo reporting pipeline).
-- Connection: mosip_idrepo
-- Gap: Same structural limits as regprc anonymous_profile (no reg_id); compare pipelines carefully.

SELECT
  COUNT(*) AS idrepo_anonymous_profile_rows
FROM idrepo.anonymous_profile
WHERE COALESCE(is_deleted, FALSE) = FALSE;
