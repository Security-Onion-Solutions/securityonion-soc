-- Add duplicated_from_id to audit_settings so that audit history records
-- the duplication state of a setting at the time of each change. This allows
-- revert operations to correctly restore the duplicated_from_id value.

ALTER TABLE audit_settings ADD COLUMN IF NOT EXISTS duplicated_from_id VARCHAR(1024);
