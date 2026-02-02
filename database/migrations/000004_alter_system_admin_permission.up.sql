-- migration_file_name.sql (e.g., 20240202_alter_permissions_to_jsonb.sql)

ALTER TABLE system_admins 
ALTER COLUMN permissions 
TYPE jsonb USING permissions::jsonb;
