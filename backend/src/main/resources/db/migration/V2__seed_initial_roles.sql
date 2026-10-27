-- ==============================================================================
-- Flyway Migration V2: Seed Immutable Enterprise Roles
-- ==============================================================================

INSERT INTO roles (code, name, description) VALUES
('ROLE_SUPER_ADMIN', 'Super Administrator', 'Full administrative authority, staff & admin management, security policies, and audit logs'),
('ROLE_ADMIN', 'Administrator', 'Administrative dashboard access, management of permitted staff accounts within defined scope'),
('ROLE_STAFF', 'Staff', 'Operational dashboard access, view and update explicitly assigned user records only')
ON CONFLICT (code) DO NOTHING;
