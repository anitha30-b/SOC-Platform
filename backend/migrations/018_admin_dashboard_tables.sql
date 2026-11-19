-- DRAFT: admin dashboard schema integration; review before execution.

-- Creates 25 missing tables and their declared indexes only.

-- No inserts, updates, deletes, drops, or changes to existing tables.

-- Python-side ORM defaults are not PostgreSQL server defaults.

BEGIN;

SET LOCAL lock_timeout = '5s';

SET LOCAL statement_timeout = '60s';

SET LOCAL search_path = public, pg_catalog;

CREATE TABLE detection_configurations (
	id SERIAL NOT NULL, 
	name VARCHAR(150) NOT NULL, 
	category VARCHAR(100) NOT NULL, 
	description TEXT NOT NULL, 
	detection_type VARCHAR(100) NOT NULL, 
	severity VARCHAR(50) NOT NULL, 
	conditions TEXT, 
	threshold INTEGER, 
	time_window_minutes INTEGER, 
	source VARCHAR(100), 
	event_type VARCHAR(100), 
	enabled BOOLEAN NOT NULL, 
	created_by VARCHAR(100), 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id)
);

CREATE INDEX ix_detection_configurations_category ON detection_configurations (category);

CREATE INDEX ix_detection_configurations_enabled ON detection_configurations (enabled);

CREATE INDEX ix_detection_configurations_id ON detection_configurations (id);

CREATE UNIQUE INDEX ix_detection_configurations_name ON detection_configurations (name);

CREATE TABLE platform_configurations (
	id SERIAL NOT NULL, 
	session_timeout_minutes INTEGER NOT NULL, 
	password_min_length INTEGER NOT NULL, 
	password_require_uppercase BOOLEAN NOT NULL, 
	password_require_lowercase BOOLEAN NOT NULL, 
	password_require_number BOOLEAN NOT NULL, 
	password_require_special BOOLEAN NOT NULL, 
	max_failed_login_attempts INTEGER NOT NULL, 
	account_lockout_minutes INTEGER NOT NULL, 
	created_by VARCHAR(100), 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id)
);

CREATE INDEX ix_platform_configurations_id ON platform_configurations (id);

CREATE TABLE retention_policies (
	id SERIAL NOT NULL, 
	name VARCHAR(150) NOT NULL, 
	data_type VARCHAR(100) NOT NULL, 
	description TEXT NOT NULL, 
	retention_days INTEGER NOT NULL, 
	archive_enabled BOOLEAN NOT NULL, 
	archive_after_days INTEGER, 
	auto_delete BOOLEAN NOT NULL, 
	enabled BOOLEAN NOT NULL, 
	created_by VARCHAR(100), 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id)
);

CREATE INDEX ix_retention_policies_data_type ON retention_policies (data_type);

CREATE INDEX ix_retention_policies_enabled ON retention_policies (enabled);

CREATE INDEX ix_retention_policies_id ON retention_policies (id);

CREATE UNIQUE INDEX ix_retention_policies_name ON retention_policies (name);

CREATE TABLE security_baselines (
	id SERIAL NOT NULL, 
	name VARCHAR(150) NOT NULL, 
	framework VARCHAR(100) NOT NULL, 
	category VARCHAR(100) NOT NULL, 
	description TEXT NOT NULL, 
	severity VARCHAR(50) NOT NULL, 
	enabled BOOLEAN NOT NULL, 
	baseline_content TEXT, 
	created_by VARCHAR(100), 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id)
);

CREATE INDEX ix_security_baselines_category ON security_baselines (category);

CREATE INDEX ix_security_baselines_enabled ON security_baselines (enabled);

CREATE INDEX ix_security_baselines_framework ON security_baselines (framework);

CREATE INDEX ix_security_baselines_id ON security_baselines (id);

CREATE UNIQUE INDEX ix_security_baselines_name ON security_baselines (name);

CREATE TABLE security_policies (
	id SERIAL NOT NULL, 
	name VARCHAR(150) NOT NULL, 
	category VARCHAR(100) NOT NULL, 
	description TEXT NOT NULL, 
	severity VARCHAR(50) NOT NULL, 
	enabled BOOLEAN NOT NULL, 
	policy_content TEXT, 
	created_by VARCHAR(100), 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id)
);

CREATE INDEX ix_security_policies_category ON security_policies (category);

CREATE INDEX ix_security_policies_enabled ON security_policies (enabled);

CREATE INDEX ix_security_policies_id ON security_policies (id);

CREATE UNIQUE INDEX ix_security_policies_name ON security_policies (name);

CREATE INDEX ix_security_policies_severity ON security_policies (severity);

CREATE TABLE soc_asset_groups (
	id SERIAL NOT NULL, 
	name VARCHAR(150) NOT NULL, 
	description TEXT, 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id)
);

CREATE INDEX ix_soc_asset_groups_id ON soc_asset_groups (id);

CREATE UNIQUE INDEX ix_soc_asset_groups_name ON soc_asset_groups (name);

CREATE TABLE soc_asset_reachability (
	asset_id SERIAL NOT NULL, 
	port INTEGER, 
	status VARCHAR(30) NOT NULL, 
	reason TEXT, 
	checked_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	duration_ms INTEGER NOT NULL, 
	PRIMARY KEY (asset_id)
);

CREATE TABLE soc_assets (
	id SERIAL NOT NULL, 
	name VARCHAR(200) NOT NULL, 
	asset_type VARCHAR(60) NOT NULL, 
	ip_address VARCHAR(100), 
	url VARCHAR(2048), 
	hostname VARCHAR(255), 
	environment VARCHAR(60) NOT NULL, 
	status VARCHAR(40) NOT NULL, 
	criticality VARCHAR(30) NOT NULL, 
	owner VARCHAR(200), 
	notes TEXT, 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id)
);

CREATE INDEX ix_soc_assets_id ON soc_assets (id);

CREATE INDEX ix_soc_assets_ip_address ON soc_assets (ip_address);

CREATE INDEX ix_soc_assets_name ON soc_assets (name);

CREATE TABLE soc_security_agents (
	id SERIAL NOT NULL, 
	agent_key_hash VARCHAR(64) NOT NULL, 
	name VARCHAR(150) NOT NULL, 
	hostname VARCHAR(255) NOT NULL, 
	operating_system VARCHAR(100) NOT NULL, 
	agent_version VARCHAR(50), 
	status VARCHAR(30) NOT NULL, 
	last_seen TIMESTAMP WITHOUT TIME ZONE, 
	registered_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	notes TEXT, 
	PRIMARY KEY (id), 
	UNIQUE (agent_key_hash)
);

CREATE INDEX ix_soc_security_agents_id ON soc_security_agents (id);

CREATE TABLE alert_configurations (
	id SERIAL NOT NULL, 
	name VARCHAR(150) NOT NULL, 
	category VARCHAR(100) NOT NULL, 
	description TEXT NOT NULL, 
	severity VARCHAR(50) NOT NULL, 
	priority VARCHAR(50) NOT NULL, 
	source VARCHAR(100), 
	event_type VARCHAR(100), 
	threshold INTEGER, 
	time_window_minutes INTEGER, 
	conditions TEXT, 
	notification_policy_id INTEGER, 
	enabled BOOLEAN NOT NULL, 
	created_by VARCHAR(100), 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(notification_policy_id) REFERENCES notification_policies (id)
);

CREATE INDEX ix_alert_configurations_category ON alert_configurations (category);

CREATE INDEX ix_alert_configurations_enabled ON alert_configurations (enabled);

CREATE INDEX ix_alert_configurations_id ON alert_configurations (id);

CREATE UNIQUE INDEX ix_alert_configurations_name ON alert_configurations (name);

CREATE TABLE role_tool_permissions (
	id SERIAL NOT NULL, 
	role_id INTEGER NOT NULL, 
	tool_id INTEGER NOT NULL, 
	allowed BOOLEAN NOT NULL, 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_role_tool_permission UNIQUE (role_id, tool_id), 
	FOREIGN KEY(role_id) REFERENCES roles (id), 
	FOREIGN KEY(tool_id) REFERENCES security_tools (id)
);

CREATE INDEX ix_role_tool_permissions_id ON role_tool_permissions (id);

CREATE INDEX ix_role_tool_permissions_role_id ON role_tool_permissions (role_id);

CREATE INDEX ix_role_tool_permissions_tool_id ON role_tool_permissions (tool_id);

CREATE TABLE soc_asset_group_members (
	id SERIAL NOT NULL, 
	group_id INTEGER NOT NULL, 
	asset_id INTEGER NOT NULL, 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_soc_asset_group_member UNIQUE (group_id, asset_id), 
	FOREIGN KEY(group_id) REFERENCES soc_asset_groups (id) ON DELETE CASCADE, 
	FOREIGN KEY(asset_id) REFERENCES soc_assets (id) ON DELETE CASCADE
);

CREATE INDEX ix_soc_asset_group_members_asset_id ON soc_asset_group_members (asset_id);

CREATE INDEX ix_soc_asset_group_members_group_id ON soc_asset_group_members (group_id);

CREATE INDEX ix_soc_asset_group_members_id ON soc_asset_group_members (id);

CREATE TABLE soc_server_monitor_results (
	id SERIAL NOT NULL, 
	asset_id INTEGER NOT NULL, 
	status VARCHAR(20) NOT NULL, 
	port INTEGER NOT NULL, 
	response_time_ms FLOAT, 
	checked_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	reason VARCHAR(250), 
	PRIMARY KEY (id), 
	FOREIGN KEY(asset_id) REFERENCES soc_assets (id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX ix_soc_server_monitor_results_asset_id ON soc_server_monitor_results (asset_id);

CREATE INDEX ix_soc_server_monitor_results_id ON soc_server_monitor_results (id);

CREATE TABLE api_keys (
	id SERIAL NOT NULL, 
	name VARCHAR(150) NOT NULL, 
	description TEXT, 
	key_prefix VARCHAR(24) NOT NULL, 
	key_hash VARCHAR(64) NOT NULL, 
	enabled BOOLEAN NOT NULL, 
	created_by INTEGER NOT NULL, 
	client_id INTEGER, 
	permissions JSON NOT NULL, 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	expires_at TIMESTAMP WITHOUT TIME ZONE, 
	last_used_at TIMESTAMP WITHOUT TIME ZONE, 
	revoked_at TIMESTAMP WITHOUT TIME ZONE, 
	PRIMARY KEY (id), 
	UNIQUE (key_hash), 
	FOREIGN KEY(created_by) REFERENCES users (id), 
	FOREIGN KEY(client_id) REFERENCES clients (id)
);

CREATE INDEX ix_api_keys_client_id ON api_keys (client_id);

CREATE INDEX ix_api_keys_enabled ON api_keys (enabled);

CREATE INDEX ix_api_keys_id ON api_keys (id);

CREATE INDEX ix_api_keys_key_prefix ON api_keys (key_prefix);

CREATE INDEX ix_api_keys_name ON api_keys (name);

CREATE TABLE email_header_analyses (
	id SERIAL NOT NULL, 
	admin_user_id INTEGER NOT NULL, 
	sender VARCHAR(255), 
	reply_to VARCHAR(255), 
	subject VARCHAR(500), 
	from_domain VARCHAR(255), 
	risk_score INTEGER NOT NULL, 
	risk_level VARCHAR(30) NOT NULL, 
	indicators JSON NOT NULL, 
	authentication_results JSON NOT NULL, 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(admin_user_id) REFERENCES users (id)
);

CREATE INDEX ix_email_header_analyses_admin_user_id ON email_header_analyses (admin_user_id);

CREATE INDEX ix_email_header_analyses_created_at ON email_header_analyses (created_at);

CREATE INDEX ix_email_header_analyses_id ON email_header_analyses (id);

CREATE TABLE service_accounts (
	id SERIAL NOT NULL, 
	name VARCHAR(150) NOT NULL, 
	description TEXT, 
	key_prefix VARCHAR(24) NOT NULL, 
	key_hash VARCHAR(64) NOT NULL, 
	role_id INTEGER NOT NULL, 
	enabled BOOLEAN NOT NULL, 
	created_by INTEGER NOT NULL, 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	expires_at TIMESTAMP WITHOUT TIME ZONE, 
	last_used_at TIMESTAMP WITHOUT TIME ZONE, 
	revoked_at TIMESTAMP WITHOUT TIME ZONE, 
	PRIMARY KEY (id), 
	UNIQUE (key_hash), 
	FOREIGN KEY(role_id) REFERENCES roles (id), 
	FOREIGN KEY(created_by) REFERENCES users (id)
);

CREATE INDEX ix_service_accounts_enabled ON service_accounts (enabled);

CREATE INDEX ix_service_accounts_id ON service_accounts (id);

CREATE INDEX ix_service_accounts_key_prefix ON service_accounts (key_prefix);

CREATE INDEX ix_service_accounts_name ON service_accounts (name);

CREATE TABLE siem_integrations (
	id SERIAL NOT NULL, 
	name VARCHAR(150) NOT NULL, 
	provider VARCHAR(50) NOT NULL, 
	base_url VARCHAR(1000) NOT NULL, 
	encrypted_credentials TEXT, 
	enabled BOOLEAN NOT NULL, 
	status VARCHAR(30) NOT NULL, 
	last_tested_at TIMESTAMP WITHOUT TIME ZONE, 
	last_error TEXT, 
	created_by INTEGER NOT NULL, 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_siem_provider_name UNIQUE (provider, name), 
	FOREIGN KEY(created_by) REFERENCES users (id)
);

CREATE INDEX ix_siem_integrations_enabled ON siem_integrations (enabled);

CREATE INDEX ix_siem_integrations_id ON siem_integrations (id);

CREATE INDEX ix_siem_integrations_provider ON siem_integrations (provider);

CREATE TABLE soc_background_jobs (
	id SERIAL NOT NULL, 
	job_id VARCHAR(36) NOT NULL, 
	tool VARCHAR(50) NOT NULL, 
	target VARCHAR(2048) NOT NULL, 
	scan_type VARCHAR(50), 
	user_id INTEGER NOT NULL, 
	status VARCHAR(40) NOT NULL, 
	progress INTEGER NOT NULL, 
	stage VARCHAR(255), 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	error TEXT, 
	result_json TEXT, 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES users (id)
);

CREATE INDEX ix_soc_background_jobs_id ON soc_background_jobs (id);

CREATE UNIQUE INDEX ix_soc_background_jobs_job_id ON soc_background_jobs (job_id);

CREATE INDEX ix_soc_background_jobs_status ON soc_background_jobs (status);

CREATE INDEX ix_soc_background_jobs_tool ON soc_background_jobs (tool);

CREATE INDEX ix_soc_background_jobs_user_id ON soc_background_jobs (user_id);

CREATE TABLE teams (
	id SERIAL NOT NULL, 
	name VARCHAR(150) NOT NULL, 
	description TEXT, 
	created_by INTEGER NOT NULL, 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(created_by) REFERENCES users (id)
);

CREATE INDEX ix_teams_id ON teams (id);

CREATE UNIQUE INDEX ix_teams_name ON teams (name);

CREATE TABLE user_sessions (
	id SERIAL NOT NULL, 
	jti VARCHAR(128) NOT NULL, 
	user_id INTEGER NOT NULL, 
	username VARCHAR(150) NOT NULL, 
	role_id INTEGER NOT NULL, 
	ip_address VARCHAR(100), 
	user_agent TEXT, 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	expires_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	last_activity_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	revoked_at TIMESTAMP WITHOUT TIME ZONE, 
	revoked_by INTEGER, 
	revocation_reason VARCHAR(255), 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES users (id), 
	FOREIGN KEY(revoked_by) REFERENCES users (id)
);

CREATE INDEX ix_user_sessions_expires_at ON user_sessions (expires_at);

CREATE INDEX ix_user_sessions_id ON user_sessions (id);

CREATE UNIQUE INDEX ix_user_sessions_jti ON user_sessions (jti);

CREATE INDEX ix_user_sessions_revoked_at ON user_sessions (revoked_at);

CREATE INDEX ix_user_sessions_role_id ON user_sessions (role_id);

CREATE INDEX ix_user_sessions_user_id ON user_sessions (user_id);

CREATE INDEX ix_user_sessions_username ON user_sessions (username);

CREATE TABLE siem_ingestion_states (
	id SERIAL NOT NULL, 
	integration_id INTEGER NOT NULL, 
	last_ingested_at TIMESTAMP WITHOUT TIME ZONE, 
	last_success_at TIMESTAMP WITHOUT TIME ZONE, 
	last_error TEXT, 
	total_events INTEGER NOT NULL, 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(integration_id) REFERENCES siem_integrations (id) ON DELETE CASCADE
);

CREATE INDEX ix_siem_ingestion_states_id ON siem_ingestion_states (id);

CREATE UNIQUE INDEX ix_siem_ingestion_states_integration_id ON siem_ingestion_states (integration_id);

CREATE TABLE team_members (
	id SERIAL NOT NULL, 
	team_id INTEGER NOT NULL, 
	user_id INTEGER NOT NULL, 
	assigned_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_team_member UNIQUE (team_id, user_id), 
	FOREIGN KEY(team_id) REFERENCES teams (id) ON DELETE CASCADE, 
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX ix_team_members_id ON team_members (id);

CREATE INDEX ix_team_members_team_id ON team_members (team_id);

CREATE INDEX ix_team_members_user_id ON team_members (user_id);

CREATE TABLE alert_results (
	id SERIAL NOT NULL, 
	security_event_id INTEGER NOT NULL, 
	alert_config_id INTEGER NOT NULL, 
	alert_name VARCHAR(150) NOT NULL, 
	severity VARCHAR(50) NOT NULL, 
	priority VARCHAR(50) NOT NULL, 
	match_details TEXT, 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_alert_event_rule UNIQUE (security_event_id, alert_config_id), 
	FOREIGN KEY(security_event_id) REFERENCES security_events (id), 
	FOREIGN KEY(alert_config_id) REFERENCES alert_configurations (id)
);

CREATE INDEX ix_alert_results_alert_config_id ON alert_results (alert_config_id);

CREATE INDEX ix_alert_results_created_at ON alert_results (created_at);

CREATE INDEX ix_alert_results_id ON alert_results (id);

CREATE INDEX ix_alert_results_security_event_id ON alert_results (security_event_id);

CREATE TABLE detection_results (
	id SERIAL NOT NULL, 
	security_event_id INTEGER NOT NULL, 
	detection_config_id INTEGER NOT NULL, 
	rule_name VARCHAR(150) NOT NULL, 
	detection_type VARCHAR(100) NOT NULL, 
	severity VARCHAR(50) NOT NULL, 
	match_details TEXT, 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_detection_event_rule UNIQUE (security_event_id, detection_config_id), 
	FOREIGN KEY(security_event_id) REFERENCES security_events (id), 
	FOREIGN KEY(detection_config_id) REFERENCES detection_configurations (id)
);

CREATE INDEX ix_detection_results_created_at ON detection_results (created_at);

CREATE INDEX ix_detection_results_detection_config_id ON detection_results (detection_config_id);

CREATE INDEX ix_detection_results_id ON detection_results (id);

CREATE INDEX ix_detection_results_security_event_id ON detection_results (security_event_id);

CREATE TABLE incident_alert_links (
	id SERIAL NOT NULL, 
	incident_id INTEGER NOT NULL, 
	alert_result_id INTEGER NOT NULL, 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_incident_alert_link UNIQUE (incident_id, alert_result_id), 
	FOREIGN KEY(incident_id) REFERENCES incidents (id), 
	FOREIGN KEY(alert_result_id) REFERENCES alert_results (id)
);

CREATE INDEX ix_incident_alert_links_alert_result_id ON incident_alert_links (alert_result_id);

CREATE INDEX ix_incident_alert_links_id ON incident_alert_links (id);

CREATE INDEX ix_incident_alert_links_incident_id ON incident_alert_links (incident_id);

COMMIT;
