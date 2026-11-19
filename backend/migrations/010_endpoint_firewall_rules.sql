-- Migration: 010_endpoint_firewall_rules
-- Purpose: Persist the current Windows firewall rule inventory reported by client endpoints.

CREATE TABLE IF NOT EXISTS public.endpoint_firewall_rules (
    id SERIAL PRIMARY KEY,
    endpoint_asset_id INTEGER NOT NULL,

    instance_id VARCHAR(500) NOT NULL,
    rule_name VARCHAR(500) NULL,
    display_name VARCHAR(1000) NULL,
    description TEXT NULL,

    enabled BOOLEAN NULL,
    direction VARCHAR(50) NULL,
    action VARCHAR(50) NULL,
    profile VARCHAR(255) NULL,

    protocol VARCHAR(100) NULL,
    local_port TEXT NULL,
    remote_port TEXT NULL,
    local_address TEXT NULL,
    remote_address TEXT NULL,

    program TEXT NULL,
    service_name VARCHAR(500) NULL,
    policy_store_source VARCHAR(500) NULL,

    first_seen TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    last_seen TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,

    CONSTRAINT fk_endpoint_firewall_rules_endpoint_asset_id
        FOREIGN KEY (endpoint_asset_id)
        REFERENCES public.endpoint_assets(id)
        ON DELETE CASCADE,

    CONSTRAINT uq_endpoint_firewall_rules_endpoint_instance
        UNIQUE (endpoint_asset_id, instance_id)
);

CREATE INDEX IF NOT EXISTS ix_endpoint_firewall_rules_endpoint_asset_id
    ON public.endpoint_firewall_rules(endpoint_asset_id);

CREATE INDEX IF NOT EXISTS ix_endpoint_firewall_rules_instance_id
    ON public.endpoint_firewall_rules(instance_id);

CREATE INDEX IF NOT EXISTS ix_endpoint_firewall_rules_rule_name
    ON public.endpoint_firewall_rules(rule_name);

CREATE INDEX IF NOT EXISTS ix_endpoint_firewall_rules_display_name
    ON public.endpoint_firewall_rules(display_name);

CREATE INDEX IF NOT EXISTS ix_endpoint_firewall_rules_enabled
    ON public.endpoint_firewall_rules(enabled);

CREATE INDEX IF NOT EXISTS ix_endpoint_firewall_rules_direction
    ON public.endpoint_firewall_rules(direction);

CREATE INDEX IF NOT EXISTS ix_endpoint_firewall_rules_action
    ON public.endpoint_firewall_rules(action);

CREATE INDEX IF NOT EXISTS ix_endpoint_firewall_rules_profile
    ON public.endpoint_firewall_rules(profile);

CREATE INDEX IF NOT EXISTS ix_endpoint_firewall_rules_last_seen
    ON public.endpoint_firewall_rules(last_seen);
