-- M87 Governed Swarm - Phase 2 Initial Schema
-- DOCUMENTATION ONLY - NOT APPLIED DIRECTLY
--
-- Schema source of truth: apps/api/app/db/models.py (SQLAlchemy)
-- Tables created via: Base.metadata.create_all() on API startup
--
-- This file documents the expected schema for:
-- - Code review visibility
-- - Manual disaster recovery
-- - Future migration tooling (if needed)

-- API Keys table
CREATE TABLE IF NOT EXISTS api_keys (
    key_id VARCHAR(64) PRIMARY KEY,
    key_hash VARCHAR(128) NOT NULL UNIQUE,
    principal_type VARCHAR(32) NOT NULL,
    principal_id VARCHAR(128) NOT NULL,
    endpoint_scopes JSONB NOT NULL DEFAULT '[]',
    effect_scopes JSONB NOT NULL DEFAULT '[]',
    max_risk FLOAT NOT NULL DEFAULT 1.0,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    expires_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    description TEXT
);

CREATE INDEX IF NOT EXISTS ix_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS ix_api_keys_principal ON api_keys(principal_type, principal_id);

-- Proposals table
CREATE TABLE IF NOT EXISTS proposals (
    proposal_id VARCHAR(64) PRIMARY KEY,
    intent_id VARCHAR(64),
    agent VARCHAR(64) NOT NULL,
    summary TEXT NOT NULL,
    effects JSONB NOT NULL,
    artifacts JSONB,
    truth_account JSONB,
    risk_score FLOAT,
    principal_type VARCHAR(32),
    principal_id VARCHAR(128),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_proposals_agent ON proposals(agent);
CREATE INDEX IF NOT EXISTS ix_proposals_created ON proposals(created_at);

-- Decisions table
CREATE TABLE IF NOT EXISTS decisions (
    decision_id VARCHAR(64) PRIMARY KEY,
    proposal_id VARCHAR(64) NOT NULL REFERENCES proposals(proposal_id),
    outcome VARCHAR(32) NOT NULL,
    reasons JSONB NOT NULL,
    required_approvals JSONB,
    allowed_effects JSONB,
    decided_by VARCHAR(32) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_decisions_proposal ON decisions(proposal_id);
CREATE INDEX IF NOT EXISTS ix_decisions_outcome ON decisions(outcome);

-- Jobs table
CREATE TABLE IF NOT EXISTS jobs (
    job_id VARCHAR(64) PRIMARY KEY,
    proposal_id VARCHAR(64) NOT NULL REFERENCES proposals(proposal_id),
    tool VARCHAR(64) NOT NULL,
    inputs JSONB NOT NULL DEFAULT '{}',
    sandbox JSONB NOT NULL DEFAULT '{}',
    timeout_seconds FLOAT NOT NULL DEFAULT 60,
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_jobs_proposal ON jobs(proposal_id);
CREATE INDEX IF NOT EXISTS ix_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS ix_jobs_created ON jobs(created_at);

-- Executions table
CREATE TABLE IF NOT EXISTS executions (
    execution_id VARCHAR(64) PRIMARY KEY,
    job_id VARCHAR(64) NOT NULL REFERENCES jobs(job_id),
    status VARCHAR(32) NOT NULL,
    output TEXT,
    error TEXT,
    runner_id VARCHAR(128),
    started_at TIMESTAMP,
    completed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_executions_job ON executions(job_id);
CREATE INDEX IF NOT EXISTS ix_executions_status ON executions(status);

-- Migration tracking
CREATE TABLE IF NOT EXISTS schema_migrations (
    version VARCHAR(32) PRIMARY KEY,
    applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO schema_migrations (version) VALUES ('001_init')
ON CONFLICT (version) DO NOTHING;
