-- +goose Up
-- +goose StatementBegin
BEGIN;
CREATE TABLE IF NOT EXISTS copytrading_pair (
    id            SERIAL PRIMARY KEY,
    policy_id     UUID         NOT NULL,
    resource      VARCHAR(255) NOT NULL,
    leader_addr   VARCHAR(255) NOT NULL,
    created_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at    TIMESTAMP
);

CREATE INDEX idx_copytrading_policy ON copytrading_pair (policy_id) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX idx_copytrading_unique_combo ON copytrading_pair (policy_id, leader_addr, resource) WHERE deleted_at IS NULL;
CREATE INDEX idx_copytrading_resource_leader ON copytrading_pair (resource, leader_addr) WHERE deleted_at IS NULL;
END;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS copytrading_pair;
-- +goose StatementEnd
