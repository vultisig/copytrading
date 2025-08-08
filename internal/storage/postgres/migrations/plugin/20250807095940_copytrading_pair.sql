-- +goose Up
-- +goose StatementBegin
BEGIN;
CREATE TABLE IF NOT EXISTS copytrading_pair (
    policy_id UUID PRIMARY KEY,
    resource VARCHAR(255) NOT NULL,
    leader_addr VARCHAR(255) NOT NULL,

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP
);

CREATE INDEX idx_copytrading_resource_leader ON copytrading_pair(resource, leader_addr)
    WHERE deleted_at IS NULL;
END;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS copytrading_pair;
-- +goose StatementEnd
