-- +goose Up
-- +goose StatementBegin
ALTER TYPE plugin_id ADD VALUE 'vultisig-copytrader-0000';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ROLLBACK;
-- +goose StatementEnd
