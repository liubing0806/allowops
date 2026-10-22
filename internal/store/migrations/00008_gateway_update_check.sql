-- +goose Up
-- Singleton: the latest released gateway version seen by the opt-in update check.
CREATE TABLE gateway_update_check (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    latest_version text NOT NULL DEFAULT '',
    published_at timestamptz,
    checked_at timestamptz,
    last_error text NOT NULL DEFAULT ''
);
-- +goose Down
DROP TABLE gateway_update_check;
