-- +goose Up
ALTER TABLE console_users ADD COLUMN disabled boolean NOT NULL DEFAULT false;
CREATE INDEX cli_login_codes_user ON cli_login_codes(user_id);

-- +goose StatementBegin
CREATE FUNCTION bump_console_user_disabled_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.revision := OLD.revision + 1;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER console_user_disabled_revision
    BEFORE UPDATE OF disabled ON console_users FOR EACH ROW
    WHEN (OLD.disabled IS DISTINCT FROM NEW.disabled)
    EXECUTE FUNCTION bump_console_user_disabled_revision();

-- +goose Down
DROP TRIGGER console_user_disabled_revision ON console_users;
DROP FUNCTION bump_console_user_disabled_revision();
DROP INDEX cli_login_codes_user;
ALTER TABLE console_users DROP COLUMN disabled;
