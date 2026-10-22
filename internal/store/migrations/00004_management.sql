-- +goose Up
ALTER TABLE hosts ADD COLUMN revision bigint NOT NULL DEFAULT 1;
ALTER TABLE hosts ADD COLUMN registered_at timestamptz;
ALTER TABLE hosts ALTER COLUMN registered_at SET DEFAULT now();
ALTER TABLE hosts ADD COLUMN capabilities bytea;
CREATE TABLE host_catalog_reports (
    host_id text NOT NULL REFERENCES hosts(host_id),
    catalog_id text NOT NULL,
    version bigint NOT NULL CHECK (version > 0),
    loaded boolean NOT NULL,
    report bytea NOT NULL,
    PRIMARY KEY (host_id, catalog_id)
);
ALTER TABLE join_tokens ADD COLUMN created_at timestamptz;
ALTER TABLE join_tokens ALTER COLUMN created_at SET DEFAULT now();
ALTER TABLE join_tokens ADD COLUMN revoked_at timestamptz;
ALTER TABLE catalog_versions ADD COLUMN published_at timestamptz;
ALTER TABLE catalog_versions ALTER COLUMN published_at SET DEFAULT now();
ALTER TABLE gateway_instances ADD COLUMN version text NOT NULL DEFAULT '';
ALTER TABLE gateway_instances ADD COLUMN draining boolean NOT NULL DEFAULT false;
CREATE TABLE host_import_previews (
    preview_id text PRIMARY KEY,
    actor_id text NOT NULL,
    csv_sha256 bytea NOT NULL CHECK (octet_length(csv_sha256) = 32),
    rows bytea NOT NULL,
    targets bytea NOT NULL,
    invalid_count bigint NOT NULL,
    expires_at timestamptz NOT NULL,
    updated_count bigint
);
CREATE TABLE catalog_uploads (
    upload_id text PRIMARY KEY,
    actor_id text NOT NULL,
    envelope_size bigint NOT NULL CHECK (envelope_size > 0),
    envelope_sha256 bytea NOT NULL CHECK (octet_length(envelope_sha256) = 32),
    data bytea NOT NULL DEFAULT '',
    chunk_ends bytea NOT NULL DEFAULT '',
    expires_at timestamptz NOT NULL,
    published_catalog bytea
);
-- Authorization revisions exclude heartbeats and connection metadata.
-- +goose StatementBegin
CREATE FUNCTION host_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.authorization_labels IS DISTINCT FROM OLD.authorization_labels
       OR NEW.certificate_status IS DISTINCT FROM OLD.certificate_status THEN
        NEW.revision := OLD.revision + 1;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER host_revision BEFORE UPDATE ON hosts FOR EACH ROW EXECUTE FUNCTION host_revision();
-- +goose Down
DROP TRIGGER host_revision ON hosts;
DROP FUNCTION host_revision();
DROP TABLE catalog_uploads;
DROP TABLE host_import_previews;
ALTER TABLE gateway_instances DROP COLUMN draining, DROP COLUMN version;
ALTER TABLE catalog_versions DROP COLUMN published_at;
ALTER TABLE join_tokens DROP COLUMN revoked_at, DROP COLUMN created_at;
DROP TABLE host_catalog_reports;
ALTER TABLE hosts DROP COLUMN capabilities, DROP COLUMN registered_at, DROP COLUMN revision;
