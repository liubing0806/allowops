-- PostgreSQL 17. Run after allowops-gateway migrate, as the maintenance owner of the AllowOps
-- tables, with permission to grant allowops_audit_writer and change public's privileges.
--   psql -X -1 -v ON_ERROR_STOP=1 -v runtime_role=allowops_gateway -f deploy/sql/runtime-grants.sql
-- Select the AllowOps database and maintenance login through the normal libpq
-- connection settings. Provision a dedicated INHERIT LOGIN with CONNECT first.
-- Its only role membership may be allowops_audit_writer. Gateways can select,
-- insert, update and delete business rows, append/read events, and read goose versions.
-- Pass its exact name, without SQL quotes. The psql identifier variable below
-- is also the fixture's template token. Use one transaction to pass the login
-- to the DO statement. That statement applies all privilege changes atomically.
--
-- Maintenance owns the AllowOps tables and manages their partitions. Reapply after adding
-- task partitions to grant direct access to the new children. The audit creation
-- function already grants its new children to the audit writer. Default table
-- privileges across public would also apply to future audit tables.
SET LOCAL search_path = pg_catalog, pg_temp;
SET LOCAL allowops.runtime_role = :"runtime_role";
-- In autocommit the SET LOCAL expires and a session default could name another
-- login. Bind the role setting to this transaction without changing that default.
SELECT pg_catalog.set_config('allowops.grants_xid', pg_catalog.pg_current_xact_id()::text, true);

DO $grants$
DECLARE
    login_name name := nullif(current_setting('allowops.runtime_role', true), '');
    login_oid oid;
    relation regclass;
BEGIN
    IF login_name IS NULL OR current_setting('allowops.grants_xid', true) IS DISTINCT FROM pg_current_xact_id()::text THEN
        RAISE EXCEPTION 'Missing transaction-local runtime role. Run the manifest in one transaction (psql -1)';
    END IF;
    SELECT oid INTO login_oid FROM pg_roles WHERE rolname = login_name AND rolcanlogin AND rolinherit
        AND NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls);
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Expected a restricted INHERIT LOGIN, got %', login_name;
    END IF;
    -- Check ownership and memberships for the login and the writer it will inherit.
    -- An owner can grant its privileges back after a REVOKE.
    IF login_name = current_user OR EXISTS (
        SELECT FROM (
            SELECT oid FROM pg_roles WHERE rolname NOT IN (login_name, 'allowops_audit_writer')
            UNION ALL SELECT nspowner FROM pg_namespace WHERE oid = 'public'::regnamespace
            UNION ALL SELECT relowner FROM pg_class WHERE relnamespace = 'public'::regnamespace
            UNION ALL SELECT proowner FROM pg_proc WHERE oid IN (
                'public.audit_create_partitions(timestamptz,integer)'::regprocedure,
                'public.tasks_create_partitions(timestamptz,integer)'::regprocedure
            )
        ) forbidden
        WHERE pg_has_role(login_oid, forbidden.oid, 'MEMBER')
           OR pg_has_role('allowops_audit_writer'::regrole, forbidden.oid, 'MEMBER')
    ) THEN
        RAISE EXCEPTION 'Runtime login % must not own AllowOps objects or belong to another role besides allowops_audit_writer', login_name;
    END IF;

    EXECUTE format('GRANT allowops_audit_writer TO %I WITH INHERIT TRUE, SET FALSE, ADMIN FALSE', login_name);
    -- Membership options are stored per grantor. This GRANT only controls its own row.
    IF NOT pg_has_role(login_oid, 'allowops_audit_writer', 'USAGE') OR EXISTS (
        SELECT FROM pg_auth_members WHERE roleid = 'allowops_audit_writer'::regrole
            AND member = login_oid AND (set_option OR admin_option)
    ) THEN
        RAISE EXCEPTION 'Runtime login % must inherit allowops_audit_writer without SET or ADMIN options', login_name;
    END IF;

    EXECUTE format('REVOKE CREATE ON SCHEMA public FROM PUBLIC, allowops_audit_writer, %I', login_name);
    EXECUTE format('GRANT USAGE ON SCHEMA public TO %I', login_name);
    -- PostgreSQL may only warn when the grantor lacks a schema grant option.
    IF has_schema_privilege(login_name, 'public', 'CREATE')
        OR NOT has_schema_privilege(login_name, 'public', 'USAGE') THEN
        RAISE EXCEPTION 'Schema owner must grant only USAGE on public to %', login_name;
    END IF;

    -- Enumerate the business tables. pg_partition_tree includes the tasks root
    -- and only its attached partitions, regardless of their names.
    FOR relation IN
        SELECT unnest(ARRAY[
            'public.gateway_instances', 'public.join_tokens', 'public.hosts',
            'public.catalog_versions', 'public.gateway_messages',
            'public.console_users', 'public.roles', 'public.role_mapping_state',
            'public.role_mappings', 'public.service_accounts', 'public.service_account_tokens',
            'public.identity_sessions', 'public.policy_versions', 'public.policy_tests',
            'public.oidc_transactions', 'public.cli_login_codes',
            'public.host_catalog_reports', 'public.host_import_previews', 'public.catalog_uploads',
            'public.job_sequences', 'public.jobs', 'public.task_steps'
        ]::regclass[])
        UNION ALL SELECT relid FROM pg_partition_tree('public.tasks')
    LOOP
        EXECUTE format('REVOKE ALL ON TABLE %s FROM allowops_audit_writer, %I', relation, login_name);
        EXECUTE format('REVOKE TRUNCATE, REFERENCES, TRIGGER, MAINTAIN ON TABLE %s FROM PUBLIC', relation);
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE %s TO %I', relation, login_name);
    END LOOP;

    FOR relation IN SELECT relid FROM pg_partition_tree('public.audit_events') LOOP
        EXECUTE format('REVOKE ALL ON TABLE %s FROM PUBLIC, allowops_audit_writer, %I', relation, login_name);
        EXECUTE format('GRANT SELECT, INSERT ON TABLE %s TO allowops_audit_writer', relation);
    END LOOP;
    -- goose's generated id is maintenance state as well.
    relation := pg_get_serial_sequence('public.goose_db_version', 'id')::regclass;
    EXECUTE format('REVOKE ALL ON SEQUENCE %s FROM PUBLIC, allowops_audit_writer, %I', relation, login_name);

    EXECUTE format('REVOKE ALL ON TABLE public.audit_partitions, public.audit_boundary,
                    public.audit_export_cursors, public.goose_db_version FROM PUBLIC, allowops_audit_writer, %I', login_name);
    GRANT SELECT ON TABLE public.audit_boundary TO allowops_audit_writer;
    GRANT SELECT, INSERT, UPDATE ON TABLE public.audit_export_cursors TO allowops_audit_writer;
    EXECUTE format('REVOKE EXECUTE ON FUNCTION public.audit_create_partitions(timestamptz, integer)
                    FROM PUBLIC, allowops_audit_writer, %I', login_name);
    EXECUTE format('REVOKE EXECUTE ON FUNCTION public.tasks_create_partitions(timestamptz, integer)
                    FROM PUBLIC, allowops_audit_writer, %I', login_name);
    EXECUTE format('GRANT SELECT ON TABLE public.goose_db_version TO %I', login_name);
END
$grants$;
