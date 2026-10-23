-- Host connection and mailbox routing statements. GetHost, GetCatalog,
-- CurrentCatalogs, RegisterInstance, TouchConnection, DisconnectHost and
-- DeleteExpiredMessages live in gateway.sql. The three mailbox statements that
-- job tests identify by SQL text prefix are hand-written in hostconn/sql.go.

-- name: SetGatewayInstanceVersion :exec
UPDATE gateway_instances SET version=$2 WHERE instance_id=$1;

-- name: TouchGatewayInstance :exec
UPDATE gateway_instances SET last_seen=now() WHERE instance_id=$1;

-- name: SetGatewayInstanceDraining :exec
UPDATE gateway_instances SET draining=true WHERE instance_id=$1;

-- name: ClaimHostConnection :one
UPDATE hosts SET instance_id=$2,connection_id=$3,reported_labels=$4,agent_version=$5,last_seen=now(),capabilities=$7 WHERE host_id=$1 AND certificate_status='active' AND certificate_serial=$6 RETURNING host_id;

-- name: UpsertHostCatalogReport :exec
INSERT INTO host_catalog_reports(host_id,catalog_id,version,loaded,report)
 SELECT hosts.host_id,$2,$3,$4,$5 FROM hosts WHERE hosts.host_id=$1 AND hosts.connection_id=$6 AND hosts.certificate_status='active'
 ON CONFLICT(host_id,catalog_id) DO UPDATE SET version=EXCLUDED.version,loaded=EXCLUDED.loaded,report=EXCLUDED.report;

-- name: LockMailboxCapacity :exec
SELECT pg_advisory_xact_lock(418002);

-- name: GetMailboxUsage :one
SELECT count(*),COALESCE(sum(octet_length(request)+1048576),0)::bigint FROM gateway_messages;

-- name: GetOnlineHostConnectionForShare :one
SELECT connection_id FROM hosts WHERE host_id=$1 AND certificate_status='active' AND instance_id IS NOT NULL FOR SHARE;

-- name: DeleteGatewayMessage :exec
DELETE FROM gateway_messages WHERE message_id=$1;

-- name: GetGatewayMessageResult :one
SELECT response,failure FROM gateway_messages WHERE message_id=$1;

-- name: GetLiveGatewayMessage :one
SELECT host_id,connection_id,request FROM gateway_messages WHERE message_id=$1 AND expires_at>now() AND response IS NULL AND failure='';

-- name: GetActiveHostConnectionForShare :one
SELECT connection_id FROM hosts WHERE host_id=$1 AND certificate_status='active' FOR SHARE;

-- name: GetJobDispatchStateForShare :one
SELECT status,cancel_requested FROM jobs WHERE job_id=$1 FOR SHARE;

-- name: GetTaskDispatchStateForShare :one
SELECT status,dispatched,host_id,COALESCE(connection_id,'') FROM tasks WHERE job_id=$1 AND task_id=$2 FOR SHARE;

-- name: FailGatewayMessageOffline :exec
UPDATE gateway_messages SET failure='offline' WHERE message_id=$1;

-- name: CompleteGatewayMessages :exec
UPDATE gateway_messages SET response=$2 WHERE message_id=ANY($1::text[]) AND gateway_messages.connection_id=$3 AND expires_at>now() AND response IS NULL AND failure='' AND EXISTS(SELECT 1 FROM hosts WHERE hosts.host_id=$4 AND hosts.connection_id=$3 AND hosts.certificate_status='active');

-- name: FailConnectionMessages :exec
UPDATE gateway_messages SET failure='offline' WHERE connection_id=$1 AND response IS NULL;
