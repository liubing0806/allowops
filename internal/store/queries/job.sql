-- name: ListActiveHosts :many
SELECT host_id,hostname,COALESCE(connection_id,''),authorization_labels,reported_labels FROM hosts WHERE certificate_status='active' ORDER BY hostname,host_id;

-- name: CountJobTasksByStatus :many
SELECT status,count(*) FROM tasks WHERE job_id=$1 GROUP BY status ORDER BY status;

-- name: ListJobTasks :many
SELECT job_id,task_id,host_id,hostname,result,started_at,finished_at,output_stored,step_count FROM tasks WHERE job_id=$1 ORDER BY position;

-- name: LockJobPartitionCreation :exec
SELECT pg_advisory_xact_lock(418006);

-- name: LockJobSubject :exec
SELECT pg_advisory_xact_lock(hashtextextended($1,418006));

-- name: CountActiveJobsBySubject :one
SELECT count(*) FROM jobs WHERE subject_id=$1 AND status IN (1,2);

-- name: NextJobSequence :one
INSERT INTO job_sequences(day,value) VALUES ($1,1) ON CONFLICT(day) DO UPDATE SET value=job_sequences.value+1 RETURNING value;

-- name: InsertJob :exec
INSERT INTO jobs(job_id,created_at,subject_id,action,action_definition,catalog_id,catalog_version,action_sha256,policy_version,reason,status,batch_size,max_failures,finished_at,origin_instance) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15);

-- name: InsertPendingTask :exec
INSERT INTO tasks(job_id,task_id,created_at,host_id,hostname,position,status,result) VALUES ($1,$2,$3,$4,$5,$6,1,$7);

-- name: JobCreatedBySubject :one
SELECT EXISTS(SELECT 1 FROM jobs WHERE job_id=$1 AND created_at=$2 AND subject_id=$3);

-- name: IsTaskTerminal :one
SELECT status>2 FROM tasks WHERE job_id=$1 AND task_id=$2;

-- name: ListStatisticsJobs :many
SELECT job_id,status FROM jobs WHERE status IN (1,2) OR (status IN (4,5) AND finished_at>=now()-interval '24 hours') ORDER BY job_id;

-- name: MarkTaskStarted :exec
UPDATE tasks SET status=2,result=$3,started_at=now() WHERE job_id=$1 AND task_id=$2;

-- name: InsertTaskStep :exec
INSERT INTO task_steps(job_id,task_id,created_at,step_index,name,result) VALUES ($1,$2,$3,$4,$5,$6);

-- name: InsertTaskStepIfAbsent :exec
INSERT INTO task_steps(job_id,task_id,created_at,step_index,name,result) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING;

-- name: GetTaskStatusResult :one
SELECT status,result FROM tasks WHERE job_id=$1 AND task_id=$2;

-- name: TaskExists :one
SELECT EXISTS(SELECT 1 FROM tasks WHERE job_id=$1 AND task_id=$2);

-- name: ListTaskSteps :many
SELECT step_index,name,result FROM task_steps WHERE job_id=$1 AND task_id=$2 ORDER BY step_index;

-- name: LockJobForCancel :one
SELECT status,cancel_requested FROM jobs WHERE job_id=$1 FOR UPDATE;

-- name: RequestJobCancel :exec
UPDATE jobs SET cancel_requested=true WHERE job_id=$1;

-- name: CancelPendingTasks :many
UPDATE tasks SET status=8,result=$2,finished_at=now(),output_state='unavailable' WHERE job_id=$1 AND status=1 RETURNING task_id;

-- name: StartQueuedJob :exec
UPDATE jobs SET status=2 WHERE job_id=$1 AND status=1;

-- name: GetJobDispatchCancelForShare :one
SELECT cancel_requested,status FROM jobs WHERE job_id=$1 FOR SHARE;

-- name: GetActiveHostConnectionID :one
SELECT connection_id FROM hosts WHERE host_id=$1 AND certificate_status='active';

-- name: ReserveTaskDispatch :execrows
UPDATE tasks SET dispatched=true,connection_id=$3 WHERE job_id=$1 AND task_id=$2 AND status=1 AND NOT dispatched;

-- name: CountJobTasksForFinish :many
SELECT status,count(*) FROM tasks WHERE job_id=$1 GROUP BY status;

-- name: LockLostInstanceJob :one
SELECT j.job_id,j.origin_instance,j.policy_version FROM jobs j JOIN gateway_instances i ON i.instance_id=j.origin_instance WHERE j.status IN (1,2) AND i.last_seen<now()-$1*interval '1 second' ORDER BY j.job_id FOR UPDATE OF j SKIP LOCKED LIMIT 1;

-- name: LockLostOutputTask :one
SELECT t.job_id,t.task_id,t.host_id,t.hostname,j.subject_id,j.action,j.policy_version FROM tasks t JOIN jobs j ON j.job_id=t.job_id JOIN gateway_instances i ON i.instance_id=t.output_instance WHERE t.output_state='pending' AND t.status>2 AND i.last_seen<now()-$1*interval '1 second' ORDER BY t.job_id,t.task_id FOR UPDATE OF t SKIP LOCKED LIMIT 1;

-- name: MarkTaskOutputUnavailable :exec
UPDATE tasks SET output_state='unavailable' WHERE job_id=$1 AND task_id=$2;

-- name: GetJobActionDefinition :one
SELECT action_definition FROM jobs WHERE job_id=$1;

-- name: ListJobAuthorizationHosts :many
SELECT DISTINCT t.host_id,h.authorization_labels FROM tasks t JOIN hosts h ON h.host_id=t.host_id WHERE t.job_id=$1 AND ($2='' OR t.hostname=$2) ORDER BY t.host_id;

-- name: GetTaskOutputByHostname :one
SELECT t.task_id,t.host_id,t.result,t.created_at,t.output_stored,t.output_state,j.action_definition FROM tasks t JOIN jobs j ON j.job_id=t.job_id WHERE t.job_id=$1 AND t.hostname=$2;

-- name: GetTaskStepResult :one
SELECT result FROM task_steps WHERE job_id=$1 AND task_id=$2 AND step_index=$3;

-- name: ListJobTaskPreviews :many
SELECT task_id,hostname,result,stdout_preview,stderr_preview,stdout_sha256,stderr_sha256,stdout_size,stderr_size FROM tasks WHERE job_id=$1 ORDER BY position;
