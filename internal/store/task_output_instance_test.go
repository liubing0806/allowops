package store

import (
	"context"
	"testing"

	"github.com/liubing0806/allowops/internal/testpg"
)

// Tasks written before the owner column keep an unknown (NULL) owner, and a
// partition created before the upgrade gains the column and its index.
func TestTaskOutputInstanceUpgradeCoversExistingPartitions(t *testing.T) {
	ctx := context.Background()
	dsn := testpg.Start(t)
	p, closeDB, err := migrationProvider(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDB()
	if _, err := p.UpTo(ctx, 7); err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `INSERT INTO gateway_instances(instance_id) VALUES ('fixture');
 INSERT INTO hosts(host_id,hostname,certificate_serial,certificate_expires_at) VALUES ('host','host','serial',now()+interval '1 hour');
 INSERT INTO jobs(job_id,created_at,subject_id,origin_instance,action,action_definition,catalog_id,catalog_version,action_sha256,policy_version,reason,status,batch_size,max_failures)
 VALUES ('job',now(),'sa','fixture','action',convert_to('{}','UTF8'),'catalog',1,decode(repeat('00',32),'hex'),1,'test',3,1,0);
 CREATE TABLE tasks_old PARTITION OF tasks DEFAULT;
 INSERT INTO tasks(job_id,task_id,created_at,host_id,hostname,position,status,result)
 SELECT job_id,'task',created_at,'host','host',0,3,decode('0803','hex') FROM jobs;`); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	var owner *string
	var column, index bool
	if err := s.Pool.QueryRow(ctx, `SELECT (SELECT output_instance FROM tasks WHERE task_id='task'),
 EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name='tasks_old' AND column_name='output_instance'),
 EXISTS(SELECT 1 FROM pg_indexes WHERE tablename='tasks_old' AND indexdef LIKE '%(output_instance)%')`).Scan(&owner, &column, &index); err != nil {
		t.Fatal(err)
	}
	if owner != nil || !column || !index {
		t.Fatalf("existing task owner=%v partition column=%t index=%t; want NULL,true,true", owner, column, index)
	}
}
