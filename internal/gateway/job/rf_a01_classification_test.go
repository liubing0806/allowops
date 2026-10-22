package job

import (
	"context"
	"testing"
	"time"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/store"
)

type rfCancelErrorRouter struct{ err error }

func (r rfCancelErrorRouter) Send(context.Context, string, *v1.ConnectResponse) (*v1.TaskCompleted, error) {
	return nil, r.err
}
func TestRFA01CancellationErrorClassification(t *testing.T) {
	s := concurrencyFixture(t)
	for _, tc := range []struct {
		name   string
		err    error
		status int16
	}{{"capacity", store.ErrCapacity, 2}, {"request_cancelled", context.Canceled, 2}, {"connection_offline", store.ErrOffline, 6}} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.Store.Pool.Exec(context.Background(), "UPDATE tasks SET status=2 WHERE task_id='fast'"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Store.Pool.Exec(context.Background(), "DELETE FROM tasks WHERE task_id='slow'"); err != nil {
				t.Fatal(err)
			}
			s.Router = rfCancelErrorRouter{err: tc.err}
			ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
			defer cancel()
			s.cancelTasks(ctx, "job")
			var status int16
			if err := s.Store.Pool.QueryRow(context.Background(), "SELECT status FROM tasks WHERE task_id='fast'").Scan(&status); err != nil {
				t.Fatal(err)
			}
			if status != tc.status {
				t.Errorf("cancel send error=%v task status=%d; want %d", tc.err, status, tc.status)
			}
		})
	}
}
