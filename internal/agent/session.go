package agent

import (
	"context"
	"errors"
	"math/rand/v2"
	"sync"
	"time"

	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/gen/allowops/v1/allowopsv1connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type outgoing struct {
	message *v1.ConnectRequest
	done    chan error
}
type received struct {
	message *v1.ConnectResponse
	err     error
}
type runningTask struct {
	job    string
	cancel context.CancelFunc
}

func (a *Agent) session(parent context.Context, client allowopsv1connect.AgentServiceClient) (time.Duration, error) {
	ctx, cancel := context.WithCancel(parent)
	stream := client.Connect(ctx)
	var workers sync.WaitGroup
	defer func() { cancel(); _ = stream.CloseRequest(); _ = stream.CloseResponse(); workers.Wait() }()
	if err := stream.Send(&v1.ConnectRequest{Message: &v1.ConnectRequest_Hello{Hello: a.hello()}}); err != nil {
		return 0, err
	}
	incoming := make(chan received, 1)
	workers.Go(func() {
		for {
			message, err := stream.Receive()
			select {
			case incoming <- received{message, err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	})
	var hello *v1.GatewayHello
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case response := <-incoming:
		if response.err != nil {
			return 0, response.err
		}
		hello = response.message.GetHello()
	case <-timer.C:
		return 0, errors.New("HELLO_TIMEOUT")
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	if hello == nil || hello.ConnectionId == "" || hello.Limits == nil {
		return 0, errors.New("INVALID_GATEWAY_HELLO")
	}
	limits := hello.Limits
	if limits.HeartbeatInterval == nil || limits.HeartbeatInterval.CheckValid() != nil || limits.HeartbeatTimeout == nil || limits.HeartbeatTimeout.CheckValid() != nil {
		return 0, errors.New("INVALID_CONNECTION_LIMITS")
	}
	interval, timeout := limits.HeartbeatInterval.AsDuration(), limits.HeartbeatTimeout.AsDuration()
	if interval <= 0 || timeout <= interval || limits.MaxMessageBytes == 0 || limits.MaxChunkBytes == 0 || limits.MaxInflightTasks == 0 {
		return 0, errors.New("INVALID_CONNECTION_LIMITS")
	}
	if err := a.writeStatus(hello.ConnectionId, true); err != nil {
		return 0, err
	}
	defer a.writeStatus("", true)
	chunkSize := min(int(limits.MaxChunkBytes), a.config.Limits.ChunkBytes)
	messageSize := min(int(limits.MaxMessageBytes), a.config.Limits.MessageBytes)
	capacity := min(int(limits.MaxInflightTasks), a.config.Limits.ConcurrentTasks)
	controls := make(chan outgoing, a.config.Limits.ControlMessages)
	outputs := make(chan outgoing, max(1, a.config.Limits.OutputQueueBytes/chunkSize))
	sendErr := make(chan error, 1)
	workers.Go(func() {
		for {
			var item outgoing
			select {
			case item = <-controls:
			default:
				select {
				case item = <-controls:
				case item = <-outputs:
				case <-ctx.Done():
					return
				}
			}
			err := stream.Send(item.message)
			item.done <- err
			if err != nil {
				sendErr <- err
				cancel()
				return
			}
		}
	})
	send := func(message *v1.ConnectRequest, output bool) error {
		if proto.Size(message) > messageSize {
			cancel()
			return errors.New("MESSAGE_TOO_LARGE")
		}
		item := outgoing{message: message, done: make(chan error, 1)}
		queue := controls
		if output {
			queue = outputs
		}
		select {
		case queue <- item:
		case <-ctx.Done():
			return ctx.Err()
		}
		select {
		case err := <-item.done:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	// Catalog workers keep pulls bounded and leave the receiver free
	// to handle cancellations, heartbeat replies and task assignments.
	pulls := make(chan *v1.CatalogAvailable, a.config.Limits.ControlMessages)
	for range a.config.Limits.CatalogPulls {
		workers.Go(func() {
			for {
				select {
				case notice := <-pulls:
					pullClient, pullTransport, err := newClient(a.config, a.identity)
					if err != nil {
						cancel()
						return
					}
					reports, err := a.catalogs.pull(ctx, pullClient, notice)
					pullTransport.CloseIdleConnections()
					if err != nil {
						cancel()
						return
					}
					for _, report := range reports {
						if send(&v1.ConnectRequest{Message: &v1.ConnectRequest_CatalogLoad{CatalogLoad: report}}, false) != nil {
							cancel()
							return
						}
					}
					if err := a.writeStatus(hello.ConnectionId, true); err != nil {
						cancel()
						return
					}
				case <-ctx.Done():
					return
				}
			}
		})
	}
	active := map[string]runningTask{}
	seen := map[string]bool{}
	seenBytes := 0
	tokens, lastToken := float64(a.config.Limits.ReceiveBurst), time.Now()
	finished := make(chan string, capacity)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	heartbeatDeadline := time.NewTimer(timeout)
	defer heartbeatDeadline.Stop()
	var sequence, acknowledged uint64
	draining := false
	var retryDelay time.Duration
	var closeTimer *time.Timer
	var closeAt <-chan time.Time
	defer func() {
		if closeTimer != nil {
			closeTimer.Stop()
		}
		for _, task := range active {
			task.cancel()
		}
	}()
	for {
		if draining && len(active) == 0 {
			return retryDelay, nil
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case err := <-sendErr:
			return 0, err
		case <-heartbeatDeadline.C:
			return 0, errors.New("HEARTBEAT_TIMEOUT")
		case <-closeAt:
			return retryDelay, nil
		case <-ticker.C:
			sequence++
			heartbeat := &v1.ConnectRequest{Message: &v1.ConnectRequest_Heartbeat{Heartbeat: &v1.AgentHeartbeat{Sequence: sequence, SentAt: timestamppb.Now(), RunningTasks: uint32(len(active))}}}
			// Never block the receiver on a slow network write.
			item := outgoing{message: heartbeat, done: make(chan error, 1)}
			select {
			case controls <- item:
			default:
				return 0, errors.New("SEND_QUEUE_FULL")
			}
		case id := <-finished:
			if task, ok := active[id]; ok {
				task.cancel()
				delete(active, id)
			}
		case response := <-incoming:
			if response.err != nil {
				return 0, response.err
			}
			now := time.Now()
			tokens = min(float64(a.config.Limits.ReceiveBurst), tokens+now.Sub(lastToken).Seconds()*float64(a.config.Limits.ReceiveRate))
			lastToken = now
			if tokens < 1 || proto.Size(response.message) > messageSize {
				return 0, errors.New("RECEIVE_LIMIT_EXCEEDED")
			}
			tokens--
			switch message := response.message.Message.(type) {
			case *v1.ConnectResponse_Heartbeat:
				if message.Heartbeat.Sequence == 0 || message.Heartbeat.Sequence > sequence || message.Heartbeat.Sequence <= acknowledged {
					return 0, errors.New("INVALID_HEARTBEAT")
				}
				acknowledged = message.Heartbeat.Sequence
				heartbeatDeadline.Reset(timeout)
			case *v1.ConnectResponse_CatalogAvailable:
				select {
				case pulls <- message.CatalogAvailable:
				default:
					return 0, errors.New("CATALOG_QUEUE_FULL")
				}
			case *v1.ConnectResponse_Task:
				task := message.Task
				if task == nil || task.TaskId == "" || task.JobId == "" {
					return 0, errors.New("INVALID_TASK")
				}
				if seen[task.TaskId] {
					continue
				}
				seenBytes += len(task.TaskId)
				if seenBytes > a.config.Limits.MessageBytes*a.config.Limits.ControlMessages {
					return 0, errors.New("TASK_HISTORY_LIMIT_EXCEEDED")
				}
				seen[task.TaskId] = true
				if draining || len(active) >= capacity {
					item := outgoing{message: completed(task, &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_FAILED, Reason: "AGENT_CAPACITY_EXCEEDED"}), done: make(chan error, 1)}
					select {
					case controls <- item:
					default:
						return 0, errors.New("SEND_QUEUE_FULL")
					}
					continue
				}
				taskCtx, taskCancel := context.WithCancel(ctx)
				active[task.TaskId] = runningTask{job: task.JobId, cancel: taskCancel}
				workers.Go(func() {
					a.execute(taskCtx, task, chunkSize, send)
					select {
					case finished <- task.TaskId:
					case <-ctx.Done():
					}
				})
			case *v1.ConnectResponse_Cancel:
				if task, ok := active[message.Cancel.GetTaskId()]; ok && task.job == message.Cancel.GetJobId() {
					task.cancel()
				}
			case *v1.ConnectResponse_Reconnect:
				reconnect := message.Reconnect
				if reconnect == nil || reconnect.CloseAt == nil || reconnect.CloseAt.CheckValid() != nil {
					return 0, errors.New("INVALID_RECONNECT")
				}
				minDelay, maxDelay := a.config.Limits.ReconnectMin, a.config.Limits.ReconnectMax
				for _, value := range []*durationpb.Duration{reconnect.RetryAfterMin, reconnect.RetryAfterMax} {
					if value == nil || value.CheckValid() != nil || value.AsDuration() < 0 {
						return 0, errors.New("INVALID_RECONNECT")
					}
				}
				minDelay = max(minDelay, min(a.config.Limits.ReconnectMax, reconnect.RetryAfterMin.AsDuration()))
				maxDelay = max(a.config.Limits.ReconnectMin, min(maxDelay, reconnect.RetryAfterMax.AsDuration()))
				if maxDelay < minDelay {
					return 0, errors.New("INVALID_RECONNECT")
				}
				retryDelay = minDelay + time.Duration(rand.Int64N(int64(maxDelay-minDelay)+1))
				draining = true
				if closeTimer != nil {
					closeTimer.Stop()
				}
				closeTimer = time.NewTimer(max(0, time.Until(reconnect.CloseAt.AsTime())))
				closeAt = closeTimer.C
			default:
				return 0, errors.New("UNKNOWN_MESSAGE")
			}
		}
	}
}

func completed(task *v1.TaskAssignment, result *v1.ExecutionResult) *v1.ConnectRequest {
	return &v1.ConnectRequest{Message: &v1.ConnectRequest_TaskCompleted{TaskCompleted: &v1.TaskCompleted{JobId: task.JobId, TaskId: task.TaskId, Result: result, FinishedAt: timestamppb.Now()}}}
}
