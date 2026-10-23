package agent

import (
	"context"
	"errors"
	"math/rand/v2"
	"sync"
	"time"

	"connectrpc.com/connect"
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

// session runs one gateway connection. Concurrency structure:
//
//   - ctx is cancelled by the caller's context, by any worker failure, or on return.
//   - The receiver goroutine owns stream.Receive and hands messages to the loop
//     through incoming (capacity 1).
//   - The sender goroutine owns stream.Send. It drains controls before outputs,
//     reports the first send error on sendErr and cancels ctx.
//   - CatalogPulls catalog workers consume pulls. Any failure cancels ctx.
//   - One goroutine per task runs execute and then reports on finished.
//   - The loop in run is the only writer of the per-session state.
//
// Deferred cleanup runs in this order on every return: task cancellation and
// close timer, heartbeat deadline timer, ticker, the disconnected status write,
// then cancel, stream close and waiting for every worker.
func (a *Agent) session(parent context.Context, client allowopsv1connect.AgentServiceClient) (time.Duration, error) {
	ctx, cancel := context.WithCancel(parent)
	stream := client.Connect(ctx)
	var workers sync.WaitGroup
	defer func() { cancel(); _ = stream.CloseRequest(); _ = stream.CloseResponse(); workers.Wait() }()
	if err := stream.Send(&v1.ConnectRequest{Message: &v1.ConnectRequest_Hello{Hello: a.hello()}}); err != nil {
		return 0, err
	}
	incoming := startReceiver(ctx, stream, &workers)
	hello, err := awaitGatewayHello(ctx, incoming)
	if err != nil {
		return 0, err
	}
	interval, timeout, err := heartbeatLimits(hello)
	if err != nil {
		return 0, err
	}
	if err := a.writeStatus(hello.ConnectionId, true); err != nil {
		return 0, err
	}
	defer a.writeStatus("", true)
	s := a.newSessionLoop(ctx, cancel, stream, &workers, incoming, hello.Limits, interval, timeout)
	s.startSender()
	s.startCatalogWorkers(hello.ConnectionId)
	return s.run()
}

func startReceiver(ctx context.Context, stream *connect.BidiStreamForClient[v1.ConnectRequest, v1.ConnectResponse], workers *sync.WaitGroup) chan received {
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
	return incoming
}

func awaitGatewayHello(ctx context.Context, incoming <-chan received) (*v1.GatewayHello, error) {
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case response := <-incoming:
		if response.err != nil {
			return nil, response.err
		}
		hello := response.message.GetHello()
		if hello == nil || hello.ConnectionId == "" || hello.Limits == nil {
			return nil, errors.New("INVALID_GATEWAY_HELLO")
		}
		return hello, nil
	case <-timer.C:
		return nil, errors.New("HELLO_TIMEOUT")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func heartbeatLimits(hello *v1.GatewayHello) (interval, timeout time.Duration, err error) {
	limits := hello.Limits
	if limits.HeartbeatInterval == nil || limits.HeartbeatInterval.CheckValid() != nil || limits.HeartbeatTimeout == nil || limits.HeartbeatTimeout.CheckValid() != nil {
		return 0, 0, errors.New("INVALID_CONNECTION_LIMITS")
	}
	interval, timeout = limits.HeartbeatInterval.AsDuration(), limits.HeartbeatTimeout.AsDuration()
	if interval <= 0 || timeout <= interval || limits.MaxMessageBytes == 0 || limits.MaxChunkBytes == 0 || limits.MaxInflightTasks == 0 {
		return 0, 0, errors.New("INVALID_CONNECTION_LIMITS")
	}
	return interval, timeout, nil
}

// sessionLoop holds the state of one connected session. Only run touches the
// mutable fields after the workers start.
type sessionLoop struct {
	agent    *Agent
	ctx      context.Context
	cancel   context.CancelFunc
	stream   *connect.BidiStreamForClient[v1.ConnectRequest, v1.ConnectResponse]
	workers  *sync.WaitGroup
	incoming <-chan received

	interval, timeout time.Duration
	chunkSize         int
	messageSize       int
	capacity          int

	controls chan outgoing
	outputs  chan outgoing
	sendErr  chan error
	pulls    chan *v1.CatalogAvailable
	finished chan string

	active    map[string]runningTask
	seen      map[string]bool
	seenBytes int

	tokens    float64
	lastToken time.Time

	sequence, acknowledged uint64
	draining               bool
	retryDelay             time.Duration
	closeTimer             *time.Timer
	closeAt                <-chan time.Time
	heartbeatDeadline      *time.Timer
}

func (a *Agent) newSessionLoop(ctx context.Context, cancel context.CancelFunc, stream *connect.BidiStreamForClient[v1.ConnectRequest, v1.ConnectResponse], workers *sync.WaitGroup, incoming <-chan received, limits *v1.ConnectionLimits, interval, timeout time.Duration) *sessionLoop {
	chunkSize := min(int(limits.MaxChunkBytes), a.config.Limits.ChunkBytes)
	capacity := min(int(limits.MaxInflightTasks), a.config.Limits.ConcurrentTasks)
	return &sessionLoop{
		agent: a, ctx: ctx, cancel: cancel, stream: stream, workers: workers, incoming: incoming,
		interval: interval, timeout: timeout,
		chunkSize:   chunkSize,
		messageSize: min(int(limits.MaxMessageBytes), a.config.Limits.MessageBytes),
		capacity:    capacity,
		controls:    make(chan outgoing, a.config.Limits.ControlMessages),
		outputs:     make(chan outgoing, max(1, a.config.Limits.OutputQueueBytes/chunkSize)),
		sendErr:     make(chan error, 1),
		pulls:       make(chan *v1.CatalogAvailable, a.config.Limits.ControlMessages),
		finished:    make(chan string, capacity),
		active:      map[string]runningTask{},
		seen:        map[string]bool{},
		tokens:      float64(a.config.Limits.ReceiveBurst),
		lastToken:   time.Now(),
	}
}

// startSender writes queued messages, preferring control messages over output.
func (s *sessionLoop) startSender() {
	s.workers.Go(func() {
		for {
			var item outgoing
			select {
			case item = <-s.controls:
			default:
				select {
				case item = <-s.controls:
				case item = <-s.outputs:
				case <-s.ctx.Done():
					return
				}
			}
			err := s.stream.Send(item.message)
			item.done <- err
			if err != nil {
				s.sendErr <- err
				s.cancel()
				return
			}
		}
	})
}

// send queues message and waits for the sender goroutine to write it.
func (s *sessionLoop) send(message *v1.ConnectRequest, output bool) error {
	if proto.Size(message) > s.messageSize {
		s.cancel()
		return errors.New("MESSAGE_TOO_LARGE")
	}
	item := outgoing{message: message, done: make(chan error, 1)}
	queue := s.controls
	if output {
		queue = s.outputs
	}
	select {
	case queue <- item:
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
	select {
	case err := <-item.done:
		return err
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

// enqueueControl never blocks the loop on a slow network write.
func (s *sessionLoop) enqueueControl(message *v1.ConnectRequest) error {
	item := outgoing{message: message, done: make(chan error, 1)}
	select {
	case s.controls <- item:
		return nil
	default:
		return errors.New("SEND_QUEUE_FULL")
	}
}

// Catalog workers keep pulls bounded and leave the receiver free
// to handle cancellations, heartbeat replies and task assignments.
func (s *sessionLoop) startCatalogWorkers(connectionID string) {
	for range s.agent.config.Limits.CatalogPulls {
		s.workers.Go(func() {
			for {
				select {
				case notice := <-s.pulls:
					if s.pullCatalog(connectionID, notice) != nil {
						s.cancel()
						return
					}
				case <-s.ctx.Done():
					return
				}
			}
		})
	}
}

func (s *sessionLoop) pullCatalog(connectionID string, notice *v1.CatalogAvailable) error {
	a := s.agent
	pullClient, pullTransport, err := newClient(a.config, a.identity)
	if err != nil {
		return err
	}
	reports, err := a.catalogs.pull(s.ctx, pullClient, notice)
	pullTransport.CloseIdleConnections()
	if err != nil {
		return err
	}
	for _, report := range reports {
		if err := s.send(&v1.ConnectRequest{Message: &v1.ConnectRequest_CatalogLoad{CatalogLoad: report}}, false); err != nil {
			return err
		}
	}
	return a.writeStatus(connectionID, true)
}

func (s *sessionLoop) run() (time.Duration, error) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	s.heartbeatDeadline = time.NewTimer(s.timeout)
	defer s.heartbeatDeadline.Stop()
	defer s.releaseTasks()
	for {
		if s.draining && len(s.active) == 0 {
			return s.retryDelay, nil
		}
		select {
		case <-s.ctx.Done():
			return 0, s.ctx.Err()
		case err := <-s.sendErr:
			return 0, err
		case <-s.heartbeatDeadline.C:
			return 0, errors.New("HEARTBEAT_TIMEOUT")
		case <-s.closeAt:
			return s.retryDelay, nil
		case <-ticker.C:
			if err := s.sendHeartbeat(); err != nil {
				return 0, err
			}
		case id := <-s.finished:
			s.finishTask(id)
		case response := <-s.incoming:
			if err := s.handleIncoming(response); err != nil {
				return 0, err
			}
		}
	}
}

func (s *sessionLoop) releaseTasks() {
	if s.closeTimer != nil {
		s.closeTimer.Stop()
	}
	for _, task := range s.active {
		task.cancel()
	}
}

func (s *sessionLoop) sendHeartbeat() error {
	s.sequence++
	return s.enqueueControl(&v1.ConnectRequest{Message: &v1.ConnectRequest_Heartbeat{Heartbeat: &v1.AgentHeartbeat{Sequence: s.sequence, SentAt: timestamppb.Now(), RunningTasks: uint32(len(s.active))}}})
}

func (s *sessionLoop) finishTask(id string) {
	if task, ok := s.active[id]; ok {
		task.cancel()
		delete(s.active, id)
	}
}

// admit applies the receive rate limit and the message size limit.
func (s *sessionLoop) admit(message *v1.ConnectResponse) error {
	limits := s.agent.config.Limits
	now := time.Now()
	s.tokens = min(float64(limits.ReceiveBurst), s.tokens+now.Sub(s.lastToken).Seconds()*float64(limits.ReceiveRate))
	s.lastToken = now
	if s.tokens < 1 || proto.Size(message) > s.messageSize {
		return errors.New("RECEIVE_LIMIT_EXCEEDED")
	}
	s.tokens--
	return nil
}

func (s *sessionLoop) handleIncoming(response received) error {
	if response.err != nil {
		return response.err
	}
	if err := s.admit(response.message); err != nil {
		return err
	}
	switch message := response.message.Message.(type) {
	case *v1.ConnectResponse_Heartbeat:
		return s.onHeartbeat(message.Heartbeat)
	case *v1.ConnectResponse_CatalogAvailable:
		select {
		case s.pulls <- message.CatalogAvailable:
			return nil
		default:
			return errors.New("CATALOG_QUEUE_FULL")
		}
	case *v1.ConnectResponse_Task:
		return s.onTask(message.Task)
	case *v1.ConnectResponse_Cancel:
		if task, ok := s.active[message.Cancel.GetTaskId()]; ok && task.job == message.Cancel.GetJobId() {
			task.cancel()
		}
		return nil
	case *v1.ConnectResponse_Reconnect:
		return s.onReconnect(message.Reconnect)
	default:
		return errors.New("UNKNOWN_MESSAGE")
	}
}

func (s *sessionLoop) onHeartbeat(heartbeat *v1.GatewayHeartbeat) error {
	if heartbeat.Sequence == 0 || heartbeat.Sequence > s.sequence || heartbeat.Sequence <= s.acknowledged {
		return errors.New("INVALID_HEARTBEAT")
	}
	s.acknowledged = heartbeat.Sequence
	s.heartbeatDeadline.Reset(s.timeout)
	return nil
}

func (s *sessionLoop) onTask(task *v1.TaskAssignment) error {
	limits := s.agent.config.Limits
	if task == nil || task.TaskId == "" || task.JobId == "" {
		return errors.New("INVALID_TASK")
	}
	if s.seen[task.TaskId] {
		return nil
	}
	s.seenBytes += len(task.TaskId)
	if s.seenBytes > limits.MessageBytes*limits.ControlMessages {
		return errors.New("TASK_HISTORY_LIMIT_EXCEEDED")
	}
	s.seen[task.TaskId] = true
	if s.draining || len(s.active) >= s.capacity {
		return s.enqueueControl(completed(task, &v1.ExecutionResult{Status: v1.TaskStatus_TASK_STATUS_FAILED, Reason: "AGENT_CAPACITY_EXCEEDED"}))
	}
	s.startTask(task)
	return nil
}

func (s *sessionLoop) startTask(task *v1.TaskAssignment) {
	taskCtx, taskCancel := context.WithCancel(s.ctx)
	s.active[task.TaskId] = runningTask{job: task.JobId, cancel: taskCancel}
	s.workers.Go(func() {
		s.agent.execute(taskCtx, task, s.chunkSize, s.send)
		select {
		case s.finished <- task.TaskId:
		case <-s.ctx.Done():
		}
	})
}

func (s *sessionLoop) onReconnect(reconnect *v1.Reconnect) error {
	if reconnect == nil || reconnect.CloseAt == nil || reconnect.CloseAt.CheckValid() != nil {
		return errors.New("INVALID_RECONNECT")
	}
	delay, err := s.agent.reconnectDelay(reconnect)
	if err != nil {
		return err
	}
	s.retryDelay = delay
	s.draining = true
	if s.closeTimer != nil {
		s.closeTimer.Stop()
	}
	s.closeTimer = time.NewTimer(max(0, time.Until(reconnect.CloseAt.AsTime())))
	s.closeAt = s.closeTimer.C
	return nil
}

// reconnectDelay picks a random retry delay inside the gateway bounds clamped
// to the agent's own reconnect limits.
func (a *Agent) reconnectDelay(reconnect *v1.Reconnect) (time.Duration, error) {
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
	return minDelay + time.Duration(rand.Int64N(int64(maxDelay-minDelay)+1)), nil
}

func completed(task *v1.TaskAssignment, result *v1.ExecutionResult) *v1.ConnectRequest {
	return &v1.ConnectRequest{Message: &v1.ConnectRequest_TaskCompleted{TaskCompleted: &v1.TaskCompleted{JobId: task.JobId, TaskId: task.TaskId, Result: result, FinishedAt: timestamppb.Now()}}}
}
