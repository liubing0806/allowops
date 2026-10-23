package job

import (
	"context"
	"encoding/hex"
	"fmt"
	"unicode/utf8"

	"connectrpc.com/connect"
	v1 "github.com/liubing0806/allowops/gen/allowops/v1"
	"github.com/liubing0806/allowops/internal/gateway/authz"
	"github.com/liubing0806/allowops/internal/store"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// PreviewSource is the replaceable boundary for reading output previews stored by other instances (design A23).
// Implementations must return only redacted, filtered, bounded previews.
type PreviewSource interface {
	Load(context.Context, string) ([]Preview, error)
}

type Preview struct {
	Task                   *v1.Task
	Stdout, Stderr         []byte
	StdoutHash, StderrHash []byte
	StdoutSize, StderrSize uint64
}

type DatabasePreviews struct{ Store *store.Store }

func (p *DatabasePreviews) Load(ctx context.Context, id string) ([]Preview, error) {
	return listJobTaskPreviews(ctx, p.Store.Pool, id)
}

func textPrefix(b []byte, n int) string {
	b = b[:min(n, len(b))]
	for len(b) > 0 && !utf8.Valid(b) {
		b = b[:len(b)-1]
	}
	return string(b)
}

func (s *Service) summary(ctx context.Context, j *v1.Job, f string) (*v1.JobSummary, error) {
	result := &v1.JobSummary{OutputTrust: v1.OutputTrust_OUTPUT_TRUST_UNTRUSTED}
	if _, _, err := s.authorize(ctx, j, authz.ViewOutput, false, ""); err != nil {
		if connect.CodeOf(err) == connect.CodePermissionDenied {
			return result, nil
		}
		return nil, err
	}
	items, err := s.Previews.Load(ctx, j.JobId)
	if err != nil {
		return nil, err
	}
	groups := map[string]*v1.OutputGroup{}
	for _, p := range items {
		if p.Task.Result.Status == v1.TaskStatus_TASK_STATUS_OFFLINE {
			result.OfflineHosts = append(result.OfflineHosts, p.Task.Hostname)
		}
		if len(p.StdoutHash) != 32 || len(p.StderrHash) != 32 {
			continue
		}
		exit := "absent"
		if p.Task.Result.ExitCode != nil {
			exit = fmt.Sprint(*p.Task.Result.ExitCode)
		}
		key := exit + ":" + hex.EncodeToString(p.StdoutHash) + ":" + hex.EncodeToString(p.StderrHash)
		g := groups[key]
		if g == nil {
			stdout := textPrefix(p.Stdout, GroupBytes)
			stderr := textPrefix(p.Stderr, GroupBytes-len(stdout))
			g = &v1.OutputGroup{ExitCode: p.Task.Result.ExitCode, StdoutSha256: p.StdoutHash, StderrSha256: p.StderrHash, Stdout: stdout, Stderr: stderr, Truncated: p.Task.Result.Truncated || uint64(len(stdout)) < p.StdoutSize || uint64(len(stderr)) < p.StderrSize}
			groups[key] = g
			result.Groups = append(result.Groups, g)
		}
		g.HostCount++
		if f == "detailed" || len(g.Hosts) < 2 {
			g.Hosts = append(g.Hosts, p.Task.Hostname)
		}
	}
	// Measure the entire protobuf JSON response, accounting for escaping/base64.
	response := &v1.GetJobResponse{Job: j, Summary: result}
	for {
		b, err := protojson.Marshal(response)
		if err != nil {
			return nil, err
		}
		if len(b) <= ResponseBytes && proto.Size(response) <= ResponseBytes {
			break
		}
		result.Truncated = true
		if n := len(result.Groups); n > 0 {
			g := result.Groups[n-1]
			switch {
			case len(g.Hosts) > 2:
				g.Hosts = g.Hosts[:len(g.Hosts)-1]
			case g.Stderr != "":
				g.Stderr = ""
				g.Truncated = true
			case g.Stdout != "":
				g.Stdout = ""
				g.Truncated = true
			default:
				result.Groups = result.Groups[:n-1]
			}
		} else if len(result.OfflineHosts) > 0 {
			result.OfflineHosts = result.OfflineHosts[:len(result.OfflineHosts)-1]
		} else {
			return nil, failure(connect.CodeResourceExhausted, "JOB_RESPONSE_LIMIT")
		}
	}
	return result, nil
}
