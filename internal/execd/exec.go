package execd

import (
	"context"
	"errors"
	"io"
	"os"
	"os/user"
	"strconv"
	"syscall"

	"github.com/liubing0806/allowops/internal/catalog"
	"github.com/liubing0806/allowops/internal/executor"
	"github.com/liubing0806/allowops/internal/params"
)

type Response struct {
	Result executor.Result `json:"result"`
	Reason string          `json:"reason,omitempty"`
}

type Event struct {
	Type     string    `json:"type"`
	Response *Response `json:"response,omitempty"`
}

func DefaultCache() Cache {
	return Cache{CatalogDir: CatalogDirectory, KeysDir: KeyDirectory, StateDir: StateDirectory, StateOwner: 0, KeyOwner: 0}
}

// Prepare authenticates one in-memory package. It never trusts an action or
// executable path supplied by the caller, and revalidates parameters as root.
func Prepare(cache Cache, request Request) (catalog.Action, error) {
	p, err := cache.Load(request.CatalogID, request.CatalogVersion)
	if err != nil {
		return catalog.Action{}, err
	}
	a, ok := p.Actions[request.Action]
	if !ok {
		return a, errors.New("ACTION_UNKNOWN")
	}
	if a.RunAs == "" && a.RequiresExec() {
		a.RunAs = "root"
	}
	if a.RunAs == "" {
		return a, errors.New("RUN_AS_REQUIRED")
	}
	defs, err := catalog.ParameterDefinitions(a)
	if err != nil {
		return a, errors.New("ACTION_UNSUPPORTED")
	}
	if _, err := params.Parse(defs, request.Params); err != nil {
		return a, errors.New("INVALID_PARAMETERS")
	}
	if _, err := executor.ParseFilters(a.Filters, request.Filters); err != nil {
		return a, errors.New("INVALID_FILTERS")
	}
	if _, err := identity(a.RunAs); err != nil {
		return a, err
	}
	if !catalog.CheckHost(a).Supported {
		return a, errors.New("ACTION_UNSUPPORTED")
	}
	return a, nil
}

type account struct {
	uid    int
	gid    int
	groups []int
}

func identity(name string) (account, error) {
	var result account
	u, err := user.Lookup(name)
	if err != nil {
		return result, errors.New("RUN_AS_UNKNOWN")
	}
	result.uid, err = strconv.Atoi(u.Uid)
	if err != nil || result.uid < 0 {
		return result, errors.New("RUN_AS_UNKNOWN")
	}
	result.gid, err = strconv.Atoi(u.Gid)
	if err != nil || result.gid < 0 {
		return result, errors.New("RUN_AS_UNKNOWN")
	}
	groups, err := u.GroupIds()
	if err != nil {
		return result, errors.New("RUN_AS_UNKNOWN")
	}
	for _, group := range groups {
		id, err := strconv.Atoi(group)
		if err != nil || id < 0 {
			return result, errors.New("RUN_AS_UNKNOWN")
		}
		result.groups = append(result.groups, id)
	}
	return result, nil
}

func dropIdentity(a account) error {
	// syscall uses all-thread credential changes in the static Go build.
	if err := syscall.Setgroups(a.groups); err != nil {
		return errors.New("SETGROUPS_FAILED")
	}
	if err := syscall.Setgid(a.gid); err != nil {
		return errors.New("SETGID_FAILED")
	}
	if err := syscall.Setuid(a.uid); err != nil {
		return errors.New("SETUID_FAILED")
	}
	if os.Getuid() != a.uid || os.Geteuid() != a.uid || os.Getgid() != a.gid || os.Getegid() != a.gid {
		return errors.New("IDENTITY_CHANGE_FAILED")
	}
	return nil
}

// Execute is process-scoped: it permanently changes the helper's identity and
// must only be called once. Tests that execute it run in a separate container.
func Execute(ctx context.Context, input io.Reader) Response {
	return ExecuteWithCallbacks(ctx, input, executor.Callbacks{})
}

func ExecuteWithCallbacks(ctx context.Context, input io.Reader, callbacks executor.Callbacks) Response {
	response := Response{Result: executor.Result{ExitCode: -1}}
	request, err := ReadRequest(input)
	if err != nil {
		response.Reason = err.Error()
		return response
	}
	if os.Geteuid() != 0 {
		response.Reason = "ROOT_REQUIRED"
		return response
	}
	a, err := Prepare(DefaultCache(), request)
	if err != nil {
		response.Reason = "REQUEST_REJECTED"
		return response
	}
	account, err := identity(a.RunAs)
	if err != nil {
		response.Reason = err.Error()
		return response
	}
	if err := dropIdentity(account); err != nil {
		response.Reason = err.Error()
		return response
	}
	response.Result, err = executor.RunWithCallbacks(ctx, a, request.Params, request.Filters, nil, callbacks)
	response.Reason = ExecutionReason(err)
	return response
}

func ExecutionReason(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.Canceled):
		return "CANCELLED"
	case errors.Is(err, context.DeadlineExceeded):
		return "TIMEOUT"
	case errors.Is(err, params.ErrPathNotTrusted):
		return "PATH_NOT_TRUSTED"
	default:
		return "EXECUTION_FAILED"
	}
}
