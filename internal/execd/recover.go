package execd

import (
	"context"
	"strings"

	"github.com/liubing0806/allowops/internal/builtin/jvmarthas"
	"github.com/liubing0806/allowops/internal/executor"
)

// recoverArthas ends the Arthas servers that earlier calls left behind. Tests replace it.
var recoverArthas = func(ctx context.Context) (jvmarthas.Recovery, error) {
	return jvmarthas.Recover(ctx, jvmarthas.NewEnv())
}

// runArthasRecover answers the arthas_recover request. The helper runs as root and keeps its
// identity, because the state directory and the target processes belong to root. The summary is on
// stdout and is empty when there was nothing to do; the records that could not be cleared are on
// stderr and make the request fail.
func runArthasRecover(ctx context.Context, callbacks executor.Callbacks) Response {
	response := Response{Result: executor.Result{ExitCode: -1}}
	if callbacks.Started != nil {
		if err := callbacks.Started(); err != nil {
			response.Reason = "EXECUTION_FAILED"
			return response
		}
	}
	rec, err := recoverArthas(ctx)
	if summary := rec.String(); summary != "" {
		response.Result.Stdout = "arthas recovery: " + summary + "\n"
	}
	switch {
	case ctx.Err() != nil:
		response.Reason = ExecutionReason(ctx.Err())
	case err != nil:
		response.Result.Stderr = err.Error() + "\n"
		response.Reason = "EXECUTION_FAILED"
	case len(rec.Failed) > 0:
		response.Result.Stderr = strings.Join(rec.Failed, "\n") + "\n"
		response.Reason = "EXECUTION_FAILED"
	}
	if response.Reason == "" {
		response.Result.ExitCode = 0
	} else {
		response.Result.ExitCode = 1
	}
	return response
}
