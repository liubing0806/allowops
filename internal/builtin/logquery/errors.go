package logquery

import "fmt"

// Error codes from docs/log-search-design.md 6.7. The executor and agent pass
// them through as the execution reason; the gateway maps them to hints.
const (
	CodeSourceUnknown     = "SOURCE_UNKNOWN"
	CodeSourceNoFiles     = "SOURCE_NO_FILES"
	CodePathOutsideRoots  = "PATH_OUTSIDE_ROOTS"
	CodeWindowTooLarge    = "WINDOW_TOO_LARGE"
	CodeTimeInvalid       = "TIME_INVALID"
	CodeTimestampUnparsed = "TIMESTAMP_UNPARSED"
	CodePatternInvalid    = "PATTERN_INVALID"
	CodeCursorInvalid     = "CURSOR_INVALID"
	CodeCursorExpired     = "CURSOR_EXPIRED"
	// CodeLevelUnsupported: level was given for a source without a level
	// rule (design 7.3).
	CodeLevelUnsupported = "LEVEL_UNSUPPORTED"
)

// Error carries a fixed reason code. Message holds request-specific detail,
// such as the available source names or the RE2 error position.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string  { return e.Code + ": " + e.Message }
func (e *Error) Reason() string { return e.Code }

func codeError(code, format string, args ...any) error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}
