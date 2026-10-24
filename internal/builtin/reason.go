package builtin

import "errors"

// Stable builtin failure reasons (log search design 6.7 and 8.2). A builtin
// error carries one by implementing interface{ Reason() string }; the agent
// forwards only codes in this list as ExecutionResult.reason.
const (
	ReasonSourceUnknown     = "SOURCE_UNKNOWN"
	ReasonSourceNoFiles     = "SOURCE_NO_FILES"
	ReasonSourceUnsupported = "SOURCE_UNSUPPORTED"
	ReasonSourceUnavailable = "SOURCE_UNAVAILABLE"
	ReasonPathOutsideRoots  = "PATH_OUTSIDE_ROOTS"
	ReasonWindowTooLarge    = "WINDOW_TOO_LARGE"
	ReasonTimeInvalid       = "TIME_INVALID"
	ReasonTimestampUnparsed = "TIMESTAMP_UNPARSED"
	ReasonPatternInvalid    = "PATTERN_INVALID"
	ReasonCursorInvalid     = "CURSOR_INVALID"
	ReasonCursorExpired     = "CURSOR_EXPIRED"
	// ReasonLevelUnsupported: the log source declares no level rule (log
	// search design 7.3).
	ReasonLevelUnsupported = "LEVEL_UNSUPPORTED"
)

var reasons = map[string]bool{
	ReasonSourceUnknown: true, ReasonSourceNoFiles: true, ReasonSourceUnsupported: true,
	ReasonSourceUnavailable: true, ReasonPathOutsideRoots: true, ReasonWindowTooLarge: true, ReasonTimeInvalid: true,
	ReasonTimestampUnparsed: true, ReasonPatternInvalid: true, ReasonCursorInvalid: true,
	ReasonCursorExpired: true, ReasonLevelUnsupported: true,
}

// KnownReason reports whether code may be forwarded unchanged.
func KnownReason(code string) bool { return reasons[code] }

// ReasonOf returns the first listed reason carried by err, or "".
func ReasonOf(err error) string {
	var r interface{ Reason() string }
	if errors.As(err, &r) && reasons[r.Reason()] {
		return r.Reason()
	}
	return ""
}

// Error attaches a reason code to a host-local message. Only the code leaves
// the host; the message stays in local errors.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string  { return e.Message }
func (e *Error) Reason() string { return e.Code }

// NewError returns an error carrying code. message defaults to code.
func NewError(code, message string) error {
	if message == "" {
		message = code
	}
	return &Error{Code: code, Message: message}
}
