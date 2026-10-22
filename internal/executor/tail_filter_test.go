package executor

import (
	"fmt"
	"io"
	"runtime"
	"strings"
	"testing"

	"github.com/liubing0806/allowops/internal/redact"
)

// numberedLines yields count lines of exactly 8 bytes ("%07d\n") without
// materializing the stream, so a test can feed far more input than it retains.
type numberedLines struct {
	count, next int
	pending     string
	atEOF       func()
}

func (r *numberedLines) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if r.pending == "" {
			if r.next >= r.count {
				if n == 0 {
					if r.atEOF != nil {
						r.atEOF()
					}
					return 0, io.EOF
				}
				break
			}
			r.pending = fmt.Sprintf("%07d\n", r.next)
			r.next++
		}
		c := copy(p[n:], r.pending)
		r.pending = r.pending[c:]
		n += c
	}
	return n, nil
}

func TestTailKeepsNewestLinesThatFitOutputLimit(t *testing.T) {
	out := &limitedOutput{limit: 80}
	input := &numberedLines{count: 1000}
	if err := streamStdout(input, out, &redact.Redactor{}, FilterOptions{Tail: 500}, DefaultMaxScan); err != nil {
		t.Fatal(err)
	}
	var want strings.Builder
	for i := 990; i < 1000; i++ {
		fmt.Fprintf(&want, "%07d\n", i)
	}
	if got := out.buffer.String(); got != want.String() {
		t.Errorf("tail output = %q, want the newest lines that fit: %q", got, want.String())
	}
	if !out.truncated {
		t.Error("lines older than the limit were dropped but truncated is not set")
	}
}

func TestTailWithinLimitIsNotTruncated(t *testing.T) {
	out := &limitedOutput{limit: 1 << 20}
	if err := streamStdout(&numberedLines{count: 1000}, out, &redact.Redactor{}, FilterOptions{Tail: 3}, DefaultMaxScan); err != nil {
		t.Fatal(err)
	}
	if got, want := out.buffer.String(), "0000997\n0000998\n0000999\n"; got != want {
		t.Errorf("tail output = %q, want %q", got, want)
	}
	if out.truncated {
		t.Error("tail asked for fewer lines than the limit allows; truncated must stay false")
	}
}

func TestTailLinesEvictedByCountDoNotMarkTruncation(t *testing.T) {
	// The two long lines are dropped for bytes while they are still in the
	// window, but the two lines tail finally asks for fit the limit.
	out := &limitedOutput{limit: 10}
	if err := streamStdout(strings.NewReader("aaaaaaa\nbbbbbbb\ncc\ndd\n"), out, &redact.Redactor{}, FilterOptions{Tail: 2}, DefaultMaxScan); err != nil {
		t.Fatal(err)
	}
	if got, want := out.buffer.String(), "cc\ndd\n"; got != want {
		t.Errorf("tail output = %q, want %q", got, want)
	}
	if out.truncated {
		t.Error("every line tail asked for was returned; truncated must stay false")
	}
}

func TestTailMemoryIsBoundedByOutputLimit(t *testing.T) {
	const lines = 3 << 20
	var before, during runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	out := &limitedOutput{limit: 1 << 20}
	input := &numberedLines{count: lines}
	// At EOF the writer still holds everything it retained for the tail.
	input.atEOF = func() {
		runtime.GC()
		runtime.ReadMemStats(&during)
	}
	if err := streamStdout(input, out, &redact.Redactor{}, FilterOptions{Tail: 1 << 30}, DefaultMaxScan); err != nil {
		t.Fatal(err)
	}
	// 3M lines of 8 bytes retain at least 24 MiB of text plus per-line
	// overhead; the bound is the 1 MiB output limit plus bookkeeping.
	if grown := int64(during.HeapAlloc) - int64(before.HeapAlloc); grown > 8<<20 {
		t.Errorf("tail retained %d MiB of heap for a 1 MiB output limit", grown>>20)
	}
	if got := out.buffer.Len(); got > 1<<20 {
		t.Errorf("output is %d bytes, over the 1 MiB limit", got)
	}
	if want := fmt.Sprintf("%07d\n", lines-1); !strings.HasSuffix(out.buffer.String(), want) {
		t.Errorf("output does not end with the newest line %q", want)
	}
}
