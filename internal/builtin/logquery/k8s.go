package logquery

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// podLogRoot is where the kubelet writes Pod logs; tests replace it.
var podLogRoot = "/var/log/pods"

// resolvePodFiles finds the log files of the source's container in the Pods
// on this node: <podLogRoot>/<namespace>_<pod>_<uid>/<container>/*.log*,
// with the namespace equal to the source's and the Pod name starting with
// its prefix. Namespaces and Pod names contain no '_'.
func resolvePodFiles(ctx context.Context, source Source) (resolvedFiles, error) {
	var result resolvedFiles
	entries, err := os.ReadDir(podLogRoot)
	if os.IsNotExist(err) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	seen := map[[2]uint64]bool{}
	for _, entry := range entries {
		parts := strings.Split(entry.Name(), "_")
		if len(parts) != 3 || parts[0] != source.Namespace || !strings.HasPrefix(parts[1], source.Pod) {
			continue
		}
		inner := filepath.Join(entry.Name(), source.Container)
		display := func(rel string) string { return filepath.Join(podLogRoot, inner, rel) }
		if err := globRoot(ctx, podLogRoot, inner, "*.log*", display, &result, seen); err != nil {
			return result, err
		}
	}
	sortFiles(result.files)
	return result, nil
}

// criLines reads CRI log lines, "<RFC3339Nano> <stdout|stderr> <P|F> <content>",
// and joins the P (partial) fragments of a line with the following ones up to
// the F fragment. The line takes the time and offset of its first fragment.
// A line not in this format is returned unstamped.
type criLines struct {
	lines *lineReader
	max   int
}

func (c *criLines) position() int64 { return c.lines.offset }

func (c *criLines) next() (rawLine, error) {
	var out rawLine
	var text strings.Builder
	first := true
	for {
		line, err := c.lines.next()
		if err != nil {
			if err == io.EOF && !first {
				break
			}
			return out, err
		}
		at, stream, partial, content, ok := parseCRI(line.text)
		if first {
			if !ok {
				return line, nil
			}
			out = rawLine{offset: line.offset, number: line.number, stamped: true, time: at, stream: stream}
			first = false
		}
		if !ok {
			content, partial = line.text, false
		}
		if room := c.max - text.Len(); room < len(content) {
			out.truncated = true
			content = cut(content, max(room, 0))
		}
		text.WriteString(content)
		out.truncated = out.truncated || line.truncated
		if !partial {
			break
		}
	}
	out.text = text.String()
	return out, nil
}

func parseCRI(line string) (at time.Time, stream string, partial bool, content string, ok bool) {
	stamp, rest, found := strings.Cut(line, " ")
	if !found {
		return
	}
	stream, rest, found = strings.Cut(rest, " ")
	if !found || (stream != "stdout" && stream != "stderr") {
		return
	}
	tag, content, _ := strings.Cut(rest, " ")
	// The tag may carry more flags after ':'; P marks a partial line.
	flag, _, _ := strings.Cut(tag, ":")
	if flag != "P" && flag != "F" {
		return
	}
	var err error
	if at, err = time.Parse(time.RFC3339Nano, stamp); err != nil {
		return
	}
	return at, stream, flag == "P", content, true
}
