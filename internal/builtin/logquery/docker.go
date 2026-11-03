package logquery

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// dockerSocket is the Docker Engine API socket; tests replace it.
var dockerSocket = "/var/run/docker.sock"

// dockerClient calls the Docker Engine API without a version prefix, so the
// daemon serves its current version. Only GET requests are sent.
type dockerClient struct {
	http *http.Client
}

func newDockerClient() *dockerClient {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "unix", dockerSocket)
	}}
	return &dockerClient{http: &http.Client{Transport: transport}}
}

func (d *dockerClient) close() { d.http.CloseIdleConnections() }

// get returns the response body of a successful request. A missing container
// or an unreachable daemon is SOURCE_UNAVAILABLE; a daemon that cannot serve
// the request (501, such as a logging driver without read support) is
// SOURCE_UNSUPPORTED.
func (d *dockerClient) get(ctx context.Context, path string, query url.Values) (io.ReadCloser, error) {
	u := url.URL{Scheme: "http", Host: "docker", Path: path, RawQuery: query.Encode()}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	response, err := d.http.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, codeError(CodeSourceUnavailable, "Docker API: %v", err)
	}
	if response.StatusCode == http.StatusOK {
		return response.Body, nil
	}
	defer response.Body.Close()
	var body struct {
		Message string `json:"message"`
	}
	json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&body)
	switch response.StatusCode {
	case http.StatusNotFound:
		return nil, codeError(CodeSourceUnavailable, "Docker API %s: %s", path, body.Message)
	case http.StatusNotImplemented:
		return nil, codeError(CodeSourceUnsupported, "Docker API %s: %s", path, body.Message)
	}
	return nil, fmt.Errorf("docker API %s: status %d: %s", path, response.StatusCode, body.Message)
}

type dockerMount struct {
	Type        string
	Source      string
	Destination string
}

// containerInfo is the part of GET /containers/{name}/json that log_query uses.
// GraphDriver is absent when the daemon stores images with the containerd
// snapshotter.
type containerInfo struct {
	Config struct {
		Tty bool
	}
	Mounts      []dockerMount
	GraphDriver *struct {
		Name string
		Data map[string]string
	}
}

func (d *dockerClient) inspect(ctx context.Context, name string) (containerInfo, error) {
	var info containerInfo
	body, err := d.get(ctx, "/containers/"+name+"/json", nil)
	if err != nil {
		return info, err
	}
	defer body.Close()
	if err := json.NewDecoder(io.LimitReader(body, 4<<20)).Decode(&info); err != nil {
		return info, fmt.Errorf("docker inspect %s: %w", name, err)
	}
	return info, nil
}

// logs streams the container's output with Docker timestamps from since on.
// tail is "" for the whole range. until is never passed: older daemons do not
// support it, and the reader stops at the first record after the range.
func (d *dockerClient) logs(ctx context.Context, name string, since time.Time, tail string) (io.ReadCloser, error) {
	query := url.Values{"stdout": {"1"}, "stderr": {"1"}, "timestamps": {"1"}}
	if !since.IsZero() {
		query.Set("since", fmt.Sprintf("%d.%09d", since.Unix(), since.Nanosecond()))
	}
	if tail != "" {
		query.Set("tail", tail)
	}
	return d.get(ctx, "/containers/"+name+"/logs", query)
}

// dockerLines reads the logs stream. Without a terminal it is multiplexed:
// each frame has an 8-byte header (stream, 3 zero bytes, big-endian payload
// length) and carries one write, "<RFC3339Nano> <text>". A write without a
// trailing newline is a partial line continued by the next frame of the same
// stream. With a terminal the stream is plain lines with the same prefix.
type dockerLines struct {
	reader  *bufio.Reader
	tty     bool
	offset  int64
	scanned *int64
	max     int
	header  [8]byte
	frames  *bufio.Reader // reused for the payload of each frame
}

func newDockerLines(r io.Reader, tty bool, max int, scanned *int64) *dockerLines {
	return &dockerLines{reader: bufio.NewReaderSize(r, 64<<10), tty: tty, max: max, scanned: scanned, frames: bufio.NewReaderSize(nil, 4096)}
}

func (d *dockerLines) position() int64 { return d.offset }

func (d *dockerLines) count(n int64) {
	d.offset += n
	*d.scanned += n
}

func (d *dockerLines) next() (rawLine, error) {
	line := rawLine{offset: d.offset, stamped: true}
	var text []byte
	var length int64
	first := true
	for {
		stream, payload, err := d.frame()
		if err != nil {
			if err == io.EOF && !first {
				break // a partial line at the end of the stream
			}
			return line, err
		}
		stamp, ended, err := d.payload(payload, &text, &length)
		if err != nil {
			return line, err
		}
		if first {
			if line.time, err = time.Parse(time.RFC3339Nano, stamp); err != nil {
				return line, fmt.Errorf("docker log line without a timestamp: %q", stamp)
			}
			line.stream, first = stream, false
		}
		if ended {
			break
		}
	}
	line.truncated = length > int64(d.max)
	text = trimEOL(text)
	line.text = string(text[:min(len(text), d.max)])
	return line, nil
}

// frame returns the stream name and the payload reader of the next write.
func (d *dockerLines) frame() (string, *bufio.Reader, error) {
	if d.tty {
		if _, err := d.reader.Peek(1); err != nil {
			return "", nil, err
		}
		return "stdout", d.reader, nil
	}
	if _, err := io.ReadFull(d.reader, d.header[:]); err != nil {
		if err == io.ErrUnexpectedEOF {
			err = errors.New("docker log stream ended inside a frame header")
		}
		return "", nil, err
	}
	d.count(8)
	stream := "stdout"
	if d.header[0] == 2 {
		stream = "stderr"
	}
	size := int64(binary.BigEndian.Uint32(d.header[4:]))
	d.frames.Reset(io.LimitReader(d.reader, size))
	return stream, d.frames, nil
}

// payload reads one write: the timestamp up to the first space, then the text
// up to and including a newline, keeping at most max bytes in text. ended
// reports that the write ended with a newline.
func (d *dockerLines) payload(r *bufio.Reader, text *[]byte, length *int64) (string, bool, error) {
	stamp, err := r.ReadString(' ')
	d.count(int64(len(stamp)))
	if err != nil {
		if err == io.EOF && d.tty && len(stamp) > 0 {
			err = io.ErrUnexpectedEOF
		}
		return "", false, err
	}
	stamp = strings.TrimSuffix(stamp, " ")
	for {
		part, err := r.ReadSlice('\n')
		d.count(int64(len(part)))
		*length += int64(len(part))
		if keep := d.max + 2 - len(*text); keep > 0 {
			*text = append(*text, part[:min(len(part), keep)]...)
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		ended := len(part) > 0 && part[len(part)-1] == '\n'
		if ended {
			*length--
			if len(part) > 1 && part[len(part)-2] == '\r' {
				*length--
			}
		}
		if err == io.EOF {
			if d.tty {
				return stamp, true, nil
			}
			return stamp, ended, nil
		}
		if err != nil {
			return "", false, err
		}
		if !d.tty {
			// The rest of the frame, if any, belongs to the same write.
			if _, peekErr := r.Peek(1); peekErr == nil {
				continue
			}
		}
		return stamp, ended, nil
	}
}
