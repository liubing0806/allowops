// Package webhook delivers approval notifications over HTTPS.
package webhook

import (
	"bytes"
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/liubing0806/allowops/plugin"
	"github.com/liubing0806/allowops/plugin/notifier"
	"golang.org/x/net/http/httpguts"
)

func init() { plugin.Register(Module{}) }

type Module struct {
	URL             string               `yaml:"url"`
	Format          string               `yaml:"format"`
	Signing         string               `yaml:"signing"`
	SecretRef       string               `yaml:"secret_ref"`
	TokenQueryParam string               `yaml:"token_query_param"`
	TokenRef        string               `yaml:"token_ref"`
	Events          []notifier.EventType `yaml:"events"`
	Headers         map[string]string    `yaml:"headers"`

	endpoint *url.URL
	host     plugin.Host
}

func (Module) Module() plugin.ModuleInfo {
	return plugin.ModuleInfo{ID: "notifier.webhook", New: func() plugin.Module { return new(Module) }}
}

func (m *Module) Validate() error {
	if err := m.validateURL(); err != nil {
		return err
	}
	switch m.Format {
	case "", "json", "slack", "dingtalk", "feishu", "wecom":
	default:
		return errors.New("notifier webhook: invalid format")
	}
	switch cmp.Or(m.Signing, "none") {
	case "none":
		if m.SecretRef != "" {
			return errors.New("notifier webhook: secret_ref requires signing")
		}
	case "hmac_sha256", "bearer", "dingtalk_timestamp", "feishu_timestamp":
		if strings.TrimSpace(m.SecretRef) == "" {
			return errors.New("notifier webhook: signing requires secret_ref")
		}
	default:
		return errors.New("notifier webhook: invalid signing mode")
	}
	if m.Signing == "feishu_timestamp" && m.Format != "feishu" {
		return errors.New("notifier webhook: feishu_timestamp requires feishu format")
	}
	if (m.TokenQueryParam == "") != (m.TokenRef == "") || m.TokenRef != "" && strings.TrimSpace(m.TokenRef) == "" ||
		(m.TokenQueryParam != "" && m.TokenQueryParam != "access_token" && m.TokenQueryParam != "key") {
		return errors.New("notifier webhook: invalid token query configuration")
	}
	seen := make(map[notifier.EventType]bool)
	for _, event := range m.Events {
		switch event {
		case notifier.EventApprovalRequested, notifier.EventApprovalApproved, notifier.EventApprovalRejected,
			notifier.EventApprovalExpired, notifier.EventApprovalCancelled:
		default:
			return errors.New("notifier webhook: invalid event type")
		}
		if seen[event] {
			return errors.New("notifier webhook: duplicate event type")
		}
		seen[event] = true
	}
	for name, value := range m.Headers {
		switch strings.ToLower(name) {
		case "authorization", "host", "cookie", "content-type", "content-length":
			return errors.New("notifier webhook: reserved header")
		}
		if !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(value) {
			return errors.New("notifier webhook: invalid header")
		}
	}
	return nil
}

func (m *Module) validateURL() error {
	invalid := errors.New("notifier webhook: url must be an absolute HTTPS URL")
	u, err := url.Parse(m.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		strings.ContainsAny(m.URL, "#\\") || strings.IndexFunc(m.URL, unicode.IsSpace) >= 0 {
		return invalid
	}
	if port := u.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return invalid
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return invalid
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return invalid
	}
	if query.Has("access_token") || query.Has("key") {
		return errors.New("notifier webhook: configure query tokens with token_ref")
	}
	return nil
}

func (m *Module) Provision(_ context.Context, h plugin.Host) error {
	if err := m.Validate(); err != nil {
		return err
	}
	m.endpoint, _ = url.Parse(m.URL)
	m.Format = cmp.Or(m.Format, "json")
	m.Signing = cmp.Or(m.Signing, "none")
	if m.Events == nil {
		m.Events = []notifier.EventType{notifier.EventApprovalRequested}
	}
	m.host = h
	return nil
}

var (
	errTransport = errors.New("notifier webhook: transport error")
	errStatus4xx = errors.New("notifier webhook: status 4xx")
	errStatus5xx = errors.New("notifier webhook: status 5xx")
	errRejected  = errors.New("notifier webhook: upstream rejected")
)

const responseLimit = 4 << 10

func (m *Module) Send(ctx context.Context, event notifier.Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !slices.Contains(m.Events, event.Type) {
		return nil
	}
	var secret []byte
	if m.SecretRef != "" {
		value, err := m.host.Credential(m.SecretRef)
		if err != nil || len(value) == 0 {
			return errTransport
		}
		secret = value
	}
	endpoint := *m.endpoint
	query := endpoint.Query()
	if m.TokenRef != "" {
		token, err := m.host.Credential(m.TokenRef)
		if err != nil || len(token) == 0 {
			return errTransport
		}
		query.Set(m.TokenQueryParam, string(token))
	}
	if m.Signing == "dingtalk_timestamp" {
		timestamp := strconv.FormatInt(m.host.Now().UnixMilli(), 10)
		query.Set("timestamp", timestamp)
		query.Set("sign", base64.StdEncoding.EncodeToString(signature(secret, []byte(timestamp+"\n"+string(secret)))))
	}
	if m.TokenRef != "" || m.Signing == "dingtalk_timestamp" {
		endpoint.RawQuery = query.Encode()
	}
	body, err := json.Marshal(m.payload(event, secret))
	if err != nil {
		return errTransport
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return errTransport
	}
	for name, value := range m.Headers {
		req.Header.Set(name, value)
	}
	req.Header.Set("Content-Type", "application/json")
	switch m.Signing {
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+string(secret))
	case "hmac_sha256":
		timestamp := strconv.FormatInt(m.host.Now().Unix(), 10)
		req.Header.Set("X-Allowops-Event", string(event.Type))
		req.Header.Set("X-Allowops-Delivery", event.EventID)
		req.Header.Set("X-Allowops-Timestamp", timestamp)
		req.Header.Set("X-Allowops-Signature-256", "sha256="+hex.EncodeToString(signature(secret, append([]byte(timestamp+"."), body...))))
	}
	response, err := m.host.HTTPClient().Do(req)
	if err != nil {
		return errTransport
	}
	defer response.Body.Close()
	switch response.StatusCode / 100 {
	case 2:
	case 4:
		return errStatus4xx
	case 5:
		return errStatus5xx
	default:
		return errRejected
	}
	if m.Format == "dingtalk" || m.Format == "feishu" || m.Format == "wecom" {
		body, err := io.ReadAll(io.LimitReader(response.Body, responseLimit))
		var result *struct {
			ErrCode int `json:"errcode"`
			Code    int `json:"code"`
		}
		if err != nil || len(body) == responseLimit || json.Unmarshal(body, &result) != nil ||
			result == nil || result.ErrCode != 0 || result.Code != 0 {
			return errRejected
		}
	}
	return nil
}

func (m *Module) payload(event notifier.Event, secret []byte) any {
	if m.Format == "json" {
		return event
	}
	title := fmt.Sprintf("Approval %s (%s)", event.ApprovalID, event.Status)
	text := fmt.Sprintf("%s\nJob: %s\nAction: %s\nRisk: %s\nRequester: %s\nTargets: %d\nApprovals: %d/%d",
		title, event.JobID, event.Action, event.Risk, event.Requester, event.TargetCount, event.ApprovedCount, event.MinApprovals)
	if event.ConsoleURL != "" {
		text += "\n" + event.ConsoleURL
	}
	switch m.Format {
	case "slack":
		return map[string]string{"text": text}
	case "dingtalk":
		return map[string]any{"msgtype": "markdown", "markdown": map[string]string{"title": title, "text": text}}
	case "feishu":
		payload := map[string]any{"msg_type": "text", "content": map[string]string{"text": text}}
		if m.Signing == "feishu_timestamp" {
			timestamp := strconv.FormatInt(m.host.Now().Unix(), 10)
			payload["timestamp"] = timestamp
			payload["sign"] = base64.StdEncoding.EncodeToString(signature([]byte(timestamp+"\n"+string(secret)), nil))
		}
		return payload
	case "wecom":
		return map[string]any{"msgtype": "markdown", "markdown": map[string]string{"content": text}}
	}
	return event
}

func signature(secret, body []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return mac.Sum(nil)
}

var _ notifier.Sender = (*Module)(nil)
