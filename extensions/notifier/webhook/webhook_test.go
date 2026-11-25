package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/liubing0806/allowops/plugin"
	"github.com/liubing0806/allowops/plugin/notifier"
	"github.com/liubing0806/allowops/plugin/plugintest"
)

const (
	fixtureSecret = "webhook-fixture-private-signing-secret"
	fixtureToken  = "webhook-fixture-private/+& token"
)

func TestNotifierContract(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	plugintest.RunNotifierContract(t, Module{}, "url: "+server.URL+"\nsigning: bearer\nsecret_ref: signing\ntoken_query_param: key\ntoken_ref: token",
		plugintest.WithHTTPServer(server), plugintest.WithExpectHTTP(),
		plugintest.WithCredential("signing", []byte(fixtureSecret)), plugintest.WithCredential("token", []byte(fixtureToken)))
}

func TestWebhookFormatsAndSignatures(t *testing.T) {
	now := time.Date(2026, time.November, 24, 10, 11, 12, 345000000, time.UTC)
	event := notifier.Event{
		Type: notifier.EventApprovalRequested, EventID: "approval-1:1", At: now.Add(-time.Second),
		ApprovalID: "approval-1", JobID: "job-1", Action: "restart", Risk: "write", Requester: "operator",
		TargetCount: 2, SampleHosts: []string{"node-one", "node-two"}, RequiredApproverRoleSets: [][]string{{"reviewer", "admin"}, {"security"}},
		MinApprovals: 2, ApprovedCount: 1, ExpiresAt: now.Add(time.Hour), ConsoleURL: "https://console.example/approvals/approval-1",
		Actor: "reviewer-one", Status: "pending",
	}
	text := "Approval approval-1 (pending)\nJob: job-1\nAction: restart\nRisk: write\nRequester: operator\nTargets: 2\nApprovals: 1/2\n" + event.ConsoleURL
	seconds, millis := strconv.FormatInt(now.Unix(), 10), strconv.FormatInt(now.UnixMilli(), 10)
	hmac := func(key, message []byte) []byte {
		hash := hmac.New(sha256.New, key)
		hash.Write(message)
		return hash.Sum(nil)
	}
	for _, tc := range []struct {
		name, format, signing, tokenParam string
		payload                           any
	}{
		{name: "JSON HMAC", signing: "hmac_sha256", payload: event},
		{name: "Slack bearer", format: "slack", signing: "bearer", payload: map[string]any{"text": text}},
		{name: "DingTalk signed query", format: "dingtalk", signing: "dingtalk_timestamp", tokenParam: "access_token",
			payload: map[string]any{"msgtype": "markdown", "markdown": map[string]any{"title": "Approval approval-1 (pending)", "text": text}}},
		{name: "Feishu signed body", format: "feishu", signing: "feishu_timestamp",
			payload: map[string]any{"msg_type": "text", "content": map[string]any{"text": text}, "timestamp": seconds,
				"sign": base64.StdEncoding.EncodeToString(hmac([]byte(seconds+"\n"+fixtureSecret), nil))}},
		{name: "WeCom query token", format: "wecom", tokenParam: "key",
			payload: map[string]any{"msgtype": "markdown", "markdown": map[string]any{"content": text}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			type delivery struct {
				method string
				header http.Header
				query  url.Values
				body   []byte
			}
			seen := make(chan delivery, 1)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error("could not read webhook request")
				}
				seen <- delivery{r.Method, r.Header.Clone(), r.URL.Query(), body}
				io.WriteString(w, `{"errcode":0,"code":0}`)
			}))
			defer server.Close()
			m := Module{URL: server.URL + "/delivery?source=gateway", Format: tc.format, Signing: tc.signing,
				TokenQueryParam: tc.tokenParam, Headers: map[string]string{"X-Static": "gateway"}}
			if tc.signing != "" {
				m.SecretRef = "signing"
			}
			if tc.tokenParam != "" {
				m.TokenRef = "token"
			}
			host := plugintest.NewHost(t, plugintest.WithHTTPServer(server), plugintest.WithNow(now),
				plugintest.WithCredential("signing", []byte(fixtureSecret)), plugintest.WithCredential("token", []byte(fixtureToken)))
			if err := m.Provision(t.Context(), host); err != nil {
				t.Fatal(err)
			}
			if err := m.Send(t.Context(), event); err != nil {
				t.Fatal(err)
			}
			var got delivery
			select {
			case got = <-seen:
			default:
				t.Fatal("webhook did not receive the event")
			}
			if got.method != http.MethodPost || got.header.Get("Content-Type") != "application/json" || got.header.Get("X-Static") != "gateway" {
				t.Error("incorrect method or static headers")
			}
			wantQuery := url.Values{"source": {"gateway"}}
			if tc.tokenParam != "" {
				wantQuery.Set(tc.tokenParam, fixtureToken)
			}
			switch tc.signing {
			case "hmac_sha256":
				want := "sha256=" + hex.EncodeToString(hmac([]byte(fixtureSecret), append([]byte(seconds+"."), got.body...)))
				if got.header.Get("X-Allowops-Signature-256") != want || got.header.Get("X-Allowops-Timestamp") != seconds ||
					got.header.Get("X-Allowops-Event") != string(event.Type) || got.header.Get("X-Allowops-Delivery") != event.EventID {
					t.Error("incorrect HMAC signature or delivery headers")
				}
			case "bearer":
				if got.header.Get("Authorization") != "Bearer "+fixtureSecret {
					t.Error("incorrect bearer authorization")
				}
			case "dingtalk_timestamp":
				wantQuery.Set("timestamp", millis)
				wantQuery.Set("sign", base64.StdEncoding.EncodeToString(hmac([]byte(fixtureSecret), []byte(millis+"\n"+fixtureSecret))))
			}
			if !reflect.DeepEqual(got.query, wantQuery) {
				t.Error("incorrect signed query or token injection")
			}
			wantBody, err := json.Marshal(tc.payload)
			if err != nil {
				t.Fatal(err)
			}
			var actual, expected any
			if json.Unmarshal(got.body, &actual) != nil || json.Unmarshal(wantBody, &expected) != nil || !reflect.DeepEqual(actual, expected) {
				t.Error("wire payload differs from expected schema or signed content")
			}
		})
	}
}

type loggingHost struct {
	plugin.Host
	logger *slog.Logger
}

func (h loggingHost) Logger() *slog.Logger { return h.logger }

func TestWebhookSafeFailures(t *testing.T) {
	const privatePath = "/sensitive-webhook-path"
	const privateBody = "opaque-upstream-response"
	for _, tc := range []struct {
		name, format, body string
		status             int
		want               error
	}{
		{name: "transport", format: "wecom", want: errTransport},
		{name: "rate limited", status: http.StatusTooManyRequests, body: privateBody, want: errStatus4xx},
		{name: "server error", status: http.StatusInternalServerError, body: fixtureSecret + privateBody, want: errStatus5xx},
		{name: "redirect response", status: http.StatusFound, body: privateBody, want: errRejected},
		{name: "DingTalk error", format: "dingtalk", status: 200, body: `{"errcode":1,"message":"` + privateBody + `"}`, want: errRejected},
		{name: "Feishu error", format: "feishu", status: 200, body: `{"code":2,"message":"` + privateBody + `"}`, want: errRejected},
		{name: "WeCom error", format: "wecom", status: 200, body: `{"errcode":3}`, want: errRejected},
		{name: "malformed JSON", format: "wecom", status: 200, body: privateBody, want: errRejected},
		{name: "oversized JSON", format: "wecom", status: 200, body: `{"response":"` + strings.Repeat("a", responseLimit) + `"}`, want: errRejected},
		{name: "codes absent", format: "wecom", status: 200, body: `{}`},
		{name: "Slack plain text", format: "slack", status: 200, body: "ok"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			defer server.Close()
			if tc.status == 0 {
				server.Close()
			}
			var logs bytes.Buffer
			host := loggingHost{Host: plugintest.NewHost(t, plugintest.WithHTTPServer(server),
				plugintest.WithCredential("signing", []byte(fixtureSecret)), plugintest.WithCredential("token", []byte(fixtureToken))),
				logger: slog.New(slog.NewTextHandler(&logs, nil))}
			m := Module{URL: server.URL + privatePath, Format: tc.format, Signing: "bearer", SecretRef: "signing", TokenQueryParam: "key", TokenRef: "token"}
			if err := m.Provision(t.Context(), host); err != nil {
				t.Fatal(err)
			}
			got := m.Send(t.Context(), notifier.Event{Type: notifier.EventApprovalRequested})
			if got != tc.want {
				t.Error("wrong fixed webhook error category")
			}
			output := logs.String()
			if got != nil {
				output += got.Error()
			}
			for _, private := range []string{fixtureSecret, fixtureToken, url.QueryEscape(fixtureToken), privatePath, privateBody, server.URL} {
				if strings.Contains(output, private) {
					t.Error("webhook exposed private request or response data")
				}
			}
		})
	}
}

func TestWebhookEventFilter(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	host := plugintest.NewHost(t, plugintest.WithHTTPServer(server))
	for _, tc := range []struct {
		configured []notifier.EventType
		want       int32
	}{
		{nil, 1},
		{[]notifier.EventType{notifier.EventApprovalApproved, notifier.EventApprovalRejected}, 2},
		{[]notifier.EventType{}, 0},
	} {
		before := requests.Load()
		m := Module{URL: server.URL, Events: tc.configured}
		if err := m.Provision(t.Context(), host); err != nil {
			t.Fatal(err)
		}
		for _, event := range []notifier.EventType{notifier.EventApprovalRequested, notifier.EventApprovalApproved, notifier.EventApprovalRejected,
			notifier.EventApprovalExpired, notifier.EventApprovalCancelled} {
			if err := m.Send(t.Context(), notifier.Event{Type: event}); err != nil {
				t.Fatal(err)
			}
		}
		if got := requests.Load() - before; got != tc.want {
			t.Fatalf("deliveries = %d, want %d", got, tc.want)
		}
	}
}

func TestWebhookValidation(t *testing.T) {
	const endpoint = "https://example.invalid/webhook"
	cases := []Module{
		{}, {URL: "http://example.invalid"}, {URL: "https://user:password@example.invalid"}, {URL: endpoint + "#"}, {URL: endpoint + "?key=secret"},
		{URL: endpoint, Format: "unknown"}, {URL: endpoint, Signing: "unknown"}, {URL: endpoint, Signing: "bearer"},
		{URL: endpoint, SecretRef: "secret"}, {URL: endpoint, TokenRef: "secret"}, {URL: endpoint, TokenQueryParam: "key"},
		{URL: endpoint, TokenQueryParam: "other", TokenRef: "secret"}, {URL: endpoint, Events: []notifier.EventType{"approval.unknown"}},
		{URL: endpoint, Events: []notifier.EventType{notifier.EventApprovalRequested, notifier.EventApprovalRequested}},
		{URL: endpoint, Headers: map[string]string{"X-Test": "head\r\nInjected: ok"}},
		{URL: endpoint, Headers: map[string]string{"X-\nTest": "value"}},
	}
	for _, header := range []string{"aUthorization", "Host", "Cookie", "Content-Type", "Content-Length"} {
		cases = append(cases, Module{URL: endpoint, Headers: map[string]string{header: "anything"}})
	}
	for i, m := range cases {
		if err := m.Provision(context.Background(), nil); err == nil {
			t.Errorf("case %d accepted invalid configuration", i)
		}
	}
}
