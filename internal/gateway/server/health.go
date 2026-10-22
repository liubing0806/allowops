package server

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// An unavailable output store degrades output persistence without blocking jobs.
const degradedReadyStatus = http.StatusOK

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	result := struct {
		Status     string `json:"status"`
		Degraded   bool   `json:"degraded"`
		PostgreSQL string `json:"postgresql,omitempty"`
		Output     string `json:"output,omitempty"`
	}{Status: "alive"}
	status := http.StatusOK
	if r.URL.Path == "/health/ready" {
		result.Status = "ready"
		result.PostgreSQL = "ok"
		dbCtx, cancelDB := context.WithTimeout(r.Context(), 2*time.Second)
		err := s.Agent.Store.CheckSchema(dbCtx)
		cancelDB()
		if err != nil {
			status = http.StatusServiceUnavailable
			result.Status = "unavailable"
			result.PostgreSQL = "unavailable"
		}
		if s.Agent.ListenerFailed() {
			status = http.StatusServiceUnavailable
			result.Status = "unavailable"
		}
		result.Output = "unavailable"
		outputCtx, cancelOutput := context.WithTimeout(r.Context(), 2*time.Second)
		if s.Output != nil && s.Output.Check(outputCtx) == nil {
			result.Output = "ok"
		}
		cancelOutput()
		result.Degraded = result.Output != "ok"
		if status == http.StatusOK && result.Degraded {
			status = degradedReadyStatus
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(result)
}
