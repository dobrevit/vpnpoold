package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dobrevit/vpnpoold/internal/proxy/dispatcher"
	"github.com/dobrevit/vpnpoold/internal/worker"
)

func TestMetricsHandlerExposesBoundedOperationalState(t *testing.T) {
	stateSince := time.Unix(100, 0)
	lastHealthy := time.Unix(110, 0)
	server, err := NewServer(
		func() []worker.Snapshot {
			return []worker.Snapshot{{
				ID: "worker-1", State: worker.StateHealthy,
				StateSince: stateSince, LastHealthyAt: lastHealthy,
				Available: true, ActiveConnections: 2,
				ConnectionsTotal: 3, BackendSelections: 4,
				BytesFromClients: 5, BytesToClients: 6,
				OpenVPNRestarts: 7, ProxyRestarts: 8,
				HealthCheckSuccesses: 9, HealthCheckFailures: 10,
				Evidence: worker.HealthEvidence{
					ExpectedIPConfigured: true, ExpectedIPChecked: true,
					ExpectedIPMatches: true, UniquenessEnforced: true,
					UniquenessChecked: true, PublicIPUnique: true,
				},
			}}
		},
		func() dispatcher.Stats {
			return dispatcher.Stats{ConnectionsTotal: 11, BackendSelections: 12}
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	response := httptest.NewRecorder()
	server.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	body := response.Body.String()
	for _, expected := range []string{
		`vpnpool_worker_healthy{worker="worker-1"} 1`,
		`vpnpool_worker_expected_ip_verified{worker="worker-1"} 1`,
		`vpnpool_worker_public_ip_unique{worker="worker-1"} 1`,
		`vpnpool_worker_state{worker="worker-1",state="HEALTHY"} 1`,
		`vpnpool_worker_active_connections{worker="worker-1"} 2`,
		`vpnpool_worker_openvpn_restarts_total{worker="worker-1"} 7`,
		`vpnpool_worker_healthcheck_failures_total{worker="worker-1"} 10`,
		`vpnpool_dispatcher_connections_total 11`,
		`vpnpool_dispatcher_selection_total 12`,
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("metrics body does not contain %q:\n%s", expected, body)
		}
	}
	if strings.Contains(body, `public_ip="`) {
		t.Fatalf("metrics unexpectedly expose public-IP labels:\n%s", body)
	}
}

func TestMetricsHandlerRejectsOtherPathsAndMethods(t *testing.T) {
	server, err := NewServer(
		func() []worker.Snapshot { return nil },
		func() dispatcher.Stats { return dispatcher.Stats{} },
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		method string
		path   string
		status int
	}{
		{http.MethodGet, "/healthz", http.StatusNotFound},
		{http.MethodPost, "/metrics", http.StatusMethodNotAllowed},
		{http.MethodHead, "/metrics", http.StatusOK},
	} {
		request := httptest.NewRequest(test.method, test.path, nil)
		response := httptest.NewRecorder()
		server.handler.ServeHTTP(response, request)
		if response.Code != test.status {
			t.Fatalf("%s %s status = %d, want %d",
				test.method, test.path, response.Code, test.status)
		}
	}
}

func TestQuoteLabelUsesPrometheusEscapesExactlyOnce(t *testing.T) {
	value := "quote=\" slash=\\ newline=\n"
	want := `"quote=\" slash=\\ newline=\n"`
	if got := quoteLabel(value); got != want {
		t.Fatalf("quoteLabel() = %q, want %q", got, want)
	}
}
