# Observability

## Prometheus metrics

Metrics are opt-in and disabled by default. Enable the loopback-only endpoint:

```yaml
metrics:
  enabled: true
  listen: 127.0.0.1:9090
```

Configuration validation requires an IP-literal loopback address. The metrics
endpoint has no authentication and cannot be exposed on a non-loopback
listener. Scrape it locally or place an authenticated, access-controlled
collector in front of it.

```sh
curl --fail http://127.0.0.1:9090/metrics
```

The endpoint serves only `GET` and `HEAD /metrics`. Listener acquisition is
part of runtime activation: a bind failure rejects startup or reload and
triggers the normal rollback path.

Exported worker metrics use only the validated, configured worker ID as a
label:

- `vpnpool_worker_healthy`
- `vpnpool_worker_draining`
- `vpnpool_worker_state`
- `vpnpool_worker_state_since_timestamp_seconds`
- `vpnpool_worker_last_healthy_timestamp_seconds`
- `vpnpool_worker_active_connections`
- `vpnpool_worker_connections_total`
- `vpnpool_worker_backend_selections_total`
- `vpnpool_worker_bytes_rx_total`
- `vpnpool_worker_bytes_tx_total`
- `vpnpool_worker_openvpn_restarts_total`
- `vpnpool_worker_proxy_restarts_total`
- `vpnpool_worker_healthcheck_successes_total`
- `vpnpool_worker_healthcheck_failures_total`

Dispatcher metrics cover active and total connections, authentication
failures, selections, safe pre-acknowledgement retries, no-worker failures, and
bytes in both directions.

Metrics deliberately omit usernames, session IDs, destination addresses,
profile paths, credentials, and observed public IPs. Counters describe the
current runtime generation and reset after a daemon restart or successful
configuration reload.

## Status

`vpnpoold status` uses the private mode-`0600` control socket and includes the
same counters, worker lifecycle state, availability, transition time, last
healthy time, reason, drain state, and verified public IP. Public IP is useful
for a trusted local operator but is deliberately excluded from Prometheus
labels and samples.

```sh
sudo vpnpoold status --config /etc/vpnpoold/vpnpoold.yaml
```

Useful alerts include:

- `vpnpool_worker_healthy == 0` for any required worker;
- an increasing `vpnpool_worker_healthcheck_failures_total`;
- an increasing OpenVPN or proxy restart counter;
- `vpnpool_dispatcher_no_worker_failures_total` increasing;
- a worker remaining outside `HEALTHY` longer than its expected recovery
  window.
