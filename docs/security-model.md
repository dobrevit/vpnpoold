# Security model

The primary threat is accidental or malicious escape of worker traffic through
the host's ordinary WAN route when a VPN, route, proxy, or health check fails.

Implemented foundations:

- public proxy configuration defaults to loopback;
- non-loopback proxy listeners require authentication or an explicit insecure
  override;
- worker selection is fail-closed and requires complete egress evidence;
- namespaces receive default-drop input, output, and forward chains;
- strict firewall mode removes tunnel and proxy data-plane allowances;
- OpenVPN recovery is limited to validated, resolved IP/protocol/port tuples;
- external commands use direct argument vectors through `exec.CommandContext`;
- identifiers used in commands or nftables input are syntactically validated;
- process errors do not echo arguments or subprocess output;
- original `.ovpn` files are read without modification and inline secret blocks
  are excluded from endpoint inspection; profiles must be private, non-symlink
  files in a non-writable profile directory;
- executable script/plugin/alternate-route/file-logging directives in source
  profiles are rejected, and OpenVPN runs with script security level 1;
- derived profiles are stored in a private runtime generation, replace remote
  hostnames with host-resolved literals, inject only the path of a validated
  private credentials file, enforce complete IPv4 `def1` routes, and retain the
  original profile directory as OpenVPN's working directory for relative
  certificate/auth paths;
- namespace resolver files contain only validated IPv4 addresses, are removed
  idempotently, and cannot send queries before the tunnel is active;
- optional upstream HTTP proxy addresses must be explicit IPv4 literals;
  CONNECT handshakes are bounded and support no proxy credentials;
- the namespace worker supports only SOCKS5 TCP `CONNECT` and is bound to an
  explicit veth address;
- public-IP checks are made through the worker SOCKS path and reject expected-IP
  mismatch, host-WAN leakage, and duplicate exits;
- configuration replacement prepares a complete candidate generation before
  cutover and restores the retained generation if activation fails;
- dispatcher credentials contain bcrypt hashes only and require private file
  permissions and a non-writable parent directory;
- management credentials are loaded only when requested from private,
  replacement-resistant files; configured challenge helpers use bounded JSON,
  output and execution time, a minimal environment, and secret-safe errors;
- dispatcher selection rechecks worker health atomically before acquisition;
- retry is limited to the period before CONNECT success is sent to the client;
- established sessions stay pinned, and can be closed by worker ID on failure.
- the composed runtime installs shared host rules before listening, cleans only
  deterministic configured stale resources, and removes its host table after
  all workers stop.
- a host-network-namespace singleton lock prevents concurrent daemon instances
  from replacing or removing each other's global firewall table;
- the local control socket is inside a private runtime directory, is mode
  `0600`, verifies same-UID peer credentials, accepts bounded requests, exposes no
  credentials or profile content, and limits mutation to validated per-worker
  enable, disable, drain, undrain, fail-closed restart, and transactional
  reload actions.
- Prometheus metrics are opt-in, restricted to an IP-literal loopback
  listener, and use only configured worker IDs as labels; usernames,
  destinations, credentials, profile paths, and public IPs are excluded.
- reload candidates are fully prepared before cutover, and the exact prior
  runtime is retained until activation succeeds.

The namespace and strict kill-switch integration test and the four-worker
failure/recovery acceptance matrix pass in the disposable Ubuntu 24.04 libvirt
guests. A separate real-provider test has exercised the same tunnel, proxy, and
public-IP path. These results do not replace validation on the operator's
target kernel, systemd, OpenVPN build, VPN provider, and network.
