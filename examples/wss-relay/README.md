# Optional authenticated WSS relay

This companion runs on an operator-owned Linux host. It gives the Worker a
WebSocket-to-TCP egress path through that host. It is optional, carries TCP only,
and does not provide a WireGuard/OpenVPN server or independent user accounting.
Keep user authentication, quota checks and traffic accounting in the Worker.

The example includes no deployment credentials, addresses or routing rules from
any existing installation. It does not alter the repository's license.

## Protocol and limits

Connect with TLS to `wss://relay.example.invalid/tcp-relay` using exactly one of
each header:

```text
Authorization: Bearer <high-entropy-relay-token>
X-Exit-Host: destination.example.invalid
X-Exit-Port: 443
```

- The bearer token must contain 32–256 URL-safe ASCII characters (`A-Z`, `a-z`,
  `0-9`, `_`, `-`). Generate at least 32 random bytes; do not use a human password.
  Configure the token in the account's protected upstream URI as
  `wss://TOKEN@relay.example.invalid/tcp-relay`. The Worker extracts the token,
  removes it from the outbound URL, and sends it in the Authorization header.
  Treat the complete configuration URI as a credential; it is not a subscription
  link. The relay reads only its SHA-256 digest from `EXIT_TOKEN_SHA256`;
  comparison is constant time. If rotating it, update both sides together.
- Only public unicast IPv4 destinations on TCP ports 80 and 443 are allowed.
  DNS resolves once per connection; mixed public/private answers fail closed.
  The validated numeric address is used for the connection to prevent a second
  DNS lookup from changing the destination. IPv6 and UDP are unsupported.
- The backend binds each outgoing socket to `EXIT_SOURCE_IPV4`, which must be
  assigned to the host. There is no fallback to another source if binding fails.
  It also blocks that address. Add all other local, NAT/public and prohibited
  addresses to the comma-separated `EXIT_BLOCKED_IPV4` list. Apply an outbound
  firewall as a further boundary appropriate to the host's environment.
- HTTP `101` is returned only after destination validation and TCP connection
  succeed. Unauthorized requests return `401`; disallowed destinations `403`;
  connection failures `502`; exhausted admission capacity `503`.
- Client data is binary, in nonempty frames of at most 64 KiB. Text data is
  rejected. Each successful TCP drain emits cumulative text `ack:<byte-count>`.
  ACKs mean bytes reached the local TCP transport, not that the remote
  application accepted them. Clients must use ACKs to bound in-flight data.
- Capacity includes connecting tunnels: 64 connections, 8-second connect
  timeout, 15-second stalled-I/O timeout and 180-second idle timeout. TCP write
  buffers and read chunks are bounded at 64 KiB; the WebSocket message limit is
  also 64 KiB. Backpressure is preserved by awaiting socket drain and sends.
  There is no unbounded application data queue. Library and kernel buffers still
  consume memory; size service memory limits for real concurrency and traffic.
- Closing either side cancels the other pumps. Admission slots are released even
  when TCP cleanup is cancelled. Shutdown stops admission and closes active
  tunnels. Compression, credential/destination logging, token query parameters
  and unauthenticated health endpoints are deliberately absent.

## Host setup

Python 3.11 or newer is required. The pinned `aiohttp` version in
`requirements.txt` was used for the offline suite on Python 3.12.10. This is a
tested dependency pin, not a claim that future security updates are unnecessary.

1. Create a dedicated unprivileged service account named `zeus-relay`. Copy this
   directory to `/opt/zeus-wss-relay`, owned by the administrator and readable by
   the service account. Create a virtual environment there and install the
   requirements into it. The service should not own or write its own source.
2. Generate a random URL-safe bearer token in a secure secret-management process.
   Use it in the protected upstream URI described above. The connector does not
   define a separate token environment binding. If the token is already supplied
   in the current process as `RELAY_TOKEN`, this command prints only the hash
   needed by the backend:

   ```sh
   python3 -c 'import hashlib, os; print(hashlib.sha256(os.environ["RELAY_TOKEN"].encode("ascii")).hexdigest())'
   ```

   Do not put the token or configuration URI in shell history, command-line
   arguments, browser navigation, public links or Git. Remove `RELAY_TOKEN` from
   the current process environment after provisioning.
3. Review `relay.env.example`; create `/etc/zeus-wss-relay/relay.env` with the hash,
   the assigned source IPv4 and the blocklist. Make it root-owned and mode `0600`.
   The reserved example addresses and placeholder hash must be replaced.
4. Review the systemd unit before installing it. It assumes the paths above and
   a compatible systemd release. Its application listener is fixed to
   `127.0.0.1:9080`; never expose that cleartext listener publicly.
5. Merge the Caddy example into the host's existing TLS configuration using a
   hostname you control. Validate before reload. Preserve any unrelated routes
   and authentication. The example has no access logging directive; if global
   logging is enabled, ensure Authorization and destination headers are never
   logged. Do not disable TLS certificate verification in the Worker.
6. Add the authenticated upstream URI to the intended account's proxy
   configuration, following [the Worker setup guide](../../docs/optional-transports.md).
   Test a permitted destination and verify that invalid tokens and local/private
   destinations are rejected before directing user traffic through the relay.

There is no automatic installer. The example does not change networking, NAT,
policy routing or an existing host service. The relay must remain authenticated;
never remove its token checks or publish a shared token in subscription links.

## Offline regression tests

From this directory, with dependencies already installed:

```sh
python -m unittest -v test_wss_relay.py
```

Tests use fake DNS and TCP connectors plus loopback-only HTTP/WebSocket/TCP
servers. They make no connection to public destinations. They cover policy,
authentication, DNS rebinding resistance, source-bind failure, admission,
backpressure ACK ordering, both data directions, frame limits, stalled I/O,
shutdown and cancellation during cleanup. They do not validate a real TLS proxy,
the host firewall or production throughput.
