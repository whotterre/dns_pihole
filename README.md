# DNS PiHole

A lightweight DNS proxy and UDP listener written in Go, designed to intercept queries and filter out advertisements, tracking metrics, and unwanted telemetry. 

Unlike traditional static blockers, this engine utilizes a session-aware runtime ledger that maps transient client network IPs to long-lived browser identities dynamically.

## Features

- **Concurrent Core Engines:** Low-latency UDP DNS core running alongside a management HTTP dashboard server.
- **Session-Aware Filtering:** Transparent browser-cookie generation (`user_id`) utilizing long-lived Unix timestamps.
- **Dynamic Time Leases:** Ephemeral in-memory routing ledger (`leaseMap`) that binds temporary DHCP client IPs to persistent rule profiles with rolling 3-hour expiration windows.
- **Automated Memory Janitor:** Thread-safe background worker running on strict ticker intervals to evict stale network mappings without memory leaks.
- **Flexible Rules Architecture:** Supports isolated blocklist profile evaluation falling back seamlessly to an aggregate upstream HaGeZi rule structure.

## Requirements

- Go 1.20+ (Go 1.25+ highly recommended)

## Build

Compile the structural binary directly inside your workspace root directory:

```bash
go mod tidy
go build -o dns_engine .

```

*Note: Compiling the binary locally ensures that the relative runtime folder targets (`./lists/`) are consistently mapped to your actual project root rather than sandboxed environment temp directories.*

## Run

Execute the compiled binary from your terminal workspace root:

```bash
# Run the application binary natively
./dns_engine

```

* **DNS Core Engine:** Binds universally to intercept network UDP packets on port `53`.
* **Management Web Dashboard:** Hosts incoming management traffic on port `8000`.
## Changelog

All notable changes to this project are documented below in accordance with Semantic Versioning standards.

### [1.3.0] - 2026-07-12

#### Added
- **Vite React Dashboard:** Built an interactive frontend dashboard UI for live metrics, featuring premium glassmorphism aesthetics, dynamic polling, and real-time backend metric visualization.
- **Robust Analytics API:** Built the `/stats` HTTP endpoint inside `handlers.go` and instrumented `sync/atomic` counters across the core UDP listener to securely stream live metrics (Total Queries, Blocked Queries, Allowed Queries, Uptime) with CORS enabled.
- **Wildcard Subdomain Blocking:** Re-engineered the core `IsBlocked` rules engine to natively support hierarchical parent domain traversal, allowing base domain lists (e.g. `example.com`) to seamlessly intercept subdomain variants (e.g. `www.example.com`).

#### Changed
- **Concurrent Core Refactoring:** Overhauled the main DNS listening loop to rapidly process multiple incoming UDP queries asynchronously via independent goroutines, completely resolving bottlenecks.
- **Dynamic Hot-Loading:** Updated `CreateBlacklist` API endpoint routines so that newly uploaded blocklists instantly merge into the operational runtime map structure without server reboots.
- **Bootloader Expansion:** Rebuilt the `main.go` startup sequence to dynamically iterate and load every text list located within the `./lists/` directory instead of hardcoding a single configuration.

#### Fixed
- **Upstream Connection Freezes:** Added missing `SetReadDeadline` configurations on all upstream UDP DNS connection dialing attempts so that silently dropped internet packets do not cause the system threads to hang indefinitely.
- **Blocklist Parsing Anomaly:** Patched a critical file scanner string validation bug within `LoadBlocklist` that mistakenly filtered out valid domains during boot instantiation.

### [1.2.0] - 2026-07-11

#### Added
- **HTTP Dashboard Engine:** Introduced a concurrent HTTP server hosted on port `8000` via standard library `net/http` multiplexing.
- **Session-Aware Upload Handler:** Created the `POST /blocklist/upload` endpoint using long-lived browser cookies (`user_id`) bound to persistent Unix timestamp identities.
- **In-Memory Time Ledger:** Added a thread-safe `leaseMap` state mechanism protected by `sync.RWMutex` to map real-time DHCP client IPs to user blocklist profiles.
- **Background Janitor Thread:** Deployed an automated, concurrent memory cleanup worker running on high-precision `time.Ticker` intervals to cleanly evict stale lease records.

#### Changed
- **Router Configuration:** Migrated route registrations from `app.Handle` interfaces to plain function adapters via `app.HandleFunc` to support raw HTTP handlers.
- **IP Extraction Logic:** Integrated `net.SplitHostPort` parsing inside the web pipeline to reliably isolate client network traffic from shifting TCP port values.
- **File System Scoping:** Hardened data persistence targets to relative workspaces (`./lists/`) to prevent environment sandboxing bugs when launching applications.

#### Fixed
- Fixed a critical variable shadowing bug where short-declaration token assignments (`:=`) accidentally isolated the system's runtime user identities inside block scopes.
- Resolved a data race vulnerability inside the garbage collector worker by wrapping map iterations in comprehensive system write-locks.

---

### [1.1.0] - 2026-06-15
#### Added
- Implemented core domain filtering mechanism capable of parsing upstream file lists.
- Added localized thread safe caching for high frequency lookup queries.

### [1.0.0] - 2026-05-10
#### Added
- Initial release containing the base low-latency UDP socket listener binding to network port `53`.
- Added standard RFC 1035 binary packet parsing skeletons.

### API Specifications
#### Upload Blocklist Profiles

* **Endpoint:** `POST /blocklist/upload`
* **Headers:** Expects incoming session validation via the `user_id` cookie. (Automatically generated and injected on first connection).
* **Payload Format:**
```json
{
  "entries": [
    "analytics.doubleclick.net",
    "telemetry.bad-actor.io"
  ]
}

```


## Helpful References

* [RFC 1035 - Domain Names Implementation & Specification](https://datatracker.ietf.org/doc/html/rfc1035)
* [Conventional Commits - Semantic Commit Specifications](https://www.conventionalcommits.org/)

## Credits

* Fundamental upstream base blocklists provided courtesy of the upstream [HaGeZi DNS Blocklists Repository](https://github.com/hagezi/dns-blocklists).
