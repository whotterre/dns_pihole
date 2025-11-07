# DNS Pi Hole 

I decided to try a challenge that doesn't involve web stuff today.
I intend this to be a tiny DNS UDP listener written in Go intended as a lightweight helper/proxy to block ads.
This repository contains a minimal example that binds to a local UDP port and reads incoming packets (for now).
## Features

- Minimal UDP DNS listener (example)
- Easy to build with Go
- Intended for local development and experimentation

## Requirements

- Go 1.20+ (Go 1.25+ is also supported)

## Build

Run the following in PowerShell or a POSIX shell inside the project directory:

```powershell
go mod tidy
go build -o dns_pihole .
```

## Run

You can run the built binary or use `go run` while iterating on the code:

```powershell
# Run the binary
.\dns_pihole.exe

# Or run directly with Go while developing
go run main.go
```

By default the example binds to `127.0.0.1:5354`. Change the address/port in `main.go` if you need a different bind.

## Helpful References
- [The structure of DNS - RFC 1035 Reference](https://datatracker.ietf.org/doc/html/rfc1035)
- [DNS Pihole](https://en.wikipedia.org/wiki/Pi-hole)

# Credits 
The domains in the blocklist are from [here](https://github.com/hagezi/dns-blocklists)