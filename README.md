# eMule from ASN

This is a simple API that generates an IP filter/blocklist in eMule format from an Autonomous System Number (ASN) for use with torrent clients, etc. It has caching but never invalidates it. It does not handle ratelimits or errors, will just generate empty list.

Note: This does not grab all IP addresses associated with the ASN.

## Usage

1. Ensure you have Go installed on your system.
2. Clone the repository or copy the provided code into a file.
3. Navigate to the directory containing the Go file.
4. Run the program by executing `go run .` in your terminal, or build a binary with `go build -o emule-to-asn`.
5. Access the `/generate` endpoint with the `asn` parameter set to the desired ASN (e.g., `http://localhost:8080/generate?asn=AS1234`).

## Cache

663 pre-generated lists are available in the `cache/` directory.

## Note

Ensure proper ASN format (e.g., AS1234).
