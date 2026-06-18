# DNS CLI Demo Client

This is a simple command-line interface (CLI) tool designed to demonstrate the usage of the underlying DNS lookup library. It parses command-line arguments, executes synchronous DNS queries, and prints the formatted resource records.

## How to Run

Compile everything from the root directory of the project using `make`, then execute the binary generated inside this folder:

```bash
./demo/demo <domain_name> <query_type>
```

### Examples

**Resolve IPv4 addresses:**
```bash
./demo/demo google.com A
```

**Resolve Mail Servers:**
```bash
./demo/demo exchange.com MX
```

## Features Demonstrated in Code

* **Metadata Printing**: Displays wire telemetry (`bytes_sent`, `bytes_received`) along with full 12-bit Extended EDNS RCODE status parameters.
* **Sections Dissection**: Displays `Answers`, `Authorities`, and `Additionals` arrays natively.
