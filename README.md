# libdigy

A lightweight, dependency-free C library for executing low-level raw DNS queries and parsing binary Resource Records (RRs) on Unix-like environments, with native Extension Mechanisms for DNS (EDNS) support.


## 🐧 Platform Support
* **Supported**: Linux, macOS, and BSD systems.
* **Not Supported**: Windows (compilation will fail explicitly via `#error`).

---

## 📦 Integration & Building

The project features a single universal `Makefile` located in the root directory. The library is built as a static archive (`lib/libdigy.a`) for fast, hassle-free linking.

### 1. Build only the Library
If you want to use the library in your own custom application without compiling the demo, run:
```bash
make lib
```
This produces `lib/libdigy.a`. Link this archive alongside your application and include `-I./lib/include`.

### 2. Build Everything (Library + Demo Client)
To compile both the static library and the diagnostic CLI tool at once, run:
```bash
make
```
This generates the binary executable inside the demo folder (`demo/demo`).

### 3. Running the Demo
Once compiled, you can run the demo client from the root folder:
```bash
./demo/demo example.com A
```

### 4. Clean Up
To remove all compiled libraries and executables, run:
```bash
make clean
```

---

## 🚀 API Usage Guide

### Executing a Query
Define a `DNSLookupQuery` configuration structure and pass it to `dns_lookup()`.

```c
#include <stdio.h>
#include "lib/include/dns-lib.h"

int main() {
    // 1. Configure the query
    DNSLookupQuery query = {
        .target = "example.com",
        .q_type = DNS_A,              // Supported: DNS_A, DNS_NS, DNS_CNAME, DNS_SOA, DNS_MX, DNS_TXT, DNS_AAAA
        .dns_resolver = NULL,         // Set to an IP or Hostname string, or NULL to read /etc/resolv.conf
        .edns_query_size = 512        // Set custom EDNS size if needed ( max : 4096 )
    };

    // 2. Execute the lookup
    DNSLookupResult *result = dns_lookup(query);

    if (result == NULL) {
        printf("DNS Lookup failed. Error code (dns_errno): %d\n", dns_errno);
        return 1;
    }

    // 3. Access Metadata
    printf("Message ID: %d\n", result->message_id);
    printf("Status Code (RCODE): %d\n", result->status_rcode);
    printf("Total Answers found: %d\n", result->answer_count);

    // 4. Clean up memory
    free_result_memory(result);
    return 0;
}
```

---

### 📋 Returned Metadata (`DNSLookupResult`)
The successful execution of `dns_lookup()` returns a pointer to a populated `DNSLookupResult` structure containing:
* **`message_id`**: The 16-bit transaction identifier cross-referenced from the query.
* **`status_rcode`**: The complete 12-bit Extended RCODE (combining the standard DNS header RCODE and the EDNS higher 8 bits).
* **`edns_version`**: The EDNS version returned by the remote nameserver.
* **`edns_server_size`**: The maximum UDP payload size supported by the remote nameserver.
* **`bytes_sent` / `bytes_received`**: The exact wire-format telemetry sizes for network performance tracking.

---
## 🔍 Resolver Initialization and Discovery

The routing layer initializes the target DNS nameservers based on the `.dns_resolver` input:

* **System Discovery (`/etc/resolv.conf`)**: If `.dns_resolver = NULL`, the library opens `/etc/resolv.conf`, extracts lines starting with `nameserver ` (up to a limit of 3), trims trailing whitespaces, and classifies each IP as IPv4 or IPv6.
* **Direct IP Input**: If `.dns_resolver` is a literal IPv4 or IPv6 string, it skips the configuration files and maps it directly into the execution context.
* **Hostname Resolution and Failover**: If `.dns_resolver` is a domain name (e.g., `"ns4.google.com"`), the library executes internal synchronous lookups for both `A` and `AAAA` records. All retrieved IP addresses are populated into a target array. The transport layer loops through every discovered IP sequentially, acting as a failover mechanism if any specific IP address fails to respond.

---

## 🔄 UDP Networking, Retries, and Timeouts

The transport layer uses a decoupled send/receive structure to handle network packets and packet loss:

* **EDNS & Extended RCODE Support**: Supports EDNS (OPT pseudo-RRs). It allows custom buffer size negotiation via `edns_query_size` to accept UDP responses larger than 512 bytes without truncation. It extracts the higher 8 bits from the OPT record to reconstruct and return the full 12-bit Extended RCODE, enabling accurate processing of modern DNS errors (e.g., BADVERS, BADCOOKIE).
* **Dual-Stack Socket Management**: It handles independent IPv4 (`AF_INET`) and IPv6 (`AF_INET6`) sockets simultaneously, routing network packets matching the target resolver IP type.
* **Socket Timeout Loops**: Sockets are configured with a `SO_RCVTIMEO` timeout of **1.5 seconds**. The read routine listens on the socket loop for up to **5 attempts** per nameserver, allocating a maximum cumulative duration of **7.5 seconds** per request to handle server latency without sending duplicate queries.
* **Transaction ID Verification**: Incoming packets are validated by checking `DNSHeader->ID` against the `expected_id`. Non-matching packets are discarded immediately, and the routine keeps listening until the correct packet arrives or the 1.5s socket timeout triggers.
* **Local Socket Fallback**: If a local interface transmission failure occurs (`sendto` returns `-1`), the engine retries the transmission after a 1-second delay, up to 5 times.
---

## 📊 Reading Resource Records (RDATA)

The library unpacks raw packet bytes into specific structures stored inside the `answers`, `authorities`, and `additionals` arrays. You can access them by casting the `void *RDATA` pointer based on the record `TYPE`.

### Reading an `A` (IPv4) Record:
```c
if (record->TYPE == DNS_A) {
    RR_A_RDATA *data = (RR_A_RDATA *)record->RDATA;
    printf("IPv4 Address: %s\n", (char *)data->ADDRESS);
}
```

### Reading an `NS` (Name Server) Record:
```c
if (record->TYPE == DNS_NS) {
    RR_NS_RDATA *data = (RR_NS_RDATA *)record->RDATA;
    printf("Authoritative Name Server: %s\n", (char *)data->NSDNAME);
}
```

### Reading a `CNAME` (Canonical Name) Record:
```c
if (record->TYPE == DNS_CNAME) {
    RR_CNAME_RDATA *data = (RR_CNAME_RDATA *)record->RDATA;
    printf("Canonical Name (Alias): %s\n", (char *)data->CNAME);
}
```

### Reading an `SOA` (Start of Authority) Record:
```c
if (record->TYPE == DNS_SOA) {
    RR_SOA_RDATA *data = (RR_SOA_RDATA *)record->RDATA;
    printf("Primary NS: %s | Responsible Mail: %s\n", (char *)data->MNAME, (char *)data->RNAME);
    printf("Serial: %u | Refresh: %u | Retry: %u | Expire: %u | Minimum: %u\n",
            data->SERIAL, data->REFRESH, data->RETRY, data->EXPIRE, data->MINIMUM);
}
```

### Reading an `MX` (Mail Server) Record:
```c
if (record->TYPE == DNS_MX) {
    RR_MX_RDATA *data = (RR_MX_RDATA *)record->RDATA;
    printf("Preference/Priority: %u | Mail Exchange: %s\n", data->PREFERENCE, (char *)data->EXCHANGE);
}
```

### Reading a `TXT` (Text) Record:
```c
if (record->TYPE == DNS_TXT) {
    RR_TXT_RDATA *data = (RR_TXT_RDATA *)record->RDATA;
    printf("TXT Content: %s\n", (char *)data->TXT_DATA);
}
```

### Reading an `AAAA` (IPv6) Record:
```c
if (record->TYPE == DNS_AAAA) {
    RR_AAAA_RDATA *data = (RR_AAAA_RDATA *)record->RDATA;
    printf("IPv6 Address: %s\n", (char *)data->ADDRESS);
}
```

### Handling Unsupported/Unknown Records:
If the DNS server returns a resource record type that is not natively supported by the library, the `RDATA` pointer is automatically mapped to `RR_UNSUPPORTED_RDATA`. This structure provides direct access to the raw binary payload returned by the server:

```c
if (record->RDATA != NULL && /* condition for unsupported type */) {
    RR_UNSUPPORTED_RDATA *data = (RR_UNSUPPORTED_RDATA *)record->RDATA;
    
    // data->DATA holds the raw binary payload bytes
    printf("Unsupported Type Payload Length: %u bytes\n", record->RDLENGTH);
}
```

---

## 🛠️ Thread-Safe Error Handling

If `dns_lookup()` returns `NULL`, the global thread-local variable `dns_errno` is populated with one of the following codes defined in `DNSError`:

| Error Constant | Value | Description |
| :--- | :--- | :--- |
| `NO_ERROR` | `0` | No error occurred. |
| `DNS_ERR_SYSTEM` | `-1` | General system or environment failure. **(Check standard `errno` for details)** |
| `DNS_ERR_RESOLV_CONF` | `-2` | Failed to open or parse `/etc/resolv.conf`. |
| `DNS_ERR_SEND` | `-3` | Failed to send network packet via socket. |
| `DNS_ERR_RECV` | `-4` | Failed to receive network data. |
| `DNS_ERR_TIMEOUT` | `-5` | Network timeout waiting for resolver response. |
| `DNS_ERR_PACKET_SIZE_EXCEEDED` | `-6` | Received packet size exceeds internal buffer boundaries. |
| `DNS_ERR_PACKET_MALFORMED` | `-7` | Server returned a corrupted or invalid DNS payload. |
| `DNS_ERR_RESOLVER_INPUT` | `-8` | The provided custom resolver string is invalid. |

### 💡 Handling System Errors
When `dns_errno` is set to `DNS_ERR_SYSTEM`, the library encountered a failure within a native POSIX/Linux system call (such as `socket()`, `malloc()`, or `open()`). In this case, the standard Linux `errno` variable (from `<errno.h>`) remains untouched, allowing you to debug the exact OS-level failure using `perror()` or `strerror()`:

```c
#include <errno.h>
#include <string.h>

DNSLookupResult *result = dns_lookup(query);
if (result == NULL) {
    if (dns_errno == DNS_ERR_SYSTEM) {
        // Print the underlying Linux OS error
        fprintf(stderr, "OS System Error: %s\n", strerror(errno));
    } else {
        fprintf(stderr, "DNS Library Error Code: %d\n", dns_errno);
    }
}
```

---

## ⚠️ Memory Allocation Note
The `dns_lookup()` function allocates heap memory dynamically for the result structure, the internal record arrays, and the unpackaged `RDATA` blocks. To prevent memory leaks, **every successful lookup must be explicitly freed** using:
```c
free_result_memory(result);
```
