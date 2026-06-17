#pragma once

#include <arpa/inet.h>

#include "global.h"

typedef enum {
    DNSRT_IPv4   = 0,
    DNSRT_IPv6   = 1,
} DNSResolverType;

typedef struct {
	DNSResolverType type;
	char ip[INET6_ADDRSTRLEN];
} DNSResolver;

typedef struct {
    DNSResolver resolvers[DNS_RESOLVERS_LEN];
	int initialized;
    int resolvers_len;
    int has_ipv4;
    int has_ipv6; 
} DNSResolverContext;

