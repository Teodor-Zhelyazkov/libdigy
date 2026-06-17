#pragma once

#include "dns-lookup.h"
#include "types.h"

int get_dns_resolvers( DNSResolverContext *r_ctx );
int init_user_dns_resolver( DNSLookupQuery query, DNSResolverContext *r_ctx );