#pragma once

#include <stdint.h>
#include "dns-lookup.h"
#include "types.h"

int send_udp( uint8_t *buffer, int buffer_len, int buffer_size, int *bytes_sent, int *bytes_received,  DNSResolverContext *r_ctx, int expected_id );