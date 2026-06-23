#pragma once

#include <stdint.h>
#include "dns-lookup.h"

int parse_dns_resource_records( DNSResourceRecord *rr_array, int rr_count, uint8_t *rr_buffer, uint8_t *buffer, int bytes_received );
int read_dns_domain_name(uint8_t *answer, uint8_t *buff, uint8_t *domain_name, int bytes_received );
int convert_domain_to_dns_format( char *src_name, uint8_t *dest_name );
int convert_dns_format_to_domain( uint8_t *src_name, uint8_t *dest_name );
int convert_ip_to_dns_ptr_format( char *src_ip, char *dest_name );