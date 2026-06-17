#include <stdio.h>
#include <ctype.h>
#include <string.h>
// #include <stdarg.h>
// #include <arpa/inet.h>

// #include "include/dns-lookup.h"
#include "include/dns-resolver.h"
// #include "include/types.h"
#include "include/global.h"
#include "include/utility.h"

#define RESOLV_FILE_PREFIX "nameserver "
#define RESOLV_FILE_PREFIX_LEN 11
#define RESOLV_FILE_LINE_SIZE 256

// external function from : dns-lookup.c
extern DNSLookupResult* run_dns_lookup( DNSLookupQuery query, DNSResolverContext *r_ctx );

/**
	Returns -1 if error occurs 
	returns 0 if there is no nameservers fournd inside the resolv.conf file
	returns 1 if nameservers found
*/
int get_dns_resolvers( DNSResolverContext *r_ctx )
{
    // Init file pointer 
    FILE* fptr;

    // Opening the file in read mode
    fptr = fopen("/etc/resolv.conf", "r");

    // Check if we opened successfully
    if (fptr == NULL) {

        printf("The file is not opened.");
		// Return falsy state
		return -1;
    }

	// Define our search version flags
	char has_ipv4 = FALSE;
	char has_ipv6 = FALSE;
	// Define line 
	char line[RESOLV_FILE_LINE_SIZE];
	// Define our dns_resolvers_pos for the array
	int dns_resolvers_pos = 0;

    while ( fgets(line, sizeof(line), fptr) &&  dns_resolvers_pos < DNS_RESOLVERS_LEN  ) 
	{
		// Compare if the line starts with the nameserver prefix word
		if( strncmp( line, RESOLV_FILE_PREFIX, RESOLV_FILE_PREFIX_LEN ) == 0 )
		{
			// Copy the ip 
			int ip_pos = 0;
			for( int i = RESOLV_FILE_PREFIX_LEN; line[i] != '\0'; i++ )
			{
				// Exclude the last space chars like new lines, tabs, etc.. .
				if( isspace(line[i]) || line[i] == '\0' )
					break;

				// Check the buffer overflow
				if( ip_pos >= INET6_ADDRSTRLEN )
					return -1;

				r_ctx->resolvers[dns_resolvers_pos].ip[ip_pos++] = line[i];
			}

			// Check the buffer overflow
			if( ip_pos >= INET6_ADDRSTRLEN )
				return -1;

			// Add the 0 terminator
			r_ctx->resolvers[dns_resolvers_pos].ip[ip_pos] = '\0';

			// Determine the nameserver ip TYPE
			int is_v4 = is_ipv4( &r_ctx->resolvers[dns_resolvers_pos].ip[0] );
			int is_v6 = is_ipv6( &r_ctx->resolvers[dns_resolvers_pos].ip[0] );
			// Assign the type
			r_ctx->resolvers[dns_resolvers_pos].type = ( is_v4 ) ? DNSRT_IPv4 : DNSRT_IPv6;

			if( is_v4 )
				has_ipv4 = TRUE;

			if( is_v6 )
				has_ipv6 = TRUE;

			// Increment ns array pos
			dns_resolvers_pos ++;
		}
	}

	// Assign the length
	r_ctx->resolvers_len = dns_resolvers_pos;
	// Assign our flags 
	r_ctx->has_ipv4 = has_ipv4;
	r_ctx->has_ipv6 = has_ipv6;

	// Close the file pointer 
	fclose(fptr);

	// Return 1 only we found some servers 
	return ( dns_resolvers_pos > 0 ) ? 1 : 0;
}

int init_user_dns_resolver( DNSLookupQuery query, DNSResolverContext *r_ctx )
{
	int resolvers_initialized = FALSE;

	int its_ipv4 = is_ipv4( query.dns_resolver );
	int its_ipv6 = is_ipv6( query.dns_resolver );

	if( its_ipv4 || its_ipv6 )
	{
		// Clear the current resolvers context 
		memset(r_ctx->resolvers, 0, sizeof(r_ctx->resolvers));

		int len = strlen(query.dns_resolver);

		// Create new DNSResolver struct 
		DNSResolver dns_resolver;
		// init DNSResolver struct 
		dns_resolver.type = DNSRT_IPv4;
		memcpy(&dns_resolver.ip, query.dns_resolver, len);
		dns_resolver.ip[len] = '\0';

		// Assign the new resolver 
		r_ctx->resolvers[0]  = dns_resolver;
		// Init context props 
		r_ctx->resolvers_len = 1;
		r_ctx->has_ipv4 	 = ( its_ipv4 ) ? TRUE : FALSE;
		r_ctx->has_ipv6 	 = ( its_ipv6 ) ? TRUE : FALSE;

		resolvers_initialized = TRUE;
	}
	else
	{
		int resolvers_cleared = FALSE;

		// Get ipv4 and ipv6 from the resolver domain
		int types[2] = {
			DNS_A,
			DNS_AAAA
		};

		int resolver_index = 0;

		for( int i = 0; i < 2; i++ )
		{
			// Build new query struct for resolver lookups
			DNSLookupQuery resolver_query 	= {0};
			resolver_query.target 			= query.dns_resolver;
			resolver_query.q_type 			= types[i];
			resolver_query.edns_query_size 	= query.edns_query_size;

			DNSLookupResult *resolver_result = run_dns_lookup(resolver_query, r_ctx);
			if( !resolver_result )
			{
				// go and try the next type 
				continue;
			}

			if( resolver_result->answer_count == 0 )
			{
				// go and try the next type 
				continue;
			}

			// If we did not clear the resolvers 
			if( resolvers_cleared == FALSE )
			{
				// Clear the current servers 
				memset(r_ctx->resolvers, 0, sizeof(r_ctx->resolvers));
				resolvers_cleared = TRUE;
			}

			// Export and build the answers
			for( int k = 0; k < resolver_result->answer_count; k++ )
			{
				void *rData = NULL;
				char *ADDRESS = NULL;
				
				if( types[i] == DNS_A )
				{
					rData = (RR_A_RDATA *) resolver_result->answers[k].RDATA;
					ADDRESS = (char *) ((RR_A_RDATA *)rData)->ADDRESS;
				}
				else
				{
					rData = (RR_AAAA_RDATA *) resolver_result->answers[k].RDATA;
					ADDRESS = (char *) ((RR_AAAA_RDATA *)rData)->ADDRESS;
				} 
				
				int len = strlen( ADDRESS );
				// Create new NSServer struct 
				DNSResolver dns_resolver;
				// init NSServer struct
				dns_resolver.type = ( types[i] == DNS_A ) ? DNSRT_IPv4 : DNSRT_IPv6;
				memcpy(&dns_resolver.ip, ADDRESS, len);
				dns_resolver.ip[len] = '\0';

				// Assign the new server 
				r_ctx->resolvers[resolver_index++] = dns_resolver;

				// Init context props 
				r_ctx->resolvers_len = resolver_index;
				if( types[i] == DNS_A )
					r_ctx->has_ipv4  = TRUE;
				if( types[i] == DNS_AAAA ) 
					r_ctx->has_ipv6 = TRUE;
			}

			free_result_memory(resolver_result);

			resolvers_initialized = TRUE;
		}
	}

	return ( resolvers_initialized ) ? TRUE : FALSE;
}