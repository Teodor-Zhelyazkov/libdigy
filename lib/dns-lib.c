#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "include/dns-lib.h"
#include "include/dns-lookup.h"
#include "include/dns-resolver.h"
#include "include/global.h"
#include "include/utility.h"

#define RESOLV_READ_INTERVAL 5

void free_rr_rdata( DNSResourceRecord *rr );

// Define our dns_errno
THREAD_LOCAL int dns_errno = NO_ERROR;

static THREAD_LOCAL int BOOT = FALSE;
static THREAD_LOCAL int read_resolvers = TRUE;
static THREAD_LOCAL time_t last_resolvers_read = 0;

// Global static resolver context 
static THREAD_LOCAL DNSResolverContext r_ctx = { 0 };

DNSLookupResult* dns_lookup( DNSLookupQuery query )
{
	// Debug log
	debug_log("DNS LOOKUP STARTED - DOMAIN : %s, TYPE : %d, QUERY SIZE : %d, RESOLVER : %s", query.target, query.q_type, query.edns_query_size, query.dns_resolver);

	// Check boot status
	if ( BOOT == FALSE )
	{
		// Debug log
		debug_log("Booting DNS lookup");
		// Init srand once
		srand(time(NULL));
		BOOT = TRUE;
	}

	// Force resolv.conf reads on time interval 
	if( time(NULL) - last_resolvers_read  >= 5 )
	{
		// Debug log
		debug_log("FORCE read resolv.conf after time interval : %d seconds", RESOLV_READ_INTERVAL);

		read_resolvers = TRUE;
	}

	if( !query.edns_query_size )
	{
		// Set the default max EDNS buffer size
		query.edns_query_size = DNS_BUFFER_SIZE;
	}

	// Check if we need to read the resolvers 
	if( read_resolvers == TRUE || r_ctx.resolvers_len == 0 )
	{
		// Debug log
		debug_log("Reading DNS Resolvers from : resolv.conf");

		// Get dns resolvers from resolv.conf
		int get_resolvers_result = get_dns_resolvers( &r_ctx );

		if( get_resolvers_result <= 0 )
		{
			// Debug error
			debug_error("Failed to get resolvers from : resolv.conf");

			// Assign error CODE 
			dns_errno = DNS_ERR_RESOLV_CONF;
			return NULL;
		}
		// Resolvers readed -> Cache them for the next call 
		read_resolvers = FALSE;
		// Register last resolvers read time
		last_resolvers_read = time(NULL);
	}

	// Check if user passes a resolver
	if( query.dns_resolver )
	{
		// Debug log
		debug_log("initialize user resolver : %s", query.dns_resolver);

		// Override the r_ctx (resolv.conf - results)  with the user resolver
		int init = init_user_dns_resolver( query, &r_ctx );
		// Trigger resolvers read on next call
		read_resolvers = TRUE;

		// Check for error 
		if( init <= 0 )
		{
			// Debug error
			debug_error("Failed to initialize user resolve : %s ", query.dns_resolver);

			dns_errno = DNS_ERR_RESOLVER_INPUT;
			return NULL;
		}
	}

	// Execute the user request
	DNSLookupResult *result = run_dns_lookup(query, &r_ctx);

	// Debug error
	if( result == NULL )
		debug_error("Failed to lookup user hostname %s", query.target);

	return result;
}


void free_result_memory( DNSLookupResult *result )
{
	if( result == NULL )
		return;
	
	// Loop all the resource records && free RDATA heap memory
	for( int i = 0; i < result->answer_count; i++ )
		free_rr_rdata( &result->answers[i] );

	for( int i = 0; i < result->authority_count; i++ )
		free_rr_rdata( &result->authorities[i] );

	for( int i = 0; i < result->additional_count; i++ )
		free_rr_rdata( &result->additionals[i] );

	free(result->answers);
	free(result->authorities);
	free(result->additionals);

	result->answers = NULL;
	result->authorities = NULL;
	result->additionals = NULL;

	free(result);

	result = NULL;
}

void free_rr_rdata( DNSResourceRecord *rr )
{
    if (rr == NULL || rr->RDATA == NULL)
        return;

    switch (rr->TYPE)
    {
        case DNS_A:
        case DNS_AAAA:
        case DNS_NS:
        case DNS_CNAME:
        case DNS_MX:
        case DNS_TXT:
        case DNS_SOA:
            free(rr->RDATA);
            break;

        default:
        {
			// Cast to "RR_UNSUPPORTED_RDATA" in order to access the "DATA" pointer
            RR_UNSUPPORTED_RDATA *rData_Unsupported = (RR_UNSUPPORTED_RDATA *) rr->RDATA;
			// Clear data pointer
            free(rData_Unsupported->DATA);
			rData_Unsupported->DATA = NULL;
			// Clear the whole thingy 
            free(rr->RDATA);
			
            break;
        }
    }

    rr->RDATA = NULL;
}