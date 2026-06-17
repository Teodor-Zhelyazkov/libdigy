#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include "../lib/include/dns-lib.h"

int resolve_query_type_to_network( const char *qtype );
static void print_rr(DNSResourceRecord *rr_array, int rr_count);

int main(int argc, char* argv[])
{
	if( argc <= 1 )
	{
		printf("Please type a domain name \n");
		return 0;
	}

	if( argc <= 2 )
	{
		printf("Please type a query type \n");
		return 0;
	}
	
	if( strlen(argv[1]) > DOMAIN_NAME_MAX_LEN )
	{
		printf("Domain name must not exceed %d \n", DOMAIN_NAME_MAX_LEN);
		return 0;
	}
	
	printf("SIZE ARGV %ld\n", strlen(argv[1]));
	
	int query_type = resolve_query_type_to_network(argv[2]);

	if( query_type == -1 )
	{
		printf("Unsupported query type %s \n", argv[2]);
		return 0;
	}

	printf("query_type %d\n", query_type);

	DNSLookupQuery q = {
		.target = argv[1],
		.q_type = query_type,
		.dns_resolver = "8.8.8.8",
        // .edns_query_size = 512,
        // .dns_resolver = "192.36.148.17",
		// .dns_resolver = "ns4.google.com",
	};

    DNSLookupResult *lookupResult = dns_lookup( q );

    if(lookupResult == NULL)
    {
        printf("DNS lookup failed\n");
        printf("dns_errno = %d\n", dns_errno);
        return 1;
    }

    printf("Message ID      : %u\n", lookupResult->message_id);
    printf("Response Code   : %d\n", lookupResult->status_rcode);
    printf("EDNS Version    : %u\n", lookupResult->edns_version);
    printf("EDNS UDP Size   : %u\n", lookupResult->edns_server_size);
    printf("Bytes sent      : %u\n", lookupResult->bytes_sent);
    printf("Bytes received  : %u\n\n", lookupResult->bytes_received);

    printf("Answers: %d\n\n", lookupResult->answer_count);
    print_rr(lookupResult->answers, lookupResult->answer_count);

    printf("Authorities: %d\n\n", lookupResult->authority_count);
    print_rr(lookupResult->authorities, lookupResult->authority_count);

    printf("Additionals: %d\n\n", lookupResult->additional_count);
    print_rr(lookupResult->additionals, lookupResult->additional_count);

    free_result_memory(lookupResult);

	return 0;
}


static void print_rr(DNSResourceRecord *rr_array, int rr_count)
{
    for(int i = 0; i < rr_count; i++)
    {
        DNSResourceRecord *rr = &rr_array[i];

        printf("NAME : %s\n", rr->NAME);
        printf("TYPE : %u\n", rr->TYPE);
        printf("TTL  : %u\n", rr->TTL);

        switch(rr->TYPE)
        {
            case DNS_A:
            {
                RR_A_RDATA *data = (RR_A_RDATA *)rr->RDATA;

                printf("IPv4 : %s\n", data->ADDRESS);
                break;
            }

            case DNS_AAAA:
            {
                RR_AAAA_RDATA *data = (RR_AAAA_RDATA *)rr->RDATA;

                printf("IPv6 : %s\n", data->ADDRESS);
                break;
            }

            case DNS_CNAME:
            {
                RR_CNAME_RDATA *data = (RR_CNAME_RDATA *)rr->RDATA;

                printf("CNAME: %s\n", data->CNAME);
                break;
            }

            case DNS_NS:
            {
                RR_NS_RDATA *data = (RR_NS_RDATA *)rr->RDATA;

                printf("NS   : %s\n", data->NSDNAME);
                break;
            }

            case DNS_MX:
            {
                RR_MX_RDATA *data = (RR_MX_RDATA *)rr->RDATA;

                printf("PREFERENCE : %u\n", data->PREFERENCE);
                printf("EXCHANGE   : %s\n", data->EXCHANGE);
                break;
            }

            case DNS_TXT:
            {
                RR_TXT_RDATA *data = (RR_TXT_RDATA *)rr->RDATA;

                printf("TXT  : %s\n", data->TXT_DATA);
                break;
            }

            case DNS_SOA:
            {
                RR_SOA_RDATA *data = (RR_SOA_RDATA *)rr->RDATA;

                printf("MNAME  : %s\n", data->MNAME);
                printf("RNAME  : %s\n", data->RNAME);
                printf("SERIAL  : %d\n", data->SERIAL);
                printf("REFRESH  : %d\n", data->REFRESH);
                printf("RETRY  : %d\n", data->RETRY);
                printf("EXPIRE  : %d\n", data->EXPIRE);
                printf("MINIMUM  : %d\n", data->MINIMUM);
                break;
            }

            default:
                printf("Unsupported RR type\n");
        }

        printf("\n");
    }
}

int resolve_query_type_to_network( const char *qtype )
{
	if( strcmp(qtype, "A") == 0 || strcmp(qtype, "a") == 0 )
	{
		return DNS_A;
	}
	else if( strcmp(qtype, "TXT") == 0 ||  strcmp(qtype, "txt") == 0)
	{
		return DNS_TXT;
	}
	else if( strcmp(qtype, "CNAME") == 0 || strcmp(qtype, "cname") == 0 )
	{
		return DNS_CNAME;
	}
	else if( strcmp(qtype, "MX") == 0 || strcmp(qtype, "mx") == 0 )
	{
		return DNS_MX;
	}
	else if( strcmp(qtype, "NS") == 0 || strcmp(qtype, "ns") == 0 )
	{
		return DNS_NS;
	}
	else if( strcmp(qtype, "SOA") == 0 || strcmp(qtype, "soa") == 0  )
	{
		return DNS_SOA;
	}
	else if( strcmp(qtype, "AAAA") == 0 || strcmp(qtype, "aaaa") == 0  )
	{
		return DNS_AAAA;
	}
	else 
	{
		return -1;
	}
}