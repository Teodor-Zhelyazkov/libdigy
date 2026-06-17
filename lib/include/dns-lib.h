#pragma once

#ifdef _WIN32
#error "This library is supported only on Linux and Unix-like systems."
#endif

#include <stdint.h>
#include <arpa/inet.h>

#include "global.h"

#define DOMAIN_NAME_MAX_LEN 255
#define DOMAIN_NAME_BUFF_SIZE ( DOMAIN_NAME_MAX_LEN + 1 )

#define CHARACTER_STRING_MAX_LEN 255
#define CHARACTER_STRING_BUFF_SIZE ( CHARACTER_STRING_MAX_LEN + 1 )

/////////////////////// DNS Types ///////////////////////

typedef enum {
    DNS_A     = 1,
    DNS_NS    = 2,
    DNS_CNAME = 5,
    DNS_SOA   = 6,
    DNS_MX    = 15,
    DNS_TXT   = 16,
    DNS_AAAA  = 28,
} DNSType;

typedef enum {
	DNS_IN = 1,
} DNSClass;

/////////////////////// Custom Error Codes ///////////////////////

typedef enum {
    NO_ERROR            			=  0,
    DNS_ERR_SYSTEM      			= -1,
    DNS_ERR_RESOLV_CONF 			= -2,
	DNS_ERR_SEND        			= -3,  
    DNS_ERR_RECV        			= -4,  
    DNS_ERR_TIMEOUT     			= -5,
	DNS_ERR_PACKET_SIZE_EXCEEDED	= -6,
    DNS_ERR_PACKET_MALFORMED 		= -7,
    DNS_ERR_RESOLVER_INPUT 			= -8,

    // DNS_ERR_MALFORMED   = -4,
} DNSError;

// make the error thread safe 
extern THREAD_LOCAL int dns_errno;
/////////////////////// Custom Resource Record Representation ///////////////////////

typedef struct {
	uint8_t NAME[DOMAIN_NAME_BUFF_SIZE];
	uint16_t TYPE;
	uint16_t CLASS;
	uint32_t TTL;
	uint16_t RDLENGTH;
	void *RDATA;
}   DNSResourceRecord;

typedef struct {
	// INET_ADDRSTRLEN is defined in <arpa/inet.h>
	uint8_t ADDRESS[INET_ADDRSTRLEN]; 
} RR_A_RDATA;

typedef struct {
	uint8_t NSDNAME[DOMAIN_NAME_BUFF_SIZE];
} RR_NS_RDATA;

typedef struct {
	uint8_t TXT_DATA[CHARACTER_STRING_BUFF_SIZE];
} RR_TXT_RDATA;

typedef struct {
	uint8_t CNAME[DOMAIN_NAME_BUFF_SIZE];
} RR_CNAME_RDATA;

typedef struct {
	uint16_t PREFERENCE;
	uint8_t EXCHANGE[DOMAIN_NAME_BUFF_SIZE];
} RR_MX_RDATA;

typedef struct {
	uint8_t MNAME[DOMAIN_NAME_BUFF_SIZE];
	uint8_t RNAME[DOMAIN_NAME_BUFF_SIZE];
	uint32_t SERIAL;
	uint32_t REFRESH;
	uint32_t RETRY;
	uint32_t EXPIRE;
	uint32_t MINIMUM;
} RR_SOA_RDATA;

typedef struct {
	// INET6_ADDRSTRLEN is defined in <arpa/inet.h>
	uint8_t ADDRESS[INET6_ADDRSTRLEN]; 
} RR_AAAA_RDATA;


typedef struct {
	uint8_t *DATA;
} RR_UNSUPPORTED_RDATA;

/////////////////////// Response Result ///////////////////////

typedef struct {

	int message_id;
	int status_rcode;
	int edns_version;
	int edns_server_size;

	DNSResourceRecord *answers;
    int answer_count;

    DNSResourceRecord *authorities;
    int authority_count;

    DNSResourceRecord *additionals;
    int additional_count;

	int bytes_sent;
	int bytes_received;

} DNSLookupResult;

typedef struct {
	char *target;
	char *dns_resolver;
	int edns_query_size;
	DNSType q_type;
} DNSLookupQuery;

// Function definitions 
DNSLookupResult* dns_lookup( DNSLookupQuery query );
void free_result_memory( DNSLookupResult *result );