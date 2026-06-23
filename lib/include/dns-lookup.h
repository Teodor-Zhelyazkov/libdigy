#pragma once

#include <stdint.h>

#include "dns-lib.h"
#include "types.h"


/*

	DOCUMENTATION SOURCE : 
		DNS Protocol definitions 
		https://datatracker.ietf.org/doc/html/rfc1035
		ENDS0
		https://datatracker.ietf.org/doc/html/rfc6891#section-1
		AAAA ipv6
		https://datatracker.ietf.org/doc/html/rfc3596#section-2.2

        TODO : 
        SRV 
        https://datatracker.ietf.org/doc/html/rfc2782

        PTR 
        format & ipv4
        https://datatracker.ietf.org/doc/html/rfc1035
        ipv6 
        https://datatracker.ietf.org/doc/html/rfc3596

        CAA
        https://datatracker.ietf.org/doc/html/rfc8659


	### Message

	+---------------------+
    |        Header       |
    +---------------------+
    |       Question      | the question for the name server
    +---------------------+
    |        Answer       | RRs answering the question
    +---------------------+
    |      Authority      | RRs pointing toward an authority
    +---------------------+
    |      Additional     | RRs holding additional information
    +---------------------+

	### HEADER 

      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

	### Question

	  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

	### RR : Resource Record 

	  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

	### OPT RR 

	+------------+--------------+------------------------------+
	| Field Name | Field Type   | Description                  |
	+------------+--------------+------------------------------+
	| NAME       | domain name  | MUST be 0 (root domain)      |
	| TYPE       | u_int16_t    | OPT (41)                     |
	| CLASS      | u_int16_t    | requestor's UDP payload size |
	| TTL        | u_int32_t    | extended RCODE and flags     |
	| RDLEN      | u_int16_t    | length of all RDATA          |
	| RDATA      | octet stream | {attribute,value} pairs      |
	+------------+--------------+------------------------------+
*/


typedef struct __attribute__((packed)) {
	uint16_t ID;
	uint16_t FLAGS;
	uint16_t QDCOUNT;
	uint16_t ANCOUNT;
	uint16_t NSCOUNT;
	uint16_t ARCOUNT;

} DNSHeader;   

typedef struct __attribute__((packed)) {
   	uint16_t QTYPE;
	uint16_t QCLASS; 
} DNSQuestionFields;

typedef struct __attribute__((packed)) {
	uint16_t TYPE;
	uint16_t CLASS;
	uint32_t TTL;
	uint16_t RDLEN;
} DNSOPTResourseRecordFields;


// Function definitions 
DNSLookupResult* run_dns_lookup( DNSLookupQuery query, DNSResolverContext *r_ctx );