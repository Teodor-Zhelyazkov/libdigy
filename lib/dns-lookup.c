#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
// #include <stdint.h>
// #include <errno.h>
// #include <sys/socket.h>
// #include <arpa/inet.h>
// #include <unistd.h>
// #include <time.h>
// #include <stdarg.h>
// #include "include/types.h"

#include "include/dns-lookup.h"
#include "include/dns-parser.h"
#include "include/dns-resolver.h"
#include "include/dns-network.h"
#include "include/global.h"
#include "include/utility.h"


/////////////////////// HEADER FLAGS ///////////////////////
typedef struct {
	int POS;
	int LEN;
} DNS_HeaderFlagConfig;

typedef struct {
	DNS_HeaderFlagConfig QR;
	DNS_HeaderFlagConfig OPCODE;
	DNS_HeaderFlagConfig AA;
	DNS_HeaderFlagConfig TC;
	DNS_HeaderFlagConfig RD;
	DNS_HeaderFlagConfig RA;
	DNS_HeaderFlagConfig Z;
	DNS_HeaderFlagConfig RCODE;
} DNS_HeaderFlag;

static const DNS_HeaderFlag DNS_HeaderFlags = {
	.QR 	= { .POS = 15, .LEN = 1 },
	.OPCODE = { .POS = 11, .LEN = 4 },
	.AA 	= { .POS = 10, .LEN = 1 },
	.TC 	= { .POS = 9, .LEN = 1 },
	.RD 	= { .POS = 8, .LEN = 1 },
	.RA 	= { .POS = 7, .LEN = 1 },
	.Z 		= { .POS = 4, .LEN = 3 },
	.RCODE 	= { .POS = 0, .LEN = 4 },
};

DNSLookupResult* run_dns_lookup( DNSLookupQuery query, DNSResolverContext *r_ctx )
{
	// Debug log
	debug_log("Building DNS query - DOMAIN : %s, TYPE : %d, QUERY SIZE : %d", query.target, query.q_type, query.edns_query_size);

	// Init packet buffer 
	uint8_t buffer[DNS_BUFFER_SIZE];
	// init domain name 
	uint8_t *domain_name;
	
	// Init header
	DNSHeader *dns_header = NULL;
	// Init question 
	DNSQuestionFields *dns_question = NULL;

	// Init a 2 byte ID 	
	uint16_t ID = (uint16_t) rand();
	// Init 2 byte FLAGS 
    uint16_t FLAGS = 0;
	// Recurstion desired, sets 9th bit to one OR 1 << 9
	FLAGS |= 1 << DNS_HeaderFlags.RD.POS; 

	// Assigning dns_header pointer to the first byte in buffer 
	dns_header   = ( DNSHeader * )&buffer[0];

	// Assigning domain_name pointer after the dns_header bytes DIRECTLY into the buffer
	domain_name  = ( uint8_t * )&buffer[sizeof( DNSHeader )];

	// Convert the domain name and get the lenght 
	int domain_name_length = convert_domain_to_dns_format(query.target, domain_name);
	// Assigning dns_question pointer after header and domain bytes 
	dns_question = ( DNSQuestionFields * )&buffer[ sizeof( DNSHeader ) + domain_name_length ];
			
	// Init header properties
	dns_header->ID 		= htons(ID);
	dns_header->FLAGS 	= htons(FLAGS);
	dns_header->QDCOUNT = htons(1);
	dns_header->ANCOUNT = htons(0);
	dns_header->NSCOUNT = htons(0);
	dns_header->ARCOUNT = htons(1); // 1 for ENS0 

	// Init question properties
	dns_question->QTYPE 	= htons(query.q_type);
	dns_question->QCLASS 	= htons(DNS_IN);

	// Init ENDS0 / OPT Resource Record 
	uint8_t *opt_name = ( uint8_t * ) &buffer[ sizeof( DNSHeader ) + domain_name_length + sizeof(DNSQuestionFields) ];
	*opt_name = 0x00;

	DNSOPTResourseRecordFields *opt_rr = ( DNSOPTResourseRecordFields * )&buffer[ sizeof( DNSHeader ) + domain_name_length + sizeof(DNSQuestionFields) + 1 ];

	// OPT (41)
	opt_rr->TYPE = htons(41);
	// requestor's UDP payload size 
	opt_rr->CLASS = htons(query.edns_query_size);
	// opt_rr->CLASS = htons(512);
	// opt_rr->CLASS = htons(4096);
	opt_rr->TTL   = htonl(0);
	opt_rr->RDLEN = htons(0);


	// Define our current buffer len
	int buffer_len 	   = sizeof( DNSHeader ) + domain_name_length + sizeof( DNSQuestionFields ) + 1 + sizeof( DNSOPTResourseRecordFields );
	
	// Define our bytes sent & received 
	int bytes_sent 	   = 0;
	int bytes_received = 0;

	// sizeof(buffer) won't work inside the function becase when we pass array as an argument 
	// We have array decays into pointer to the first element of the array 
	int buffer_size = sizeof(buffer);

	// Debug log
	debug_log("Sending UPD message, bytes sending : %d", buffer_len);

	// Send the UPD packet
	int sent 		= send_udp( &buffer[0], buffer_len, buffer_size, &bytes_sent, &bytes_received, r_ctx ,ID );
	// If we failed return null
	if( sent <= 0 )
		return NULL;

	// Debug log
	debug_log("UPD message sended, bytes sended %d / bytes received %d", bytes_sent, bytes_received);

	// Get our new header from the received data 
	DNSHeader *res_dns_header 	= (DNSHeader *) &buffer[0];

	uint16_t is_truncated = get_bits_16(ntohs(res_dns_header->FLAGS), DNS_HeaderFlags.TC.POS, DNS_HeaderFlags.TC.LEN);
	if( is_truncated )
	{
		// Debug error
		debug_error("message was truncated due to length greater than that permitted on the transmission channel\nMax message lenght is %lu\n", query.edns_query_size);

		dns_errno = DNS_ERR_PACKET_SIZE_EXCEEDED;
		return NULL;
	}

	// Debug log
	debug_log("Initializing the result struct \n");

	// init message section counts
	int answer_count 	 = ntohs( res_dns_header->ANCOUNT );
	int authority_count  = ntohs( res_dns_header->NSCOUNT );
	int additional_count = ntohs( res_dns_header->ARCOUNT );

	DNSLookupResult *result = malloc(sizeof(DNSLookupResult));
	if( !result )
	{
		dns_errno = DNS_ERR_SYSTEM;
		return NULL;
	}

	// Initialize the result structure
	result->message_id = ID;
	result->status_rcode = 0;
	result->edns_version = 0;
	result->edns_server_size = 0;
	result->bytes_sent = bytes_sent;
	result->bytes_received = bytes_received;
	
	result->answers 	 = NULL;
	result->answer_count = answer_count;

	result->authorities 	= NULL;
	result->authority_count = authority_count;

	result->additionals 	 = NULL;
	result->additional_count = additional_count;

	if( answer_count > 0 )
	{
		// Imporant to use calloc for "free_result_memory" and DNSResourceRecord->RDATA void pointer
		result->answers = calloc( answer_count, sizeof(DNSResourceRecord) );

		if( result->answers == NULL )
		{
			free_result_memory(result);
			dns_errno = DNS_ERR_SYSTEM;
			return NULL;
		}
	}

	if( authority_count > 0 )
	{
		// Imporant to use calloc for "free_result_memory" and DNSResourceRecord->RDATA void pointer
		result->authorities = calloc( authority_count, sizeof(DNSResourceRecord) );
		if( result->authorities == NULL )
		{
			free_result_memory(result);
			dns_errno = DNS_ERR_SYSTEM;
			return NULL;
		}
	}

	if( additional_count > 0 )
	{
		// Imporant to use calloc for "free_result_memory" and DNSResourceRecord->RDATA void pointer
		result->additionals = calloc( additional_count, sizeof(DNSResourceRecord) );
		if( result->additionals == NULL )
		{
			free_result_memory(result);
			dns_errno = DNS_ERR_SYSTEM;
			return NULL;
		}
	}

	// Debug log
	debug_log("Parsing the result \n");
	
	// Get answer RR
	uint8_t *answer  = &buffer[ sizeof(DNSHeader) + domain_name_length + sizeof(DNSQuestionFields) ];
	int answer_offset = parse_dns_resource_records( result->answers, answer_count, answer, &buffer[0], bytes_received );

	if( answer_offset < 0 )
	{
		// Debug error
		debug_error("Failed to parse answer section");

		free_result_memory(result);
		return NULL;
	}
	
	// Get authority RR
	uint8_t *authority   = answer + answer_offset;
	int authority_offset = parse_dns_resource_records( result->authorities, authority_count, authority , &buffer[0], bytes_received );

	if( authority_offset < 0 )
	{
		// Debug error
		debug_error("Failed to parse authority section");

		free_result_memory(result);
		return NULL;
	}

	// Get additional RR
	uint8_t *additional   = authority + authority_offset;
	int additional_offset = parse_dns_resource_records( result->additionals, additional_count, additional , &buffer[0], bytes_received );

	if( additional_offset < 0 )
	{
		// Debug error
		debug_error("Failed to parse additional section");

		free_result_memory(result);
		return NULL;
	}

	for( int i = 0; i < additional_count; i++ )
	{
		if( result->additionals[i].TYPE == OPT_EDNS_RR_TYPE )
		{
			uint16_t RCODE = get_bits_16(ntohs(res_dns_header->FLAGS), DNS_HeaderFlags.RCODE.POS, DNS_HeaderFlags.RCODE.LEN);

			// Get the approvet buffer size from the server
			uint16_t APPROVED_SIZE 	= result->additionals[i].CLASS;

			// Extract the extended rcode BITS ( bits from 24 to 32 )
			uint8_t EXTENDED_RCODE 	= result->additionals[i].TTL >> 24;
			// Extraxt the ENS0 version BITS
			uint8_t VERSION 		= ( result->additionals[i].TTL >> 16 ) & 0x00FF;

			// Assign to result
			result->status_rcode = ( EXTENDED_RCODE << 4 ) | RCODE; // make room for the 4 RCODE bits and combine
			result->edns_version = VERSION;
			result->edns_server_size = APPROVED_SIZE;

			// IMPORTANT NOTE : 
			// IF ever OPT RR starts to use RDATA : We need to celar it here before the REALLOC
			//  free -> "result->additionals[i].RDATA"

			// Read all elements from this one till the end
			for( int k = i; k < additional_count - 1; k++ )
			{
				// Move all elements one possition ot LEFT, and basically current is not in the array right now 
				result->additionals[k] = result->additionals[k + 1];
			}

			// Decrement the additional_count 
			result->additional_count = result->additional_count - 1;

			if( result->additional_count == 0 )
			{
				// Just free additionals no need for resize
				free(result->additionals);
				// SUPER IMPORTANT to set it to NULL because we will have double free() !!!!
				result->additionals = NULL;
			}
			else
			{
				DNSResourceRecord *resized_addiotionals = realloc(result->additionals, result->additional_count * sizeof(DNSResourceRecord));
	
				if( resized_addiotionals == NULL )
				{
					free_result_memory(result);
					return NULL;
				}
	
				// Re assign the new re-allocated memory
				result->additionals = resized_addiotionals;
			}

			break;
		}
	}

	return result;
}