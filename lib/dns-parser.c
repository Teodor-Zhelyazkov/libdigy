#include <string.h>
#include <stdlib.h>

// #include "include/dns-lookup.h"
#include "include/dns-parser.h"
#include "include/global.h"
#include "include/types.h"
#include "include/utility.h"

/////////////////////// HIDDEN INTERNAL RR_OPT_RDATA Struct ///////////////////////

typedef struct {
    uint16_t OPTION_CODE;
    uint16_t OPTION_LENGTH;
    uint8_t *OPTION_DATA;
} RR_OPT_RDATA;

int parse_dns_resource_records( DNSResourceRecord *rr_array, int rr_count, uint8_t *rr_buffer, uint8_t *buffer, int bytes_received )
{
	// Save the starting address of the rr_buffer 
	uint8_t *rr_buffer_start = rr_buffer;
	// Define the end of the buffer addres / packet ends here
	uint8_t *end_packet = buffer + bytes_received;

	// Loop all the resource records 
	for( int i = 0; i < rr_count; i++ )
	{
		// Read the domain name 
		int adn_length = read_dns_domain_name( rr_buffer, &buffer[0], &rr_array[i].NAME[0], bytes_received );
		// Check the read 
		if( adn_length == -1 )
		{
			// Debug error
			debug_error("Failed to read Resrouce Record - NAME from the buffer.");

			dns_errno = DNS_ERR_PACKET_MALFORMED;
			return -1;
		}
		// Convert the domain name
		int converted_length = convert_dns_format_to_domain(&rr_array[i].NAME[0], &rr_array[i].NAME[0]);
		// Check the convert 
		if ( converted_length == -1 )
		{
			// Debug error
			debug_error("Failed to convert Resrouce Record - NAME to human readable format.");

			dns_errno = DNS_ERR_PACKET_MALFORMED;
			return -1;
		}

		// for( int k = 0; k < strlen((char *) rr_array[i].NAME); k++ )
		// {
		// 	// printf("CONVERTED -- %c \n", answer_domain[i]);
		// 	printf("BYTE %d -- %02x (char: %c)\n", i, rr_array[i].NAME[k], rr_array[i].NAME[k]);
		// }

		// Bounds check for domain name
		if( rr_buffer + adn_length > end_packet )
		{
			// Debug error
			debug_error("Packet out of bounds before Resource Record domain name part");

			dns_errno = DNS_ERR_PACKET_MALFORMED;
			return -1;
		}

		// re-position the rr_buffer pointer offset 
		rr_buffer += adn_length;


		// Bounds check for the RR head ( 10 is the size of all the memcpy-s down there )
		int head_size_chheck = sizeof(rr_array[i].TYPE) + sizeof(rr_array[i].CLASS) + sizeof(rr_array[i].TTL) + sizeof(rr_array[i].RDLENGTH);
		if( rr_buffer + head_size_chheck > end_packet )
		{
			// Debug error
			debug_error("Packet out of bounds before Resource Record head part");

			dns_errno = DNS_ERR_PACKET_MALFORMED;
			return -1;
		}


		memcpy( &rr_array[i].TYPE, rr_buffer, sizeof(rr_array[i].TYPE) );
		rr_array[i].TYPE = ntohs(rr_array[i].TYPE );
		rr_buffer += sizeof(rr_array[i].TYPE);

		memcpy( &rr_array[i].CLASS, rr_buffer, sizeof(rr_array[i].CLASS) );
		rr_array[i].CLASS = ntohs(rr_array[i].CLASS );
		rr_buffer += sizeof(rr_array[i].CLASS);

		memcpy( &rr_array[i].TTL, rr_buffer, sizeof(rr_array[i].TTL) );
		rr_array[i].TTL = ntohl(rr_array[i].TTL );
		rr_buffer += sizeof(rr_array[i].TTL);

		memcpy( &rr_array[i].RDLENGTH, rr_buffer, sizeof(rr_array[i].RDLENGTH) );
		rr_array[i].RDLENGTH = ntohs(rr_array[i].RDLENGTH );
		rr_buffer += sizeof(rr_array[i].RDLENGTH);


		// Bounds check for the RDATA 
		if( rr_buffer + rr_array[i].RDLENGTH > end_packet )
		{
			// Debug error
			debug_error("Packet out of bounds before Resource Record RDATA part");

			dns_errno = DNS_ERR_PACKET_MALFORMED;
			return -1;
		}


		/**
			Parse RDATA 
			Important :
				the void * -> "rr_array[i].RDATA" uses [HEAP MEMORY] in each block 
		*/

		switch( rr_array[i].TYPE )
		{
			case DNS_A:
			{
				// Allocate void pointer memory
				rr_array[i].RDATA = malloc( sizeof(RR_A_RDATA) );
				if( rr_array[i].RDATA == NULL )
				{
					dns_errno = DNS_ERR_SYSTEM;
					return -1;
				}
			
				RR_A_RDATA * pData_A = (RR_A_RDATA *) rr_array[i].RDATA;

				// Build the IP address as string 
				uint32_t ipv4_bytes = 0;
				memcpy( &ipv4_bytes, rr_buffer, sizeof(uint32_t) );
				// NOTE : Expects BIG ENDIAN bits order 
				const char *ipv4_convert = inet_ntop(AF_INET, &ipv4_bytes, (char *)pData_A->ADDRESS, INET_ADDRSTRLEN);
				
				if( ipv4_convert == NULL )
				{
					// Debug error
					debug_error("Failed to parse IPv4 for DNS_A");

					dns_errno = DNS_ERR_SYSTEM;
					return -1;
				}

				// OLD WAY 
				// Build the IP address as string
				// sprintf((char *) pData_A->ADDRESS, "%d.%d.%d.%d", rr_buffer[0], rr_buffer[1], rr_buffer[2], rr_buffer[3]);
				
				break;
			}
			case DNS_AAAA:
			{
				// Allocate void pointer memory
				rr_array[i].RDATA = malloc( sizeof(RR_AAAA_RDATA) );
				if( rr_array[i].RDATA == NULL )
				{
					dns_errno = DNS_ERR_SYSTEM;
					return -1;
				}
			
				RR_AAAA_RDATA * pData_AAAA = (RR_AAAA_RDATA *) rr_array[i].RDATA;

				// Define 16 bytes / 128 bit number 
				uint8_t ipv6_bytes[16];
				memcpy( &ipv6_bytes, rr_buffer, 16 );

				// Convert to ipv6 string 
				// NOTE : Expects BIG ENDIAN bits order 
				const char *ipv6_convert = inet_ntop(AF_INET6, &ipv6_bytes, (char *)pData_AAAA->ADDRESS, INET6_ADDRSTRLEN);

				if( ipv6_convert == NULL )
				{
					// Debug error
					debug_error("Failed to parse IPv6 for DNS_AAAA");

					dns_errno = DNS_ERR_SYSTEM;
					return -1;
				}

				break;
			}
			case DNS_NS:
			{
				// Allocate void pointer memory
				rr_array[i].RDATA = malloc( sizeof(RR_NS_RDATA) );
				if( rr_array[i].RDATA == NULL )
				{
					dns_errno = DNS_ERR_SYSTEM;
					return -1;
				}

				RR_NS_RDATA * pData_NS = (RR_NS_RDATA *) rr_array[i].RDATA;


				// Read the domain name
				int nsdname_length = read_dns_domain_name( rr_buffer, &buffer[0], &pData_NS->NSDNAME[0], bytes_received );
				// Check the read 
				if( nsdname_length == -1 )
				{
					// Debug error
					debug_error("Failed to read DNS_NS - NSDNAME from the buffer.");

					dns_errno = DNS_ERR_PACKET_MALFORMED;
					return -1;
				}
				// Convert the domain
				int ns_convert_length = convert_dns_format_to_domain(&pData_NS->NSDNAME[0], &pData_NS->NSDNAME[0]);
				// Check the Convert 
				if( ns_convert_length == -1 )
				{
					// Debug error
					debug_error("Failed to convert DNS_NS - NSDNAME to human readable format.");

					dns_errno = DNS_ERR_PACKET_MALFORMED;
					return -1;
				}

				break;
			}
			case DNS_CNAME:
			{
				// Allocate void pointer memory
				rr_array[i].RDATA = malloc( sizeof(RR_CNAME_RDATA) );
				if( rr_array[i].RDATA == NULL )
				{
					dns_errno = DNS_ERR_SYSTEM;
					return -1;
				}

				RR_CNAME_RDATA * pData_CNAME = (RR_CNAME_RDATA *) rr_array[i].RDATA;

				// Read the domain
				int cname_length = read_dns_domain_name( rr_buffer, &buffer[0], &pData_CNAME->CNAME[0], bytes_received );
				// Check the read 
				if( cname_length == -1 )
				{
					// Debug error
					debug_error("Failed to read DNS_CNAME - CNAME from the buffer.");

					dns_errno = DNS_ERR_PACKET_MALFORMED;
					return -1;
				}
				// Convert the domain
				int cname_convert_length = convert_dns_format_to_domain(&pData_CNAME->CNAME[0], &pData_CNAME->CNAME[0]);
				// Check the convert 
				if( cname_convert_length == -1 )
				{
					// Debug error
					debug_error("Failed to convert DNS_CNAME - CNAME to human readable format.");

					dns_errno = DNS_ERR_PACKET_MALFORMED;
					return -1;
				}

				break;
			}
			case DNS_MX:
			{
				// Allocate void pointer memory
				rr_array[i].RDATA = malloc( sizeof(RR_MX_RDATA) );
				if( rr_array[i].RDATA == NULL )
				{
					dns_errno = DNS_ERR_SYSTEM;
					return -1;
				}

				RR_MX_RDATA * pData_MX = (RR_MX_RDATA *) rr_array[i].RDATA;

				memcpy( &pData_MX->PREFERENCE, rr_buffer, sizeof(pData_MX->PREFERENCE) );
				pData_MX->PREFERENCE = ntohs(pData_MX->PREFERENCE);

				// Define our rr_buffer offset
				int offset = sizeof(pData_MX->PREFERENCE);
				// Super important to do the expression :  rr_buffer + offset -> In order to move the current offset cased by PREFERENCE
				int exchange_length = read_dns_domain_name( rr_buffer + offset , &buffer[0], &pData_MX->EXCHANGE[0], bytes_received );
				// Check the read 
				if( exchange_length == -1 )
				{
					// Debug error
					debug_error("Failed to read DNS_MX - EXCHANGE from the buffer.");

					dns_errno = DNS_ERR_PACKET_MALFORMED;
					return -1;
				}
				// Convert the domain
				int exchange_convert_length = convert_dns_format_to_domain(&pData_MX->EXCHANGE[0], &pData_MX->EXCHANGE[0]);
				// Check the convert 
				if( exchange_convert_length == -1 )
				{
					// Debug error
					debug_error("Failed to convert DNS_MX - EXCHANGE to human readable format.");

					dns_errno = DNS_ERR_PACKET_MALFORMED;
					return -1;
				}

				break;
			}
			case DNS_TXT:
			{
				// Allocate void pointer memory
				rr_array[i].RDATA = malloc( sizeof(RR_TXT_RDATA) );
				if( rr_array[i].RDATA == NULL )
				{
					dns_errno = DNS_ERR_SYSTEM;
					return -1;
				}

				RR_TXT_RDATA * pData_TXT = (RR_TXT_RDATA *) rr_array[i].RDATA;

				// First byte represents the text length
				size_t txt_length = rr_buffer[0];
				// Define our offset after the text length byte 
				int offset = 1;

				// [RCE memory check]
				if( txt_length >= sizeof( pData_TXT->TXT_DATA ) )
				{
					// Debug error
					debug_error("Failed to write DNS_TXT - TXT_DATA due to size limit exceeded.");

					dns_errno = DNS_ERR_PACKET_MALFORMED;
					return -1;
				}
				
				memcpy( pData_TXT->TXT_DATA, rr_buffer + offset, txt_length );
				pData_TXT->TXT_DATA[txt_length] = '\0';

				break;
			}
			case DNS_SOA:
			{
				// Allocate void pointer memory
				rr_array[i].RDATA = malloc( sizeof(RR_SOA_RDATA) );
				if( rr_array[i].RDATA == NULL )
				{
					dns_errno = DNS_ERR_SYSTEM;
					return -1;
				}

				RR_SOA_RDATA * pData_SOA = (RR_SOA_RDATA *) rr_array[i].RDATA;

				// Define offset in order to move to the specific properties
				int offset = 0;
				// Read the domain
				int soa_mname_length = read_dns_domain_name( rr_buffer, &buffer[0], &pData_SOA->MNAME[0], bytes_received );
				// Check the read 
				if( soa_mname_length == -1 )
				{
					// Debug error
					debug_error("Failed to read DNS_SOA - MNAME from the buffer.");

					dns_errno = DNS_ERR_PACKET_MALFORMED;
					return -1;
				}
				// Convert the domain
				int soa_mname_converted_length = convert_dns_format_to_domain(&pData_SOA->MNAME[0], &pData_SOA->MNAME[0]);
				// Check convert 
				if( soa_mname_converted_length == -1 )
				{
					// Debug error
					debug_error("Failed to convert DNS_SOA - MNAME to human readable format.");
					
					dns_errno = DNS_ERR_PACKET_MALFORMED;
					return -1;
				}
				// Apply offset 
				offset += soa_mname_length;
				
				// Read the domain
				int soa_rname_length = read_dns_domain_name( rr_buffer + offset, &buffer[0], &pData_SOA->RNAME[0], bytes_received );
				// Check the read 
				if( soa_rname_length == -1 )
				{
					// Debug error
					debug_error("Failed to read DNS_SOA - RNAME from the buffer.");

					dns_errno = DNS_ERR_PACKET_MALFORMED;
					return -1;
				}
				int soa_rname_converted_length = convert_dns_format_to_domain(&pData_SOA->RNAME[0], &pData_SOA->RNAME[0]);
				// Check the read 
				if( soa_rname_converted_length == -1 )
				{
					// Debug error
					debug_error("Failed to convert DNS_SOA - RNAME to human readable format.");

					dns_errno = DNS_ERR_PACKET_MALFORMED;
					return -1;
				}
				// Apply offset
				offset += soa_rname_length;

				// Check if somehow the server lies about the RDLENGTH
				int soa_data_to_copy = sizeof(pData_SOA->SERIAL) + sizeof(pData_SOA->REFRESH) + sizeof(pData_SOA->RETRY) + sizeof(pData_SOA->EXPIRE) + sizeof(pData_SOA->MINIMUM);
				if( offset + soa_data_to_copy > rr_array[i].RDLENGTH )
				{
					// Debug error
					debug_error("Packet out of bounds before DNS_SOA : SERIAL, REFRESH, RETRY, EXPIRE parts");

					dns_errno = DNS_ERR_PACKET_MALFORMED;
					return -1;
				}

				memcpy( &pData_SOA->SERIAL, rr_buffer + offset, sizeof(pData_SOA->SERIAL));
				pData_SOA->SERIAL = ntohl(pData_SOA->SERIAL);
				offset += sizeof(pData_SOA->SERIAL);

				memcpy( &pData_SOA->REFRESH, rr_buffer + offset, sizeof(pData_SOA->REFRESH));
				pData_SOA->REFRESH = ntohl(pData_SOA->REFRESH);
				offset += sizeof(pData_SOA->REFRESH);

				memcpy( &pData_SOA->RETRY, rr_buffer + offset, sizeof(pData_SOA->RETRY));
				pData_SOA->RETRY = ntohl(pData_SOA->RETRY);
				offset += sizeof(pData_SOA->RETRY);

				memcpy( &pData_SOA->EXPIRE, rr_buffer + offset, sizeof(pData_SOA->EXPIRE));
				pData_SOA->EXPIRE = ntohl(pData_SOA->EXPIRE);
				offset += sizeof(pData_SOA->EXPIRE);

				memcpy( &pData_SOA->MINIMUM, rr_buffer + offset, sizeof(pData_SOA->MINIMUM));
				pData_SOA->MINIMUM = ntohl(pData_SOA->MINIMUM);
				// offset += sizeof(pData_SOA->MINIMUM);  // -> NO NEED TO INCREMENT 

				break;
			}
			case OPT_EDNS_RR_TYPE: /////////////////// OPT - ENDS0 ///////////////////
			{
				rr_array[i].RDATA = NULL;

				// NOTE : 
				// the prop "OPTION_DATA" is a pointer here so we will leave it as it is 
				// We dont have any idea what kind of options we will support so we will leave it 

				/*
					rr_array[i].RDATA = malloc( sizeof(RR_OPT_RDATA) );
					if( rr_array[i].RDATA == NULL )
						return -1;
					
					RR_OPT_RDATA *pData_OPT = (RR_OPT_RDATA *) rr_array[i].RDATA;

					// Define offset in order to move to the specific properties
					int offset = 0;

					memcpy( &pData_OPT->OPTION_CODE, rr_buffer + offset, sizeof(pData_OPT->OPTION_CODE));
					pData_OPT->OPTION_CODE = ntohl(pData_OPT->OPTION_CODE);
					offset += sizeof(pData_OPT->OPTION_CODE);

					memcpy( &pData_OPT->OPTION_LENGTH, rr_buffer + offset, sizeof(pData_OPT->OPTION_LENGTH));
					pData_OPT->OPTION_LENGTH = ntohl(pData_OPT->OPTION_LENGTH);
					offset += sizeof(pData_OPT->OPTION_LENGTH);

					// TODO : pData_OPT->OPTION_DATA
				*/

				break;
			}
			default : /////////////////// ALL UNSUPPORTED RR ///////////////////
			{
				// Allocate void pointer memory
				rr_array[i].RDATA = malloc( sizeof(RR_UNSUPPORTED_RDATA) );
				if( rr_array[i].RDATA == NULL )
				{
					dns_errno = DNS_ERR_SYSTEM;
					return -1;
				}

				RR_UNSUPPORTED_RDATA * pData_Unsupported = ( RR_UNSUPPORTED_RDATA * ) rr_array[i].RDATA;

				pData_Unsupported->DATA = NULL;
				pData_Unsupported->DATA = malloc(rr_array[i].RDLENGTH);

				if( pData_Unsupported->DATA == NULL )
				{
					dns_errno = DNS_ERR_SYSTEM;
					return -1;
				}

				memcpy( pData_Unsupported->DATA, rr_buffer, rr_array[i].RDLENGTH);

				break;
			}
		}

		// Move the rr_buffer offset 
		rr_buffer += rr_array[i].RDLENGTH;
	}

	// In C pointer substraction is valid ( addition is not ! ) so here we can get a int like number from 2 address subsctraction
	return rr_buffer - rr_buffer_start;
}

int read_dns_domain_name( uint8_t *reader, uint8_t *buffer, uint8_t *dns_domain, int bytes_received )
{
	int answer_length = 0;
	int domain_length = 0;
	int is_offset = FALSE;
	int jumps = 0;
	// 0x00 is the same as '\0'
	dns_domain[0] = 0x00;


	// [OUT OF BOUNDS CHECK]
	if( reader >= buffer + bytes_received)
		return -1;

	// 6google3com
	while ( *reader != 0x00 )
	{
		// Check if we overflow the buffer
		if( domain_length >= 255 )
			return -1;

		if( jumps > 50 )
			return -1;

		/*
			The first two bits are ones means we have name compression 

			+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
			| 1  1|                OFFSET                   |
			+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

		*/

		// 0xC0 -> represends 1100 0000 in hexdecimal 
		// The reason we are doing & operator here because the offset is acctualy 14 bits so if the number
		// from the offset enters the first byte 6 leftover bits - in case of bigger number
		if ( (*reader & 0xC0) == 0xC0 )
		{
			// [OUT OF BOUNDS CHECK]
			if( reader + 1 >= ( buffer + bytes_received) )
				return -1;

			// 0x3F -> represents 0011 1111 in hexdecimal
			// So here we wanna exclude the first 2 bits that we checked above and preserve the 6 left 
			uint16_t high_bits = ( *reader & 0x3F ) << 8;
			uint8_t low_bits   = * ( reader + 1 );

			// Build the offset which is represented as 14 bits integer 
			uint16_t offset = high_bits | low_bits;

			// Offset is out of bounds 
			if( offset >= bytes_received )
				return -1;

			// If we dont have offset yet
			if( is_offset == FALSE )
			{
				// move answer length pointer by 2 bytes
				answer_length += 2;
				is_offset = TRUE;
			}

			// change reader pointer to buffer offset
			reader = &buffer[offset];

			// Check if new offset position is invalid
			if( *reader == 0x00 )
				return -1;

			// Increment all offset jumps 
			jumps ++;
		}
		else
		{
			// assign characters to dns_domain
			dns_domain[domain_length] = *reader;
			
			// if thats not a offset we want to count the characters AKA bytes
			if( is_offset == FALSE )
				answer_length += 1;
	
			// move the address on the next byte
			reader++;
			// increment domain string length
			domain_length++;

			// [OUT OF BOUNDS CHECK] 
			if( reader >= ( buffer + bytes_received) )
				return -1;
		}
	}

	// We need to add the last null terminator from the DNS buffer 
	if( is_offset == FALSE )
	{
		answer_length += 1;
	}

	// We want to add the last string null terminator character
	// 0x00 is the same as '\0'
	dns_domain[domain_length] = 0x00;

	return answer_length;
}

int convert_dns_format_to_domain( uint8_t *src_name, uint8_t *dest_name )
{
	// example :  6google3com -> google.com
	int char_num = 0;
	int dest_pos = 0;
	int src_pos  = 0;
	// get the first char num && increment
	char_num = src_name[0];
	src_pos++;

	while( char_num > 0 )
	{
		// If the data is corrupted and we meet 0 terminator before char_num ends 
		if( src_name[src_pos] == '\0' )
			return -1;

		// Check out of buffer 
		if( dest_pos >= CHARACTER_STRING_MAX_LEN )
			return -1;

		// move the chars 
		dest_name[dest_pos++] = src_name[src_pos++];
		// decrement the current char_num count
		char_num--;

		if( char_num == 0 )
		{
			if( src_name[src_pos] != '\0' )
			{
				// Check out of buffer 
				if( dest_pos >= CHARACTER_STRING_MAX_LEN )
					return -1;

				// re-assign char_num with the next character numbers 
				char_num = src_name[src_pos++];
				// add a dot
				dest_name[dest_pos++] = '.';
			}
			else
			{
				break;
			}
		}
	}

	// Check out of buffer 
	if( dest_pos >= CHARACTER_STRING_MAX_LEN )
		return -1;

	dest_name[dest_pos] = '\0';

	return dest_pos;
}

int convert_domain_to_dns_format( char *src_name, uint8_t *dest_name )
{
	int pos    = 0;
   	int start  = 0;
	int length = 0;
	// Start with null char
	dest_name[pos] = '\0';

	for( size_t i = 0; i <= strlen(src_name); i++ )
	{
		if( src_name[i] == '.' || src_name[i] == '\0' )
		{
			// Add the char lenght we found
			dest_name[pos++] = (uint8_t)length;
			// Assign each character 
			for( int k = start; k < start + length; k++ )
			{
				dest_name[pos++] = src_name[k];
			}
			// increment start & + 1 cuz of the length added on the start 
			start += length + 1;
			// clear current length 
			length = 0;
		}
		else 
		{
			length ++;
		}
	}		
	// Assign the null character
	dest_name[pos++] = '\0';
	// Return the new string length
	return pos;
}