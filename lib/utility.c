#include <stdio.h>
#include <stdarg.h>
#include <arpa/inet.h>

#include "include/global.h"
#include "include/types.h"
#include "include/utility.h"

/*
 *	Return bits from given position
 *
 *	STEP 1 : ( number >> bit_position )
 *		- Shifts the number to the desired position 
 *
 *	STEP 2 : ( 1 << width ) - 1
 *		- Creates a mask via shifting ->  (1 << width) - 1 :
 *			1 << 4 = 16 OR 2 to the power of 4 2^4 
 *			16 in binary is = 10000 
 *			15 - 1 = 01111
 *		NOTE : Every power of 2 ( 2^N ) starts with 1 and end with 0s
 *  
 *  STEP 3 : AND the shifted number with the mask 
 *			0101 - shifted number 
 *		&
 *			1111 - created mask
 *		= 
 *			0101 - the result
 */
uint16_t get_bits_16(uint16_t number, int bit_position, int width)
{
	return ( number >> bit_position ) & ( ( 1 << width ) - 1 );
}

void set_bits_16( uint16_t *bits, int value, int bit_position, int width )
{
	// Create a mask with the width
	int mask = ( 1 << width ) - 1;
	// Set the bits at bit_possition to 0's
	*bits &= ~( mask << bit_position );
	// Assign the new value at bit_position
	*bits |= value << bit_position;
}


int is_ipv4( char *ip )
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ip, &(sa.sin_addr));
	return result;
}

int is_ipv6( char *ip )
{
	struct sockaddr_in6 sa;
    int result = inet_pton(AF_INET6, ip, &(sa.sin6_addr));
	return result;
}

void debug_log ( const char * format, ... )
{
	if( DEBUG == FALSE )
		return;

	printf("[LIBDNS][LOG] ");
	va_list args;
	va_start (args, format);
	vprintf (format, args);
	va_end (args);
	printf("\n");
}

void debug_error ( const char * format, ... )
{
	if( DEBUG == FALSE )
		return;

	printf("[LIBDNS][ERROR] ");
	va_list args;
	va_start (args, format);
	vprintf (format, args);
	va_end (args);
	printf("\n");
}

void print_binary(void *ptr, size_t size) 
{
    uint8_t *bytes = (uint8_t *)ptr;

    for (int i = size - 1; i >= 0; i--) {        // go byte by byte (MSB first)
        for (int bit = 7; bit >= 0; bit--) {     // each bit in the byte
		
            printf("%d", (bytes[i] >> bit) & 1);

			if( bit % 4 == 0 )
			{
				printf(" ");
			}
        }
        // printf(" ");
    }
    printf("\n");
}