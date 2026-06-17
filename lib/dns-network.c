#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#include "include/dns-network.h"
#include "include/dns-lookup.h"
#include "include/global.h"
#include "include/utility.h"


/*
	Description : 
	Loops all the ns servers array and for each of them try + re-try to send a message 
	and if it does try + re-try to receive the correct ID message 
*/
int send_udp( uint8_t *buffer, int buffer_len, int buffer_size, int *bytes_sent, int *bytes_received, DNSResolverContext *r_ctx, int expected_id )
{

	int socket_ipv4 = -1;
	int socket_ipv6 = -1;

	int packet_received = FALSE;

	////////////// Create a socket descriptors for both ipv4 and ipv6 //////////////

	// Init time interval struct
	struct timeval t;
	t.tv_sec = 1; // seconds 
	t.tv_usec = 500000; // microseconds
	
	if( r_ctx->has_ipv4 )
	{
		socket_ipv4 = socket( AF_INET, SOCK_DGRAM, 0 );

		// IPv4 Check if we have the socket created
		if( socket_ipv4 == -1 )
		{
			printf("Can't create a socket descriptor");
			
			dns_errno = DNS_ERR_SYSTEM;
			return -1;
		}

		int set_recv_opts_v4 = setsockopt(socket_ipv4, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof(t));

		if( set_recv_opts_v4 == -1 )
		{
			printf("Can't set UDP options : %s \n", strerror(errno));

			dns_errno = DNS_ERR_SYSTEM;
			close(socket_ipv4);
			return -1;
		}
	}

	if( r_ctx->has_ipv6 )
	{
		socket_ipv6 = socket( AF_INET6, SOCK_DGRAM, 0 );

		// IPv6 Check if we have the socket created
		if( socket_ipv6 == -1 )
		{
			dns_errno = DNS_ERR_SYSTEM;

			// Close ipv4 socket
			if( r_ctx->has_ipv4 ) close (socket_ipv4);

			printf("Can't create a socket descriptor");
			return -1;
		}

		int set_recv_opts_v6 = setsockopt(socket_ipv6, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof(t));

		if( set_recv_opts_v6 == -1 )
		{
			dns_errno = DNS_ERR_SYSTEM;

			// Close ipv4 socket
			if( r_ctx->has_ipv4 ) close (socket_ipv4);

			// printf("Can't set UDP options : %s \n", strerror(errno));

			// Debug error
			debug_error("Can't set UDP options : %s \n", strerror(errno));

			close(socket_ipv6);
			return -1;
		}
	}
	

	for( int i = 0; i < r_ctx->resolvers_len; i ++ )
	{
		if( packet_received == TRUE )
			break;

		// Define a current socket type property 
		int current_socket = -1;

		// SUPER IMPORATNT -> Init struct with 0 bytes 
		struct sockaddr_storage sa_storage = {0};
		// Define dest_len
		socklen_t dest_len = 0;

		if( r_ctx->resolvers[i].type == DNSRT_IPv4 )
		{
			// Define a struct for ipv4 FROM the stack memory of the "sockaddr_storage" struct
			struct sockaddr_in *dest_addr_ipv4 = ( struct sockaddr_in * ) &sa_storage;

			// Init the destination address
			dest_addr_ipv4->sin_family 		= AF_INET;
			dest_addr_ipv4->sin_port 	    = htons(DNS_PORT);
			dest_addr_ipv4->sin_addr.s_addr = inet_addr( r_ctx->resolvers[i].ip );
			// dest_addr_ipv4.sin_addr.s_addr 	= inet_addr("192.36.148.17"); // Trigger additional results for testing

			// init dest_len 
			dest_len = sizeof(struct sockaddr_in); 
			// Assign the current socket 
			current_socket = socket_ipv4;
		}
		else if( r_ctx->resolvers[i].type == DNSRT_IPv6 )
		{
			// Define a struct for ipv6 FROM the stack memory of the "sockaddr_storage" struct
			struct sockaddr_in6 *dest_addr_ipv6  = ( struct sockaddr_in6 * ) &sa_storage;

			// Init the destination address
			dest_addr_ipv6->sin6_family  = AF_INET6;
			dest_addr_ipv6->sin6_port 	 = htons(DNS_PORT);
			
			// assign the ipv6 into the desired struct 
			// NOTE : No need to check for error we already checked with functions is_ipv6 
			inet_pton(AF_INET6, r_ctx->resolvers[i].ip, &dest_addr_ipv6->sin6_addr);
			// init dest_len 
			dest_len = sizeof(struct sockaddr_in6); 
			// Assign the current socket 
			current_socket = socket_ipv6;
		}

		int max_attempts = 5;

		int sent_attempts = 0;
		int recv_attempts = 0;

		// Sent packet while 
		while ( TRUE )
		{
			// increment the sent_attempts by one on each iteration
			sent_attempts ++;

			// Send the buffer to the DNS server
			*bytes_sent = sendto(current_socket, buffer, buffer_len, 0, (struct sockaddr *) &sa_storage, dest_len);
		
			if( *bytes_sent == -1 )
			{
				// Re-Try sending the socket message
				if( sent_attempts < max_attempts )
				{
					// Debug log
					debug_log("Failed to send UDP re-trying again in 1 second : %d / %d attempts", sent_attempts, max_attempts);

					// Sleep for 1 sec before re-try
					sleep(1);
					continue;
				}

				dns_errno = DNS_ERR_SEND;

				// Close ipv4 socket
				if( r_ctx->has_ipv4 ) close (socket_ipv4);
				// Close ipv6 socket
				if( r_ctx->has_ipv6 ) close (socket_ipv6);

				// Debug error
				debug_error("Can't send UDP message after %d attempts : %s", max_attempts, strerror(errno));

				// TERMINATE function here
				return -1;
			}

			// Receive packet while 
			while ( TRUE )
			{
				// increment the recv_attempts by one on each iteration
				recv_attempts ++;

				// Super important to define "current_dest_len" for "recvfrom" function 
				// We are passing the address on "recvfrom" so in case of re-try the address len will be wrong for another call
				socklen_t current_dest_len = dest_len;

				// get the received bytes
				*bytes_received = recvfrom(current_socket, &buffer[0], buffer_size, 0, (struct sockaddr *) &sa_storage, &current_dest_len);

				if( *bytes_received == -1 )
				{
					if ( errno == EAGAIN || errno == EWOULDBLOCK )
					{
						if( recv_attempts <= max_attempts )
							continue;

						dns_errno = DNS_ERR_TIMEOUT;

						// Debug error
						debug_error("DNS query timed out after %d attempts", max_attempts);

						break;
					}
					else
					{
						dns_errno = DNS_ERR_SYSTEM;

						// Close ipv4 socket
						if( r_ctx->has_ipv4 ) close (socket_ipv4);
						// Close ipv6 socket
						if( r_ctx->has_ipv6 ) close (socket_ipv6);
						
						// Debug error
						debug_error("Can't receive UDP response : %s \n", strerror(errno));

						return -1;
					}
				}

				// Extract the header from the received buffer 
				DNSHeader *recv_header = (DNSHeader *) &buffer[0];
				// Check if we have the same id that we have sent 
				if( ntohs(recv_header->ID) != expected_id )
				{
					if( recv_attempts <= max_attempts )
						continue;

					dns_errno = DNS_ERR_RECV;
					// Break RECEIVING while
					// We was not able to receive the right packet 
					break;
				}

				// Assign that we received the packed 
				packet_received = TRUE;

				// Break RECEIVING while 
				break;
			}

			// Break SENDING while 
			break;
		}
	}

	///////////// Close the socket descriptors

	// Close ipv4 socket
	if( r_ctx->has_ipv4 ) close (socket_ipv4);
	// Close ipv6 socket
	if( r_ctx->has_ipv6 ) close (socket_ipv6);

	if( packet_received == TRUE )
	{
		// Clear the error in case of packet received 
		dns_errno = NO_ERROR;
		return 1;
	}

	return 0;

	// return packet_received == TRUE ? 1 : 0;
}