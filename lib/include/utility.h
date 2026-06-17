#pragma once

#include <stdint.h>

uint16_t get_bits_16( uint16_t number, int bit_position, int width );
void set_bits_16( uint16_t *bits, int value, int bit_position, int width );
int is_ipv4( char *ip );
int is_ipv6( char *ip );
void debug_log ( const char * format, ... );
void debug_error ( const char * format, ... );