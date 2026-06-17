CC = gcc
CFLAGS = -Wall -Wextra -I./lib/include

# List of all library source files
LIB_SRCS = lib/dns-lib.c lib/dns-lookup.c lib/utility.c lib/dns-parser.c lib/dns-resolver.c lib/dns-network.c

TARGET_LIB = lib/libdigy.a
TARGET_DEMO = demo/demo

# Default target executed when running 'make' (builds both library and demo)
all: $(TARGET_LIB) $(TARGET_DEMO)

# Target to build only the static library archive (run 'make lib')
lib: $(TARGET_LIB)

$(TARGET_LIB): $(LIB_SRCS)
	$(CC) $(CFLAGS) -c $(LIB_SRCS)
	ar rcs $(TARGET_LIB) *.o
	rm -f *.o

# Target to build the demo executable using the compiled static library
$(TARGET_DEMO): demo/demo.c $(TARGET_LIB)
	$(CC) $(CFLAGS) demo/demo.c $(TARGET_LIB) -o $(TARGET_DEMO)

# Clean up all generated binary objects, executables, and libraries
.PHONY: all lib clean
clean:
	rm -f $(TARGET_DEMO) $(TARGET_LIB)
