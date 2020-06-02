project (6bed4 C)
cmake_minimum_required (VERSION 2.6)
set (VERSION "0.0.1")
cmake_policy (SET CMP0053 NEW)

add_definitions (-DLINUX)

option (DEBUG
	"Switch on output and flags that aid developpers in debugging"
	OFF)

if (DEBUG)
	add_compile_options (-DDEBUG -ggdb3 -O0 -fstack-protector)
endif()

add_executable (6bed4peer "src/6bed4peer.c")
add_executable (6bed4router "src/6bed4router.c")

install (PROGRAMS
	${CMAKE_BINARY_DIR}/6bed4peer
	${CMAKE_BINARY_DIR}/6bed4router
	DESTINATION sbin)
install (FILES
	${CMAKE_SOURCE_DIR}/doc/man/6bed4peer.man
	${CMAKE_SOURCE_DIR}/doc/man/6bed4router.man
	DESTINATION ${SHARE_INSTALL_PREFIX}/man/man8)


#
# Setup a number of parameters.  Until we get 6bed4 standardised,
# these are preliminary values that MUST NOT be assumed static.
#
# This is why CMake will present a warning, but it will still
# go ahead with the values.  They can be changed at will using
# any tool that interacts with the CMakeCache.txt file or that
# overrides the settings at build time.
#
# Please beware that the values contain the information in a
# number of different forms.  In a perfect world, we would
# derive values from one another.  In a portable world, for
# now at least, we resort to letting you maintain consistency.
#

if (NOT ND_OPT_DESTINATION_LINKADDR)
	message ("\nSTEALING an experimental Neighbor Discovery Option Type 253 for Destination Link-Layer Address -- please configure your local override\n")
	set (ND_OPT_DESTINATION_LINKADDR 253
		CACHE STRING "Neighbor Discovery Option Type for Destination Link-Layer Address; Configure an unused value until this is standardised"
	)
else ()
	message (WARNING
		"Using experimental Neighbour Discovery Option Type ${ND_OPT_DESTINATION_LINKADDR}")
endif ()

if (NOT UDP_PORT_6BED4)
	message ("\nSTEALING an experimental UDP port number 25790 or 0x64be -- please configure your local override\n")
	set (UDP_PORT_6BED4 25790
		CACHE STRING "Decimal UDP Port to use in this 6bed4 setup; Must be consistent with other settings that mention it in different forms; Configure an unused value until this is standardised"
	)
	set (SERVER_6BED4_PORT_TXT "\"25790\""
		CACHE STRING "Decimal string representation of the UDP Port to use; Must be consistent with UDP_PORT_6BED4"
	)
	set (SERVER_6BED4_PORT_BINSTR "\"\\xbe\\x64\""
		CACHE STRING "Binary string representation of the UDP Port to use; Unsigned 16 bits in network byte order; Must be consistent with UDP_PORT_6BED4"
	)
else ()
	message (WARNING
		"Using experimental UDP port number ${UDP_PORT_6BED4}")
endif ()

if (NOT SERVER_6BED4_IPV4_TXT)
	message ("\nSTEALING an expermental 6bed4 server IP address 145.136.0.1 -- please configure your local override\n")
	set (SERVER_6BED4_IPV4_TXT "\"145.136.0.1\""
		CACHE STRING "String representation of decimal IP address of the 6bed4 server to use; Must be consistent with other settings that mention it in different forms"
	)
	set (SERVER_6BED4_IPV4_INT32 252183167
		CACHE STRING "Unsinged 32-bit integer form of the IP address of the 6bed4 server; Higher bits are for coarser routing; Must be consistent with SERVER_6BED4_IPV4_TXT"
	)
	set (SERVER_6BED4_IPV4_INT0 145
		CACHE STRING "Decimal form of the byte 1/4 of the IP address of the 6bed4 server; Must be consistent with SERVER_6BED4_IPV4_TXT"
	)
	set (SERVER_6BED4_IPV4_INT1 136
		CACHE STRING "Decimal form of the byte 2/4 of the IP address of the 6bed4 server; Must be consistent with SERVER_6BED4_IPV4_TXT"
	)
	set (SERVER_6BED4_IPV4_INT2 0
		CACHE STRING "Decimal form of the byte 3/4 of the IP address of the 6bed4 server; Must be consistent with SERVER_6BED4_IPV4_TXT"
	)
	set (SERVER_6BED4_IPV4_INT3 1
		CACHE STRING "Decimal form of the byte 4/4 of the IP address of the 6bed4 server; Must be consistent with SERVER_6BED4_IPV4_TXT"
	)
	set (SERVER_6BED4_IPV4_BINSTR "\"\\x91\\x88\\x00\\x01\""
		CACHE STRING "Binary string representation of the IP address of the 6bed4 server; Must be consistent with SERVER_6BED4_IPV4_TXT"
	)
else ()
	message (WARNING
		"Using experimental server IP address ${SERVER_6BED4_IPV4_TXT}")
endif ()

set (SERVER_6BED4_IPV4_PORT_TXT "\"145.136.0.1:25790\""
	CACHE STRING "Textual representation of the 6bed4 server IPv4 address and port number; Must be consistent with SERVER_6BED4_IPV4_TXT and UDP_PORT_6BED4"
)
set (SERVER_6BED4_PORT_IPV4_ADDRSTR "\"\\xbe\\x64\\x91\\x88\\x00\\x01\""
	CACHE STRING "Binary string representation of the 6bed4 server port number followed by the IPv4 address; Must be the concatenation of SERVER_6BED4_PORT_BINSTR and SERVER_6BED4_IPV4_BINSTR"
)
set (SERVER_6BED4_PORT_IPV4_MACSTR "\"\\xbc\\x64\\x91\\x88\\x00\\x01\""
	CACHE STRING "Binary string representation of the 6bed4 server port number and IPv4 address as a MAC address; Must be equal to SERVER_6BED4_PORT_IPV4_ADDRSTR except for an applied XOR with 0x02 on the first byte"
)

set (INTERFACE_NAME_6BED4 "6bed4"
	CACHE STRING "The name of the network interface created by 6bed4peer and 6bed4router.  The default name is \"6bed4\" which may conflict with local naming policies for interfaces, or scripts.  It is the clearest name, so it is the default, but you can override it if you need to.")

option (LOCAL_OVERRIDES_PORT0 "Addresses PREFIX6BED4:x:x:0:x have no meaning to 6bed4 and will be treated as local addresses of the 6bed4router" ON)


configure_file (
	${CMAKE_SOURCE_DIR}/src/nonstd.h.in
	${CMAKE_BINARY_DIR}/src/nonstd.h
	IMMEDIATE @ONLY
)

include_directories (${CMAKE_BINARY_DIR}/src)

add_definitions (-DINTERFACE_NAME_6BED4="${INTERFACE_NAME_6BED4}")

if (LOCAL_OVERRIDES_PORT0)
	add_definitions (-DLOCAL_OVERRIDES_PORT0=yes)
endif ()


#
# Packaging
#
include (CPack)
