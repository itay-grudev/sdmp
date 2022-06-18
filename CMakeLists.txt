##
# Project Setup
#
project( sdmp )
set( SDMPServer_VERSION_MAJOR 0 )
set( SDMPServer_VERSION_MINOR 1 )
set( SDMPServer_VERSION_REV 0 )

# CMake version
cmake_minimum_required (VERSION 2.6)

##
# Build Properties
#
set( CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib )
set( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib )
set( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin )

##
# CMake Modules
#
SET( CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_LIST_DIR}/cmake/Modules/" )

set( CMAKE_CXX_STANDARD 17 )

##
# Subprojects
#

# Pistache
set( PISTACHE_USE_SSL OFF CACHE BOOL "add server support for SSL via OpenSSL" FORCE )
set( PISTACHE_SSL_GNUTLS ON CACHE BOOL "add server support for SSL via GnuTLS" FORCE )
add_subdirectory( libs/pistache )
add_custom_target( libpistache DEPENDS ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libpistache.a )

add_subdirectory( sdmp-client )
add_subdirectory( sdmp-server )
