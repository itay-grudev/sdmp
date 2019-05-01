##
# Project Setup
#
project( sdmp-server )
set( SDMPServer_VERSION_MAJOR 0 )
set( SDMPServer_VERSION_MINOR 1 )
set( SDMPServer_VERSION_REV 0 )

# CMake version
cmake_minimum_required (VERSION 2.6)

##
# CMake Modules
#
SET( CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_LIST_DIR}/cmake/Modules/" )

##
# Build Properties
#
set( CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib )
set( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib )
set( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin )

##
# Build Files
#
file( GLOB SOURCES
    "src/*.cpp"
)
add_executable( sdmp-server ${SOURCES} )

include( CMakeDetermineSystem )
include( CheckCCompilerFlag )
include( CheckFunctionExists )
include( CheckSymbolExists )
include( CheckIncludeFile )
include( CheckIncludeFileCXX )
include( CheckIncludeFiles )
include( CheckLibraryExists )
include( CMakeDependentOption )

##
# Required packages
#
check_include_files( getopt.h               HAVE_GETOPT_H )
check_function_exists( getopt_long          HAVE_GETOPT_LONG )
check_include_files( unistd.h               HAVE_UNISTD_H )
check_include_files( arpa/inet.h            HAVE_ARPA_INET_H )
check_include_files( pistache/endpoint.h    HAVE_PISTACHE_ENDPOINT_H )
check_include_files( odb/core.hxx           HAVE_ODB_CORE_H )

include(GnuTLS)
target_link_libraries( sdmp-server ${GNUTLS_LIBRARIES} )

##
# SSL Private key & Certificate
#
add_custom_target( ssl-cert ALL DEPENDS server.crt )

add_custom_command(
    OUTPUT   server.key
    COMMAND  openssl genrsa -out ${CMAKE_BINARY_DIR}/bin/server.key 4096
)

add_custom_command(
    OUTPUT   server.crt
    COMMAND  openssl req -new -days 365 -nodes -x509 -subj "/C=/ST=/L=/O=/CN=" -key ${CMAKE_BINARY_DIR}/bin/server.key -out ${CMAKE_BINARY_DIR}/bin/server.crt
    DEPENDS  server.key
)
