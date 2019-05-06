##
# Project Setup
#
project( sdmp-server )
set( SDMPServer_VERSION_MAJOR 0 )
set( SDMPServer_VERSION_MINOR 1 )
set( SDMPServer_VERSION_REV 0 )

# CMake version
cmake_minimum_required( VERSION 2.6 )

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
add_executable( ${PROJECT_NAME} ${SOURCES} )


##
# Required packages
#
include( CheckIncludeFiles )
include( CheckFunctionExists )

check_include_files( getopt.h               HAVE_GETOPT_H )
check_function_exists( getopt_long          HAVE_GETOPT_LONG )
check_include_files( unistd.h               HAVE_UNISTD_H )
check_include_files( arpa/inet.h            HAVE_ARPA_INET_H )
check_include_files( pistache/endpoint.h    HAVE_PISTACHE_ENDPOINT_H )
check_include_files( odb/core.hxx           HAVE_ODB_CORE_H )

# GnuTLS
include(GnuTLS)
target_link_libraries( ${PROJECT_NAME} ${GNUTLS_LIBRARIES} )

# Pistache
set( PISTACHE_DIR "libs/pistache/" )
include_directories( ${CMAKE_SOURCE_DIR} ${PISTACHE_DIR} "include/" )
target_link_libraries( ${PROJECT_NAME}  ${CMAKE_LIBRARY_OUTPUT_DIRECTORY} "libpistache.a" )
target_link_libraries( ${PROJECT_NAME}  "pthread" )

##
# SSL Private key & Certificate
#
add_custom_target( ssl-cert ALL DEPENDS ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/server.key ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/server.crt )

add_custom_command(
    OUTPUT   ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/server.key
    COMMAND  openssl genrsa -out ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/server.key 4096
)

add_custom_command(
    OUTPUT   ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/server.crt
    COMMAND  openssl req -new -days 365 -nodes -x509 -subj "/C=/ST=/L=/O=/CN=" -key ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/server.key -out ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/server.crt
    DEPENDS  ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/server.key
)
