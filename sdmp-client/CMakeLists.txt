##
# Project Setup
#
project( sdmp-client )
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
check_include_files( odb/core.hxx           HAVE_ODB_CORE_H )

include(GnuTLS)
target_link_libraries( ${PROJECT_NAME} ${GNUTLS_LIBRARIES} )
