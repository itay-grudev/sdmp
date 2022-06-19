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

# Debugging
if (CMAKE_BUILD_TYPE EQUAL "DEBUG")
    target_link_libraries( ${PROJECT_NAME} dl )
endif (CMAKE_BUILD_TYPE EQUAL "DEBUG")

# GnuTLS
include(GnuTLS)
target_link_libraries( ${PROJECT_NAME} ${GNUTLS_LIBRARIES} )

# Pistache
set( PISTACHE_DIR "libs/pistache/" )
include_directories( "${CMAKE_SOURCE_DIR}/${PISTACHE_DIR}/include/" )
target_link_libraries( ${PROJECT_NAME}  "pthread" "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libpistache.a" )
add_dependencies( ${PROJECT_NAME} ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libpistache.a )

##
# Embed files
#
set( RC_DEPENDS "" )
function( add_resource input )
    string( MAKE_C_IDENTIFIER ${input} input_identifier )
    set( output "${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/${input_identifier}.o" )
    target_link_libraries( ${PROJECT_NAME} ${output} )

    add_custom_command(
        OUTPUT ${output}
        COMMAND ${CMAKE_LINKER} --relocatable --format binary --output ${output} ${input}
        DEPENDS ${input}
    )

    set( RC_DEPENDS ${RC_DEPENDS} ${output} PARENT_SCOPE )
endfunction()
add_resource( "src/static/index.html" )
add_resource( "src/static/status.json" )
add_resource( "src/static/not_found.json" )
add_custom_target( static-resources ALL DEPENDS ${RC_DEPENDS} )

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
