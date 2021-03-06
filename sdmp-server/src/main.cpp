/**
 * Copyright Itay Grudev (c) 2019 all rights reserved.
 *
 * This file is part of the SDMP Server Reference Implementation.
 *
 * The SDMP Server is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The SDMP Server is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the SDMP Server.  If not, see <https://www.gnu.org/licenses/>.
 */

// Base
#include <csignal>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

// Networking
// #include <sys/types.h>
// #include <sys/socket.h>
// #include <netinet/in.h>
#include <arpa/inet.h>

// HTTP REST framework
#include <pistache/net.h>
#include <pistache/endpoint.h>

// GnuTLS
// #include <gnutls/gnutls.h>

// Web API
#include "public_api.h"
#include "private_api.h"

// Data Storage
#include "data/user.h"

#define KEYFILE "server.key"
#define CERTFILE "server.crt"
#define CAFILE "/etc/ssl/certs/ca-certificates.crt"

#define MAX_BUF 1024

#define LOOP_CHECK( rval, cmd ) \
    do { \
        rval = cmd; \
    } while( !ExitFlag && rval == GNUTLS_E_AGAIN || rval == GNUTLS_E_INTERRUPTED )
#define SOCKET_ERR( err,s ) if( err == -1 ){ perror( s ); return( 1 ); }

// Defined in credentials_lookup.cpp
int credentials_lookup( gnutls_session_t, const char*, gnutls_datum_t*, gnutls_datum_t*, gnutls_datum_t*, gnutls_datum_t* );

// Help and usage
#define USAGE_MENU "Usage: sdmp-server [-p <port>] [-h] [--help]"
int help();
inline int usage();
inline int error();

bool VerboseFlag = false;
bool ExitFlag = false;
PublicApi *public_api;
PrivateApi *private_api;

void signal_handler( int );

int main( int argc, char* argv[] )
{
    int err, listen_sd;
    int sd, ret;
    struct sockaddr_in sa_serv;
    struct sockaddr_in sa_cli;
    socklen_t client_len;
    char topbuf[512];
    gnutls_session_t session;
    gnutls_certificate_credentials_t cert_cred;
    char buffer[MAX_BUF + 1];
    int optval = 1;

    // Intentionally using int32 for atoi converion
    uint32_t httpPort = 2585;
    uint32_t srpPort = 2586;

    // Parsing command line arguments
    int c;
    while( true ){
        static struct option long_options[] = {
            { "help",           no_argument,            nullptr, 'h' },
            { "verbose",        no_argument,            nullptr, 'v' },
            { "public-port",    required_argument,      nullptr, 'p' },
            { "srp-port",       required_argument,      nullptr, 'r' },
            { "use-ssl",        required_argument,      nullptr, 's' },
            { "concurrency",    required_argument,      nullptr, 'c' },
            {0, 0, 0, 0}
        };

        int option_index = 0;
        c = getopt_long( argc, argv, "hv:p:", long_options, &option_index );

        if( c == -1 ) // End of options
            break;

        switch( c ){
            case 0:
                // If the option sets a flag - do nothing
                if( long_options[option_index].flag != 0 ) break;
                break;
            case 'v':
                VerboseFlag = true;
                std::printf( "VerboseFlag\n" );
                break;
            case 'h':
                return help();
                break;
            case 's':
                VerboseFlag = true;
                std::printf( "VerboseFlag\n" );
                break;
            case 'p':
                httpPort = atoi( optarg );
                if( httpPort == 0 || httpPort > 65535 ){
                    std::cerr << "Invalid port specified." << std::endl;
                    return error();
                }
                break;
            case 'r':
                srpPort = atoi( optarg );
                if( srpPort == 0 || srpPort > 65535 ){
                    std::cerr << "Invalid port specified." << std::endl;
                    return error();
                }
                break;
            default:
                return help();
        }
    }

    // Public API
    Pistache::Address public_api_addr( Pistache::Ipv4::any(), Pistache::Port( httpPort ));
    public_api = new PublicApi( public_api_addr );
    public_api->init( 1 );
    public_api->startThreaded();
    printf( "SDMP Public API Ready. Listening on port '%d'.\n", httpPort );

    // Private (SRP) API
    // Pistache::Address private_api_addr( Pistache::Ipv4::any(), Pistache::Port( srpPort ));
    // private_api = new PrivateApi( private_api_addr );
    // private_api->init( Pistache::hardware_concurrency() );

    // private_api->startThreaded();
    printf( "SDMP Private API Ready. Listening on port '%d'.\n", srpPort );

    // Wait for interrupt
    sigset_t sigset;
    sigemptyset( &sigset );
    sigaddset( &sigset, SIGHUP );
    sigaddset( &sigset, SIGINT );
    sigaddset( &sigset, SIGTERM );
    sigprocmask( SIG_BLOCK, &sigset, nullptr );
    int sig = 0;
    sigwait( &sigset, &sig );
    std::cerr << "Shutting down..." << std::endl;
    sigprocmask( SIG_UNBLOCK, &sigset, nullptr );

    public_api->stop();
    private_api->stop();

    return 0;
    //
    // if( gnutls_check_version( "3.3.0" ) == NULL ){
    //     std::cerr << "GnuTLS 3.3.0 or later is required." << std::endl;
    //     return error();
    // }
    //
    // // SRP Credentials initialisation
    // gnutls_srp_server_credentials_t srp_cred;
    // gnutls_srp_allocate_server_credentials( &srp_cred );
    // gnutls_srp_set_server_credentials_file( srp_cred, "tpasswd", "tpasswd.conf" );
    // gnutls_srp_set_server_credentials_function( srp_cred, credentials_lookup );
    //
    // gnutls_certificate_allocate_credentials( &cert_cred );
    // gnutls_certificate_set_x509_trust_file( cert_cred, CAFILE, GNUTLS_X509_FMT_PEM );
    // gnutls_certificate_set_x509_key_file( cert_cred, CERTFILE, KEYFILE, GNUTLS_X509_FMT_PEM );
    //
    // // TCP socket operations
    // listen_sd = socket( AF_INET, SOCK_STREAM, 0 );
    // SOCKET_ERR( listen_sd, "socket" );
    //
    // memset( &sa_serv, '\0', sizeof(sa_serv) );
    // sa_serv.sin_family = AF_INET;
    // sa_serv.sin_addr.s_addr = INADDR_ANY;
    // sa_serv.sin_port = htons( srpPort );
    //
    // setsockopt( listen_sd, SOL_SOCKET, SO_REUSEADDR, (void*)&optval, sizeof(int) );
    //
    // err = bind( listen_sd, (struct sockaddr*)&sa_serv, sizeof(sa_serv) );
    // SOCKET_ERR( err, "bind" );
    // err = listen( listen_sd, 1024 );
    // SOCKET_ERR( err, "listen" );
    //
    // printf( "SDMP Server ready. Listening on port '%d'.\n\n", srpPort );
    //
    // client_len = sizeof( sa_cli );
    // while( !ExitFlag ){
    //     gnutls_init( &session, GNUTLS_SERVER );
    //     gnutls_priority_set_direct(
    //         session,
    //         "NORMAL:-KX-ALL:+SRP:+SRP-DSS:+SRP-RSA",
    //         NULL
    //     );
    //     // "NORMAL:-KX-ALL:+SRP:+SRP-DSS:+SRP-RSA",
    //     gnutls_credentials_set( session, GNUTLS_CRD_SRP, srp_cred );
    //     // For certificate authenticated ciphersuites
    //     // gnutls_credentials_set( session, GNUTLS_CRD_CERTIFICATE, cert_cred );
    //
    //     // We don't request a certificate from the client
    //     gnutls_certificate_server_set_request( session, GNUTLS_CERT_IGNORE );
    //
    //     sd = accept( listen_sd, (struct sockaddr*) &sa_cli, &client_len );
    //
    //     printf(
    //         "- connection from %s, port %d\n",
    //         inet_ntop(AF_INET, &sa_cli.sin_addr, topbuf, sizeof(topbuf) ),
    //         ntohs( sa_cli.sin_port )
    //     );
    //
    //     gnutls_transport_set_int( session, sd );
    //
    //     LOOP_CHECK( ret, gnutls_handshake( session ));
    //     if( ret < 0 ){
    //         close( sd );
    //         gnutls_deinit( session );
    //         fprintf(
    //             stderr,
    //             "*** Handshake has failed (%s)\n\n",
    //             gnutls_strerror( ret )
    //         );
    //         continue;
    //     }
    //     printf( "- Handshake was completed\n" );
    //     printf(
    //         "- User %s was connected\n",
    //         gnutls_srp_server_get_username( session )
    //     );
    //
    //     // print_info( session );
    //
    //     while( !ExitFlag ){
    //         LOOP_CHECK( ret, gnutls_record_recv( session, buffer, MAX_BUF ));
    //
    //         if( ret == 0 ){
    //             printf( "\n- Peer has closed the GnuTLS connection\n" );
    //             break;
    //         } else if(
    //             ret < 0 &&
    //             gnutls_error_is_fatal( ret ) == 0
    //         ){
    //             fprintf( stderr, "*** Warning: %s\n", gnutls_strerror( ret ) );
    //         } else if( ret < 0 ){
    //             fprintf(
    //                 stderr,
    //                 "\n*** Received corrupted data(%d). Closing the connection.\n\n",
    //                 ret
    //             );
    //             break;
    //         } else if( ret > 0 ){
    //             // echo data back to the client
    //             gnutls_record_send( session, buffer, ret );
    //         }
    //     }
    //
    //     printf( "\n" );
    //
    //     // do not wait for the peer to close the connection.
    //     LOOP_CHECK( ret, gnutls_bye( session, GNUTLS_SHUT_WR ) );
    //
    //     close( sd );
    //     gnutls_deinit( session );
    //
    // }
    //
    // close( listen_sd );
    //
    // gnutls_srp_free_server_credentials( srp_cred );
    // gnutls_certificate_free_credentials( cert_cred );

    public_api->stop();
    return 0;
}

void signal_handler( int signal ){
    switch( signal ){
        case SIGHUP:
        case SIGINT:
        case SIGTERM:
            ExitFlag = true;
            public_api->stop();
            private_api->stop();
            printf( "Shutting down...\n" );
            break;
    }
}

inline int usage(){
    std::cout << USAGE_MENU << std::endl;
    return 0;
}

inline int error(){
    std::cerr << USAGE_MENU << std::endl;
    return 1;
}

int help() {
    std::cout << USAGE_MENU << "\n";
    std::cout << "Options:" << "\n";
    std::cout << "   -p, --public-port  Sets the port number for the public HTTP API.\n";
    std::cout << "   -s, --use-ssl      Set to use HTTPS instead of HTTP for the public API.\n";
    std::cout << "   -r, --srp-port     Sets the port number for SRP connections.\n";
    std::cout << "   -h, --help         Show an extended usage menu and exit.\n";
    std::cout << "\n"
        "Copyright Itay Grudev (C) 2019 all rights reserved. This program is "
        "released under the terms of the GNU General Public License, version 3 "
        "or later." << std::endl;
        return 0;
}
