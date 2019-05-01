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

#include <iostream>
#include <cstring>
#include <unistd.h>
#include <gnutls/gnutls.h>

extern char * username;
extern char * password;

/**
 * Prompts the user for credentials
 * @return 0 on success -1 on error
 */

/**
 * Lookups a user SRP credentials in a database
 * @param  gnutls_session_t
 * @param  username
 * @param  salt
 * @param  verifier
 * @param  generator
 * @param  prime
 * @return 0 on success -1 indicates an error
 * @see gnutls_srp_set_server_credentials_function
 */
int credentials_lookup(
    gnutls_session_t,
    const char* username,
    gnutls_datum_t *salt,
    gnutls_datum_t *verifier,
    gnutls_datum_t *generator,
    gnutls_datum_t *prime
){
    // gnutls_malloc( strlen( tmp ) + 2 );

    // ito:
    // 2XSLzjo1cUrBvmACdqmYiM1iMarH3m/L1dCd1SQUnzvN7J7a.64jjJsITRYCWVHT8XK/LGI7SOSM9dIKsMU5u3XBozfqVbEzFHF6lk15qKLZGuSRfFdpZmC4L0CXqB7abo3FLvL1V4IVglnlNol7MQKIlZBHVZsXtWSpmrRDn8rAnlBysZEOQqKb76MXchedyX0Sn1q3x9vNtrYEIEiVkzmi2OFJ0vRTaCudhdkvkLy.7EhC6f8FDVjpN3MZkC3YR7kO5cy9tgMAcnbuw5FLDxPwuUZdkLzt2IyU2s93MUT.ptUBEQH6M5aHV.wQEG2CZsUNSEHPiFXpRUuUtgs2Rl:
    // 1yAl.uAjYG69Wbokr.kryl:
    // 3

    printf( "%s\n", (char*)username );
    printf( "%s\n", (char*)salt );
    printf( "%s\n", (char*)verifier );
    printf( "%d\n", (long)generator );
    printf( "%s\n", (char*)prime );

    // return -1;

    return 0;
}
