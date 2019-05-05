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
#include <gnutls/crypto.h>

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
int credentials_lookup(gnutls_session_t session, const char *username,
	gnutls_datum_t *salt, gnutls_datum_t *verifier, gnutls_datum_t *generator, gnutls_datum_t *prime)
{
    // Generator and Prime
    // The following two sections of code do the same thing a different way.
    // I've left both so the code could be later reused.
    generator->size = gnutls_srp_4096_group_generator.size;
    generator->data = (unsigned char*)gnutls_malloc( generator->size );
    memcpy( generator->data, gnutls_srp_4096_group_generator.data, generator->size );

    gnutls_datum_t n;
    gnutls_srp_base64_encode_alloc( &gnutls_srp_4096_group_prime, &n );
    gnutls_srp_base64_decode_alloc( &n, prime );
    gnutls_free(n.data);

    // Generate salt
    // Fatal in parts of session if broken, i.e., vulnerable to statistical analysis.
    salt->data = (unsigned char*)gnutls_malloc( 24 );
    salt->size = 24;
    if( gnutls_rnd( GNUTLS_RND_NONCE, salt->data, salt->size )) return -1;

    // Generate verifier
    if(
        gnutls_srp_verifier( username, "password", salt, generator, prime, verifier )
    ) return -1;

    return 0;
}
