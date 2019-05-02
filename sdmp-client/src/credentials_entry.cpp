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
 * @param  gnutls_session_t
 * @param  username_p
 * @param  password_p
 * @return 0 on success -1 on error
 */
int credentials_entry( gnutls_session_t, char** username_p, char** password_p ){
    char *tmp;

    // If the username is not specified as a command line argument attempt to
    // get the USER environment variable or abort.
    std::string user;
    if( username == nullptr ){
        tmp = std::getenv( "USER" );
        if( ! tmp ){
            std::cout << "Enter username: " << std::flush;
            std::cin >> user;
            tmp = (char*)user.c_str();
        }
        if( ! tmp ){
            std::cerr << "Error: No username specified!" << std::endl;
            return -1;
        }
    } else {
        tmp = username;
    }
    *username_p = (char*)gnutls_malloc( strlen( tmp ) + 2 );
    strcpy( *username_p, tmp );

    // If no password is specified prompt the user to enter a password
    if( password == nullptr ){
        tmp = getpass( "Enter password: " );
        if( ! tmp ){
            std::cerr << "Error: No password specified!" << std::endl;
            return -1;
        }
    } else {
        tmp = password;
    }
    *password_p = (char*)gnutls_malloc( strlen( tmp ) + 2 );
    strcpy( *password_p, tmp );

    return 0;
}
