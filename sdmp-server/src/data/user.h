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
 * along with the SDMP Server.  If n    ot, see <https://www.gnu.org/licenses/>.
 */

#include <string>
#include <odb/core.hxx>
#include <gnutls/gnutls.h>

class User {
public:
    User(){};

    const unsigned long id() const;

    const std::string& username() const;
    void username( const std::string& );

    const std::string& email() const;
    void email( const std::string& );

    const gnutls_datum_t& salt() const;
    void salt( const gnutls_datum_t& );

    const gnutls_datum_t& verifier() const;
    void verifier( const gnutls_datum_t& );

    const gnutls_datum_t& generator() const;
    void generator( const gnutls_datum_t& );

    const gnutls_datum_t& prime() const;
    void prime( const gnutls_datum_t& );

private:
    unsigned long id_;
    std::string username_;
    std::string email_;
    std::string salt_;
    std::string verifier_;
    std::string generator_;
    std::string prime_;

    friend class odb::access;
};

#pragma db object(User)
#pragma db member(User::id_) id
