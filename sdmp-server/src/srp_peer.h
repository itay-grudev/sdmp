/* peer.h
   Mathieu Stefani, 12 August 2015

  A class representing a TCP Peer
*/

#pragma once

#include <string>
#include <iostream>
#include <memory>
#include <unordered_map>

#include <pistache/net.h>
#include <pistache/os.h>
#include <pistache/peer.h>
#include <pistache/async.h>
#include <pistache/stream.h>

#define PISTACHE_SSL_GNUTLS

#ifdef PISTACHE_SSL_GNUTLS
#include <gnutls/gnutls.h>
#endif /* PISTACHE_SSL_GNUTLS */

namespace Pistache {
    namespace Http { namespace Private { class ParserBase; } }
namespace Tcp {

class Transport;

// TODO: Verify this inheritance is correct
// When submiting a full rewrite with GnuTLS this will no longer be necesarry
// as there will just Peer
class SRPPeer : public Peer {
public:
    friend class Transport;

    SRPPeer();
    SRPPeer(const Address& addr);
    ~SRPPeer();

    const Address& address() const;
    const std::string& hostname() const;

    void associateFd(Fd fd);
    Fd fd() const;

    void initTLSSession();
    // void setTLSCredential( gnutls_credentials_type_t type, void *cred );
    void initTLSSession( gnutls_session_t* gnutls_session );
    gnutls_session_t* gnutls_session();

    void putData(std::string name, std::shared_ptr<Pistache::Http::Private::ParserBase> data);
    std::shared_ptr<Pistache::Http::Private::ParserBase> getData(std::string name) const;
    std::shared_ptr<Pistache::Http::Private::ParserBase> tryGetData(std::string name) const;

    Async::Promise<ssize_t> send(const RawBuffer& buffer, int flags = 0);

private:
    void associateTransport(Transport* transport);
    Transport* transport() const;

    Transport* transport_;
    Address addr;
    Fd fd_;

    std::string hostname_;
    std::unordered_map<std::string, std::shared_ptr<Pistache::Http::Private::ParserBase>> data_;

    gnutls_session_t *gnutls_session_;
};

std::ostream& operator<<(std::ostream& os, const SRPPeer& peer);

} // namespace Tcp
} // namespace Pistache
