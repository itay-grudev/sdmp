/* peer.cc
   Mathieu Stefani, 12 August 2015

*/

#include <iostream>
#include <stdexcept>

#include <sys/socket.h>

#include <pistache/async.h>
#include <pistache/transport.h>

#include "srp_peer.h"

#define LOOP_CHECK( rval, cmd ) \
    do { \
        rval = cmd; \
    } while( rval == GNUTLS_E_AGAIN || rval == GNUTLS_E_INTERRUPTED )

namespace Pistache {
namespace Tcp {

SRPPeer::SRPPeer()
    : transport_(nullptr)
    , fd_(-1)
    , gnutls_session_(NULL)
{ }

SRPPeer::SRPPeer(const Address& addr)
    : transport_(nullptr)
    , addr(addr)
    , fd_(-1)
    , gnutls_session_(NULL)
{ }

SRPPeer::~SRPPeer()
{
#ifdef PISTACHE_SSL_GNUTLS
    gnutls_deinit( *gnutls_session_ );
#endif /* PISTACHE_SSL_GNUTLS */
}

const Address& SRPPeer::address() const
{
    return addr;
}

const std::string& SRPPeer::hostname() const
{
    return hostname_;
}

void
SRPPeer::associateFd(int fd) {
    fd_ = fd;
}

#ifdef PISTACHE_SSL_GNUTLS
void SRPPeer::initTLSSession( gnutls_session_t* gnutls_session )
{
    gnutls_session_ = gnutls_session;

    gnutls_transport_set_int( *gnutls_session_, fd_ );
    int ret;
    LOOP_CHECK( ret, gnutls_handshake( *gnutls_session_ ));
    if( ret < 0 ){
        close( fd_ );
        gnutls_deinit( *gnutls_session_ );
        throw std::runtime_error(
            "Handshake has failed (" +
            std::string( gnutls_strerror( ret )) +
            ")"
        );
    }

    // TODO: Drop this logging. Only used for debugging the SRP connection
    // establishment
    printf( "Handshake completed\n" );
    printf(
        "    User connected: %s\n",
        gnutls_srp_server_get_username( *gnutls_session_ )
    );
}

gnutls_session_t* SRPPeer::gnutls_session   ()
{
    return gnutls_session_;
}
#endif /* PISTACHE_SSL_GNUTLS */

int
SRPPeer::fd() const {
    printf("2.1: %d\n", fd_);
    if (fd_ == -1) {
        printf("2.2: %d\n", fd_);
        throw std::runtime_error("The peer has no associated fd");
    }

    return fd_;
}

void
SRPPeer::putData(std::string name, std::shared_ptr<Pistache::Http::Private::ParserBase> data) {
    auto it = data_.find(name);
    if (it != std::end(data_)) {
        throw std::runtime_error("The data already exists");
    }

    data_.insert(std::make_pair(std::move(name), std::move(data)));
}

std::shared_ptr<Pistache::Http::Private::ParserBase>
SRPPeer::getData(std::string name) const {
    auto data = tryGetData(std::move(name));
    if (data == nullptr) {
        throw std::runtime_error("The data does not exist");
    }

    return data;
}

std::shared_ptr<Pistache::Http::Private::ParserBase>
SRPPeer::tryGetData(std::string(name)) const {
    auto it = data_.find(name);
    if (it == std::end(data_)) return nullptr;

    return it->second;
}

Async::Promise<ssize_t>
SRPPeer::send(const RawBuffer& buffer, int flags) {
    return transport()->asyncWrite(fd_, buffer, flags);
}

std::ostream& operator<<(std::ostream& os, const SRPPeer& peer) {
    const auto& addr = peer.address();
    os << "(" << addr.host() << ", " << addr.port() << ") [" << peer.hostname() << "]";
    return os;
}

void
SRPPeer::associateTransport(Transport* transport) {
    transport_ = transport;
}

Transport*
SRPPeer::transport() const {
    if (!transport_)
        throw std::logic_error("Orphaned peer");

    return transport_;
}

} // namespace Tcp
} // namespace Pistache
