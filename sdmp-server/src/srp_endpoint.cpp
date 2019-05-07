/* endpoint.cc
   Mathieu Stefani, 22 janvier 2016

   Implementation of the http endpoint
*/

#include <pistache/config.h>
#include <pistache/tcp.h>
#include <pistache/peer.h>

#include "srp_endpoint.h"

namespace Pistache {
namespace Http {

SRPEndpoint::Options::Options()
    : threads_(1)
    , flags_()
    , backlog_(Const::MaxBacklog)
    , maxPayload_(Const::DefaultMaxPayload)
{ }

SRPEndpoint::Options&
SRPEndpoint::Options::threads(int val) {
    threads_ = val;
    return *this;
}

SRPEndpoint::Options&
SRPEndpoint::Options::flags(Flags<Tcp::Options> flags) {
    flags_ = flags;
    return *this;
}

SRPEndpoint::Options&
SRPEndpoint::Options::backlog(int val) {
    backlog_ = val;
    return *this;
}

SRPEndpoint::Options&
SRPEndpoint::Options::maxPayload(size_t val) {
    maxPayload_ = val;
    return *this;
}

SRPEndpoint::SRPEndpoint()
{ }

SRPEndpoint::SRPEndpoint(const Address& addr)
    : listener(addr)
{ }

void
SRPEndpoint::init(const SRPEndpoint::Options& options) {
    listener.init(options.threads_, options.flags_);
    ArrayStreamBuf<char>::maxSize = options.maxPayload_;
}

void
SRPEndpoint::setHandler(const std::shared_ptr<Handler>& handler) {
    handler_ = handler;
}

void
SRPEndpoint::bind() {
    listener.bind();
}

void
SRPEndpoint::bind(const Address& addr) {
    listener.bind(addr);
}

void
SRPEndpoint::serve()
{
    serveImpl(&Tcp::Listener::run);
}

void
SRPEndpoint::serveThreaded()
{
    serveImpl(&Tcp::Listener::runThreaded);
}

void
SRPEndpoint::shutdown()
{
    listener.shutdown();
}

void
SRPEndpoint::useSSL(std::string cert, std::string key, bool use_compression)
{
#ifndef PISTACHE_USE_SSL
    (void)cert;
    (void)key;
    (void)use_compression;
    throw std::runtime_error("Pistache is not compiled with SSL support.");
#else
    listener.setupSSL(cert, key, use_compression);
#endif /* PISTACHE_USE_SSL */
}

void
SRPEndpoint::useSSLAuth(std::string ca_file, std::string ca_path, int (*cb)(int, void *))
{
#ifndef PISTACHE_USE_SSL
    (void)ca_file;
    (void)ca_path;
    (void)cb;
    throw std::runtime_error("Pistache is not compiled with SSL support.");
#else
    listener.setupSSLAuth(ca_file, ca_path, cb);
#endif /* PISTACHE_USE_SSL */

}

Async::Promise<Tcp::Listener::Load>
SRPEndpoint::requestLoad(const Tcp::Listener::Load& old) {
    return listener.requestLoad(old);
}

SRPEndpoint::Options
SRPEndpoint::options() {
    return Options();
}

} // namespace Http
} // namespace Pistache