/* listener.cc
   Mathieu Stefani, 12 August 2015

*/

#include <pistache/common.h>
#include <pistache/os.h>
#include <pistache/transport.h>
#include <pistache/errors.h>

#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>

#include <chrono>
#include <memory>
#include <vector>

#include <cerrno>
#include <signal.h>

#define PISTACHE_SSL_GNUTLS

#ifdef PISTACHE_SSL_GNUTLS
// TODO: remove this altogether
#endif /* PISTACHE_SSL_GNUTLS */

#include "srp_listener.h"
#include "srp_peer.h"

// Defined in credentials_lookup.cpp
// TODO: custom callback support
int credentials_lookup( gnutls_session_t, const char*, gnutls_datum_t*, gnutls_datum_t*, gnutls_datum_t*, gnutls_datum_t* );

namespace Pistache {
namespace Tcp {

namespace {
    volatile sig_atomic_t g_listen_fd = -1;

    void closeSRPListener() {
        if (g_listen_fd != -1) {
            ::close(g_listen_fd);
            g_listen_fd = -1;
        }
    }

    void handle_sigint(int) {
        closeSRPListener();
    }
}

SRPListener::SRPListener()
    : addr_()
    , listen_fd(-1)
    , backlog_(Const::MaxBacklog)
    , shutdownFd()
    , poller()
    , options_()
    , workers_(Const::DefaultWorkers)
    , reactor_()
    , transportKey()
    , useSSL_(false)
{ }

SRPListener::SRPListener(const Address& address)
    : addr_(address)
    , listen_fd(-1)
    , backlog_(Const::MaxBacklog)
    , shutdownFd()
    , poller()
    , options_()
    , workers_(Const::DefaultWorkers)
    , reactor_()
    , transportKey()
    , useSSL_(false)
{
}

SRPListener::~SRPListener() {
    if (isBound())
        shutdown();
    if (acceptThread.joinable())
        acceptThread.join();
#ifdef PISTACHE_SSL_GNUTLS
    if (this->useSSL_)
    {
        gnutls_srp_free_server_credentials( srp_cred );
        gnutls_certificate_free_credentials( cert_cred );
    }
#endif /* PISTACHE_SSL_GNUTLS */
}

void
SRPListener::init(
    size_t workers,
    Flags<Options> options, int backlog)
{
    if (workers > hardware_concurrency()) {
        // Log::warning() << "More workers than available cores"
    }

    options_ = options;
    backlog_ = backlog;
    useSSL_ = false;

    if (options_.hasFlag(Options::InstallSignalHandler)) {
        if (signal(SIGINT, handle_sigint) == SIG_ERR) {
            throw std::runtime_error("Could not install signal handler");
        }
    }

    workers_ = workers;

}

void
SRPListener::setHandler(const std::shared_ptr<Handler>& handler) {
    handler_ = handler;
}

void
SRPListener::pinWorker(size_t worker, const CpuSet& set)
{
    UNUSED(worker)
    UNUSED(set)
#if 0
    if (ioGroup.empty()) {
        throw std::domain_error("Invalid operation, did you call init() before ?");
    }
    if (worker > ioGroup.size()) {
        throw std::invalid_argument("Trying to pin invalid worker");
    }

    auto &wrk = ioGroup[worker];
    wrk->pin(set);
#endif
}

void
SRPListener::bind() {
    bind(addr_);
}

void
SRPListener::bind(const Address& address) {
    if (!handler_)
        throw std::runtime_error("Call setHandler before calling bind()");
    addr_ = address;

    struct addrinfo hints;
    hints.ai_family = address.family();
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = 0;

    const auto& host = addr_.host();
    const auto& port = addr_.port().toString();
    AddrInfo addr_info;

    TRY(addr_info.invoke(host.c_str(), port.c_str(), &hints));

    int fd = -1;

    const addrinfo * addr = nullptr;
    for (addr = addr_info.get_info_ptr(); addr; addr = addr->ai_next) {
        fd = ::socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (fd < 0) continue;

        setSocketOptions(fd, options_);

        if (::bind(fd, addr->ai_addr, addr->ai_addrlen) < 0) {
            close(fd);
            continue;
        }

        TRY(::listen(fd, backlog_));
        break;
    }

    // At this point, it is still possible that we couldn't bind any socket. If it is the case, the previous
    // loop would have exited naturally and addr will be null.
    if (addr == nullptr) {
        throw std::runtime_error(strerror(errno));
    }

    make_non_blocking(fd);
    poller.addFd(fd, Polling::NotifyOn::Read, Polling::Tag(fd));
    listen_fd = fd;
    g_listen_fd = fd;

    auto transport = std::make_shared<Transport>(handler_);

    reactor_.init(Aio::AsyncContext(workers_));
    transportKey = reactor_.addHandler(transport);
}

bool
SRPListener::isBound() const {
    return listen_fd != -1;
}

// Return actual TCP port SRPListener is on, or 0 on error / no port.
// Notes:
// 1) Default constructor for 'Port()' sets value to 0.
// 2) Socket is created inside 'SRPListener::run()', which is called from
//    'Endpoint::serve()' and 'Endpoint::serveThreaded()'.  So getting the
//    port is only useful if you attempt to do so from a _different_ thread
//    than the one running 'SRPListener::run()'.  So for a traditional single-
//    threaded program this method is of little value.
Port
SRPListener::getPort() const {
    if (listen_fd == -1) {
        return Port();
    }

    struct sockaddr_in sock_addr = {0};
    socklen_t addrlen = sizeof(sock_addr);
    auto sock_addr_alias = reinterpret_cast<struct sockaddr*>(&sock_addr);

    if (-1 == getsockname(listen_fd, sock_addr_alias, &addrlen)) {
        return Port();
    }

    return Port(ntohs(sock_addr.sin_port));
}

void
SRPListener::run() {
    shutdownFd.bind(poller);
    reactor_.run();

    for (;;) {
        std::vector<Polling::Event> events;
        int ready_fds = poller.poll(events);

        if (ready_fds == -1) {
            if (errno == EINTR && g_listen_fd == -1) return;
            throw Error::system("Polling");
        }
        for (const auto& event: events) {
            if (event.tag == shutdownFd.tag())
                return;

            if (event.flags.hasFlag(Polling::NotifyOn::Read)) {
                auto fd = event.tag.value();
                if (static_cast<ssize_t>(fd) == listen_fd) {
                    try {
                        handleNewConnection();
                    }
                    catch (SocketError& ex) {
                        std::cerr << "Server: " << ex.what() << std::endl;
                    }
                    catch (ServerError& ex) {
                        std::cerr << "Server: " << ex.what() << std::endl;
                        throw;
                    }
                }
            }
        }
    }
}

void
SRPListener::runThreaded() {
    acceptThread = std::thread([=]() { this->run(); });
}

void
SRPListener::shutdown() {
    if (shutdownFd.isBound()) shutdownFd.notify();
    reactor_.shutdown();
}

Async::Promise<SRPListener::Load>
SRPListener::requestLoad(const SRPListener::Load& old) {
    auto handlers = reactor_.handlers(transportKey);

    std::vector<Async::Promise<rusage>> loads;
    for (const auto& handler: handlers) {
        auto transport = std::static_pointer_cast<Transport>(handler);
        loads.push_back(transport->load());
    }

    return Async::whenAll(std::begin(loads), std::end(loads)).then([=](const std::vector<rusage>& usages) {

        Load res;
        res.raw = usages;

        if (old.raw.empty()) {
            res.global = 0.0;
            for (size_t i = 0; i < handlers.size(); ++i) res.workers.push_back(0.0);
        } else {

            auto totalElapsed = [](rusage usage) {
                return (usage.ru_stime.tv_sec * 1e6 + usage.ru_stime.tv_usec)
                     + (usage.ru_utime.tv_sec * 1e6 + usage.ru_utime.tv_usec);
            };

            auto now = std::chrono::system_clock::now();
            auto diff = now - old.tick;
            auto tick = std::chrono::duration_cast<std::chrono::microseconds>(diff);
            res.tick = now;

            for (size_t i = 0; i < usages.size(); ++i) {
                auto last = old.raw[i];
                const auto& usage = usages[i];

                auto nowElapsed = totalElapsed(usage);
                auto timeElapsed = nowElapsed - totalElapsed(last);

                auto loadPct = (timeElapsed * 100.0) / tick.count();
                res.workers.push_back(loadPct);
                res.global += loadPct;

            }

            res.global /= usages.size();
        }

        return res;

     }, Async::Throw);
}

Address
SRPListener::address() const {
    return addr_;
}

Options
SRPListener::options() const {
    return options_;
}

void SRPListener::handleNewConnection()
{
    struct sockaddr_in peer_addr;
    int client_fd = acceptConnection(peer_addr);

#ifdef PISTACHE_SSL_GNUTLS
    gnutls_session_t *session;
    if( this->useSSL_ ){
        // Preconfigure the TLS session before passing to the Peer class
        gnutls_init( session, GNUTLS_SERVER );
        // TODO: Allow setting custom priorities for a universal SSL implementation
        gnutls_priority_set_direct(
            *session,
            "NORMAL:+SRP:+SRP-DSS:+SRP-RSA",
            NULL
        );
        // "NORMAL:-KX-ALL:+SRP:+SRP-DSS:+SRP-RSA",
        // TODO: Add support for requesting a certificate from the client
        // But for now disable it
        gnutls_certificate_server_set_request( *session, GNUTLS_CERT_IGNORE );

        // Assign TLS credentials
        gnutls_credentials_set( *session, GNUTLS_CRD_CERTIFICATE, cert_cred );
        gnutls_credentials_set( *session, GNUTLS_CRD_SRP, srp_cred );
    }
#endif /* PISTACHE_SSL_GNUTLS */

    make_non_blocking(client_fd);

    auto peer = std::make_shared<SRPPeer>(Address::fromUnix((struct sockaddr *)&peer_addr));
    peer->associateFd(client_fd);

    printf("1: %d\n", client_fd);
    printf("2: %d\n", peer->fd());

#ifdef PISTACHE_SSL_GNUTLS
    if( this->useSSL_ ){
        peer->initTLSSession( session );
    }
#endif /* PISTACHE_SSL_GNUTLS */

    dispatchPeer(peer);
}

int SRPListener::acceptConnection(struct sockaddr_in& peer_addr) const
{
    socklen_t peer_addr_len = sizeof(peer_addr);
    int client_fd = ::accept(listen_fd, (struct sockaddr *)&peer_addr, &peer_addr_len);
    if (client_fd < 0) {
        if (errno == EBADF || errno == ENOTSOCK)
            throw ServerError(strerror(errno));
        else
            throw SocketError(strerror(errno));
    }
    return client_fd;
}

void
SRPListener::dispatchPeer(const std::shared_ptr<SRPPeer>& peer) {
    auto handlers = reactor_.handlers(transportKey);
    auto idx = peer->fd() % handlers.size();
    printf("3: %d\n", peer->fd());
    auto transport = std::static_pointer_cast<Transport>(handlers[idx]);

    transport->handleNewPeer(peer);

}

#ifdef PISTACHE_SSL_GNUTLS

// static SSL_CTX *ssl_create_context(const std::string &cert, const std::string &key, bool use_compression)
// {
//     const SSL_METHOD    *method;
//     SSL_CTX             *ctx;
//
//     method = SSLv23_server_method();
//
//     ctx = SSL_CTX_new(method);
//     if (ctx == NULL) {
//         ERR_print_errors_fp(stderr);
//         throw std::runtime_error("Cannot setup SSL context");
//     }
//
//     if (!use_compression) {
//         /* Disable compression to prevent BREACH and CRIME vulnerabilities. */
//         if (!SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION)) {
//             ERR_print_errors_fp(stderr);
//             throw std::runtime_error("Cannot disable compression");
//         }
//     }
//
//     /* Function introduced in 1.0.2 */
// #if OPENSSL_VERSION_NUMBER >= 0x10002000L
//     SSL_CTX_set_ecdh_auto(ctx, 1);
// #endif /* OPENSSL_VERSION_NUMBER */
//
//     if (SSL_CTX_use_certificate_file(ctx, cert.c_str(), SSL_FILETYPE_PEM) <= 0) {
//         ERR_print_errors_fp(stderr);
//         throw std::runtime_error("Cannot load SSL certificate");
//     }
//
//     if (SSL_CTX_use_PrivateKey_file(ctx, key.c_str(), SSL_FILETYPE_PEM) <= 0) {
//         ERR_print_errors_fp(stderr);
//         throw std::runtime_error("Cannot load SSL private key");
//     }
//
//     if (!SSL_CTX_check_private_key(ctx)) {
//         ERR_print_errors_fp(stderr);
//         throw std::runtime_error("Private key does not match public key in the certificate");
//     }
//
//     return ctx;
// }

// void
// SRPListener::setupSSLAuth(const std::string &ca_file, const std::string &ca_path, int (*cb)(int, void *) = NULL)
// {
//     const char *__ca_file = NULL;
//     const char *__ca_path = NULL;
//
//     if (this->ssl_ctx_ == NULL)
//         throw std::runtime_error("SSL Context is not initialized");
//
//     if (!ca_file.empty())
//         __ca_file = ca_file.c_str();
//     if (!ca_path.empty())
//         __ca_path = ca_path.c_str();
//
//     if (SSL_CTX_load_verify_locations((SSL_CTX *)this->ssl_ctx_, __ca_file, __ca_path) <= 0) {
//         ERR_print_errors_fp(stderr);
//         throw std::runtime_error("Cannot verify SSL locations");
//     }
//
//     SSL_CTX_set_verify((SSL_CTX *)this->ssl_ctx_,
//         SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_CLIENT_ONCE,
//         /* Callback type did change in 1.0.1 */
// #if OPENSSL_VERSION_NUMBER < 0x10100000L
//         (int (*)(int, X509_STORE_CTX *))cb
// #else
//         (SSL_verify_cb)cb
// #endif /* OPENSSL_VERSION_NUMBER */
//     );
// }

void
SRPListener::setupSSL( const char* cert_path,  const char* key_path, bool use_compression )
{
    // Verify an apropriate GnuTLS version is available with SRP support
    if( gnutls_check_version( "3.3.0" ) == NULL )
        throw std::runtime_error( "GnuTLS 3.3.0 or later is required." );

    gnutls_srp_allocate_server_credentials( &srp_cred );
    // gnutls_srp_set_server_credentials_file( srp_cred, "tpasswd", "tpasswd.conf" );
    gnutls_srp_set_server_credentials_function( srp_cred, credentials_lookup );

    gnutls_certificate_allocate_credentials( &cert_cred );
    // gnutls_certificate_set_x509_trust_file( cert_cred, CAFILE, GNUTLS_X509_FMT_PEM );
    gnutls_certificate_set_x509_key_file( cert_cred, cert_path, key_path, GNUTLS_X509_FMT_PEM );
}

#endif /* PISTACHE_SSL_GNUTLS */

} // namespace Tcp
} // namespace Pistache
