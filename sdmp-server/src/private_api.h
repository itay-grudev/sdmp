#ifndef PRIVATE_API_H
#define PRIVATE_API_H

#include <pistache/http.h>
#include <pistache/router.h>
#include <pistache/endpoint.h>

class PrivateApi {
public:
    PrivateApi( Pistache::Address addr );
    ~PrivateApi();

    void init( uint8_t thread_count = 2 );
    void start();
    void startThreaded();
    void stop();

private:
    void setupRoutes();
    void index( const Pistache::Rest::Request&, Pistache::Http::ResponseWriter );
    void status( const Pistache::Rest::Request&, Pistache::Http::ResponseWriter );
    void sign_up( const Pistache::Rest::Request&, Pistache::Http::ResponseWriter );
    void not_found( const Pistache::Rest::Request&, Pistache::Http::ResponseWriter );

    std::shared_ptr <Pistache::Http::Endpoint> srpEndpoint;
    Pistache::Rest::Router router;
    Pistache::Address addr;
    char* index_html;
    char* status_json;
    char* not_found_json;

    // HTTP_PROTOTYPE( RegistrationHandler )
    // void onRequest( const Pistache::Http::Request&, Pistache::Http::ResponseWriter );
};


#endif // PRIVATE_API_H
