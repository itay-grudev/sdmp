#define KEYFILE "bin/server.key"
#define CERTFILE "bin/server.crt"
#define CAFILE "/etc/ssl/certs/ca-certificates.crt"

#include "private_api.h"

using namespace Pistache;

// Format: _binary_underscored_path_(start|end|size)
// Example: _binary_src_static_index_html_size
extern uint8_t index_html_start[] asm("_binary_src_static_index_html_start");
extern uint8_t index_html_end[]   asm("_binary_src_static_index_html_end");

extern uint8_t status_json_start[] asm("_binary_src_static_status_json_start");
extern uint8_t status_json_end[]   asm("_binary_src_static_status_json_end");

extern uint8_t not_found_json_start[] asm("_binary_src_static_not_found_json_start");
extern uint8_t not_found_json_end[]   asm("_binary_src_static_not_found_json_end");

inline char* char_array( uint8_t *input_start, uint8_t *input_end ){
    char* output = (char*)malloc( input_end - input_start + 1 ); // +1x\0
    memcpy( output, input_start, input_end - input_start);
    output[input_end - input_start] = '\0';
    return output;
}

PrivateApi::PrivateApi( Address addr )
    : srpEndpoint( std::make_shared<Http::Endpoint>( addr ) )
{
    index_html = char_array( index_html_start, index_html_end );
    status_json = char_array( status_json_start, status_json_end );
    not_found_json = char_array( not_found_json_start, not_found_json_end );
    printf("PrivateApi ssl on\n" );
}

PrivateApi::~PrivateApi()
{
    stop();
    free( index_html );
    free( status_json );
    free( not_found_json );
}

void PrivateApi::init( uint8_t thread_count ){
    auto options = Http::Endpoint::options()
        .threads( thread_count );
    srpEndpoint->init( options );
    srpEndpoint->useSSL( CERTFILE, KEYFILE, false );
    setupRoutes();
}

void PrivateApi::start(){
    srpEndpoint->setHandler( router.handler() );
    srpEndpoint->serve();
}

void PrivateApi::startThreaded(){
    srpEndpoint->setHandler( router.handler() );
    srpEndpoint->serveThreaded();
}

void PrivateApi::stop(){
    srpEndpoint->shutdown();
}

void PrivateApi::setupRoutes(){
    using namespace Rest;

    Routes::Get( router, "/", Routes::bind( &PrivateApi::index, this ));
    Routes::Get( router, "/api/status", Routes::bind( &PrivateApi::status, this ));
    Routes::Post( router, "/api/sign_up", Routes::bind( &PrivateApi::sign_up, this ));
    Routes::NotFound( router, Routes::bind( &PrivateApi::not_found, this ));
}

void PrivateApi::index( const Pistache::Rest::Request &request, Pistache::Http::ResponseWriter response ){
    response.send(Http::Code::Ok, index_html );
}

void PrivateApi::status( const Pistache::Rest::Request &request, Pistache::Http::ResponseWriter response ){
    response.send(Http::Code::Ok, status_json );
}

void PrivateApi::sign_up( const Pistache::Rest::Request &request, Pistache::Http::ResponseWriter response ){
    // TODO:
    response.send(Http::Code::Ok, status_json );
}

void PrivateApi::not_found( const Pistache::Rest::Request &request, Pistache::Http::ResponseWriter response ){
    response.send(Http::Code::Not_Found, not_found_json );
}
