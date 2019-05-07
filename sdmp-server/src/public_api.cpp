#include "public_api.h"

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

PublicApi::PublicApi( Address addr )
    : httpEndpoint( std::make_shared<Http::Endpoint>( addr ) )
{
    index_html = char_array( index_html_start, index_html_end );
    status_json = char_array( status_json_start, status_json_end );
    not_found_json = char_array( not_found_json_start, not_found_json_end );
}

PublicApi::~PublicApi()
{
    stop();
    free( index_html );
    free( status_json );
    free( not_found_json );
}

void PublicApi::init( uint8_t thread_count ){
    auto options = Http::Endpoint::options()
        .threads( thread_count );
    httpEndpoint->init( options );
    setupRoutes();
}

void PublicApi::start(){
    httpEndpoint->setHandler( router.handler() );
    httpEndpoint->serveThreaded();
}

void PublicApi::stop(){
    httpEndpoint->shutdown();
}

void PublicApi::setupRoutes(){
    using namespace Rest;

    Routes::Get( router, "/", Routes::bind( &PublicApi::index, this ));
    Routes::Get( router, "/api/status", Routes::bind( &PublicApi::status, this ));
    Routes::Post( router, "/api/sign_up", Routes::bind( &PublicApi::sign_up, this ));
    Routes::NotFound( router, Routes::bind( &PublicApi::not_found, this ));
}

void PublicApi::index( const Pistache::Rest::Request &request, Pistache::Http::ResponseWriter response ){
    response.send(Http::Code::Ok, index_html );
}

void PublicApi::status( const Pistache::Rest::Request &request, Pistache::Http::ResponseWriter response ){
    response.send(Http::Code::Ok, status_json );
}

void PublicApi::sign_up( const Pistache::Rest::Request &request, Pistache::Http::ResponseWriter response ){
    // TODO:
    response.send(Http::Code::Ok, status_json );
}

void PublicApi::not_found( const Pistache::Rest::Request &request, Pistache::Http::ResponseWriter response ){
    response.send(Http::Code::Not_Found, not_found_json );
}
