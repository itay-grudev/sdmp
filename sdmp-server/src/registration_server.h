#ifndef REGISTRATION_SERVRER_H
#define REGISTRATION_SERVRER_H

#include <pistache/endpoint.h>

class RegistrationHandler : public Pistache::Http::Handler {
public:
    HTTP_PROTOTYPE( RegistrationHandler )
    void onRequest( const Pistache::Http::Request&, Pistache::Http::ResponseWriter );
};


#endif // REGISTRATION_SERVRER_H
