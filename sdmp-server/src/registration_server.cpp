#include "registration_server.h"

using namespace Pistache;

void RegistrationHandler::onRequest(const Http::Request& request, Http::ResponseWriter response) {
     response.send(Http::Code::Ok, "Hello, World");
}
