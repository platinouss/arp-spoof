#ifndef GETIP_H
#define GETIP_H
#include <netinet/in.h>



int GetIpAddress(const char* dev, uint32_t ip_address);

#endif // GETIP_H
