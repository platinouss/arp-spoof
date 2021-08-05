#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

int GetIpAddress(const char* dev, uint32_t ip_address)
{
 int fd;
 struct ifreq ifr;

 fd = socket(AF_INET, SOCK_DGRAM, 0);

 ifr.ifr_addr.sa_family = AF_INET;

 strncpy((char*)ifr.ifr_name, dev, IFNAMSIZ - 1);

 ioctl(fd, SIOCGIFADDR, &ifr);

 close(fd);

 ip_address = ntohl((((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr).s_addr);

 return ip_address;
}
