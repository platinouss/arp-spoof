#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "getmac.h"

#define MAC_ALEN 6

int GetMacAddress(const char *dev, uint8_t *mac_addr) {
    struct ifreq ifr;
    int sockfd, ret;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0) {
        printf("Fail to get MAC Address");
        return -1;
    }

    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if(ret < 0) {
        printf("Fail to get Mac Address");
        close(sockfd);
        return -1;
    }

    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, MAC_ALEN);
    close(sockfd);

    return 0;
}
