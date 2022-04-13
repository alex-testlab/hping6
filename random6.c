// vim:sw=4:ts=4:et:

/*
 * Copyright (C) 2021 Andrei Belov (@defanator on github)
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>


/* 16 octets in binary form + dots between octets + trailing zero */
#define INET6_ADDRBINSTRLEN ((8 * 16) + (1 * 15) + 1UL)

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")
#endif

char * sprintb(char *dst, void const * const ptr, size_t const size)
{
    int i, j;
    char *dp = dst;
    unsigned char byte;
    unsigned char *b = (unsigned char*) ptr;

    for (i = size - 1; i >= 0; i--) {
        for (j = 7; j >= 0; j--) {
            byte = (b[i] >> j) & 1;
            *dp++ = byte ? '1' : '0';
        }
    }

    *dp = 0x0;
    return dst;
}

char * sprintb_addr6(char *dst, struct in6_addr *in6) {
    char *dp = dst;
    u_char *p = in6->s6_addr;
    int i;

    for (i = 0; i < 16; i++) {
        sprintb(dp, &p[i], sizeof(u_char));
        dp += 8;
        if (i < 15) *dp++ = '.';
    }

    return dst;
}

struct in6_addr ipv6_rand(char *net,uint8_t prefixlen)
{
    int i, j, s;
    uint8_t bits, shift;
    u_char *addr, *mask;
    struct in6_addr addr6, mask6,rand6;
    //char straddr6[INET6_ADDRSTRLEN];
    //char binaddr6[INET6_ADDRBINSTRLEN];

    char *ip6net = net;

    if (inet_pton(AF_INET6, ip6net, &addr6) < 1) {
        printf("incorrect IPv6 address/net: \"%s\"\n", ip6net);
        exit(1);
    }

    addr = addr6.s6_addr;
    mask = mask6.s6_addr;
    shift = prefixlen;
    bits = 128 - shift;

    for (i = 0; i < 16; i++) {
        s = (shift > 8) ? 8 : shift;
        shift -= s;

        mask[i] = (u_char) (0xffu << (8 - s));

        if (addr[i] != (addr[i] & mask[i])) {
            addr[i] &= mask[i];
        }
    }


    //inet_ntop(AF_INET6, &addr6, straddr6, INET6_ADDRSTRLEN);
    //printf("network: %s/%d\n", straddr6, prefixlen);

    //inet_ntop(AF_INET6, &mask6, straddr6, INET6_ADDRSTRLEN);
    //printf("netmask: %s (free bits=%d)\n", straddr6, bits);

    //printf("%s\n", sprintb_addr6(binaddr6, &addr6));
    //printf("%s\n", sprintb_addr6(binaddr6, &mask6));
    //printf("----\n");

    srand(((unsigned) getpid() << 16) ^ time(NULL));

    uint32_t rv = rand();
    int k = 0;

    shift = bits;
    rand6 = addr6;
    addr = rand6.s6_addr;

    for (j = 15; j >= 0; j--) {
        s = (shift > 8) ? 8 : shift;
        shift -= s;

        addr[j] = addr[j] ^ ((addr[j] ^ rv) & ~mask[j]);

        if (shift == 0) break;

        rv >>= 8;

        /*
            * Note that the MSB of the first octet in random value rv
            * will always be 0 as RAND_MAX=0x7FFFFFFF, i.e. if we refresh
            * rv after using all the 4 octets from uint32_t, the leading
            * bit in octets 4, 8, 12, 16 in generated IPv6 address
            * will _always_ be 0.
            *
            * While it seems legit for e.g. ::ffff:0:0/96 (IPv4-mapped
            * addresses), there may be a better way of handling this
            * (e.g. refresh rv after using 3 of 4 octets or reverse
            * bits in first octet before applying).
            *
            */
        //if (++k > 2) {
        if (++k > 3) {
            rv = rand();
            k = 0;
        }
    }
    //inet_ntop(AF_INET6, &rand6, straddr6, INET6_ADDRSTRLEN);
    //printf("%s [%s]\n", sprintb_addr6(binaddr6, &rand6), straddr6);

    return rand6;
}