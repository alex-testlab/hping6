/* 
 * $smu-mark$ 
 * $name: sendip6.c$ 
 * $author: Matyas Koszik <koszik@atw.hu>$ 
 * $copyright: Copyright (C) 2006 by Matyas Koszik$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Sun Apr 16 05:18:30 CEST 2006$
 * $rev: 1$ 
 */ 

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "hping2.h"
#include "globals.h"

void send_ip6 (char *src, char *dst, char *data, unsigned int datalen)
{
	char		*packet;
	int		result,
			packetsize;
	struct myip6hdr	*ip6;

	packetsize = IP6HDR_SIZE + datalen;
	if ( (packet = malloc(packetsize)) == NULL) {
		perror("[send_ip] malloc()");
		return;
	}

	memset(packet, 0, packetsize);
	ip6 = (struct myip6hdr*) packet;

	/* copy src and dst address */
	memcpy(ip6->saddr, src, sizeof(ip6->saddr));
	memcpy(ip6->daddr, dst, sizeof(ip6->daddr));

	/* build ip header */
	ip6->version	= 6;
//	ip->tos		= ip_tos;

#if defined OSTYPE_FREEBSD || defined OSTYPE_NETBSD || defined OSTYPE_BSDI
/* FreeBSD */
/* NetBSD */
	ip6->paylen	= datalen;
#else
/* Linux */
/* OpenBSD */
	ip6->paylen	= htons(datalen);
#endif

	ip6->hoplimit	= src_ttl;
	if (opt_rawipmode)	ip6->nextheader = raw_ip_protocol;
	else if	(opt_icmpmode)	ip6->nextheader = 58;	/* icmp */
	else if (opt_udpmode)	ip6->nextheader = 17;	/* udp  */
	else			ip6->nextheader = 6;	/* tcp  */

	/* copies data */
	memcpy(packet + IP6HDR_SIZE, data, datalen);
	
    if (opt_debug == TRUE)
    {
        unsigned int i;

        for (i=0; i<packetsize; i++)
            printf("%.2X ", packet[i]&255);
        printf("\n");
    }
	result = sendto(sockraw, packet, packetsize, 0,
		(struct sockaddr*)&remote, sizeof(remote));
	
	if (result == -1 && errno != EINTR && !opt_rand_dest && !opt_rand_source) {
		perror("[send_ip6] sendto");
		if (close(sockraw) == -1)
			perror("[ipsender] close(sockraw)");
#if (!defined OSTYPE_LINUX) || (defined FORCE_LIBPCAP)
		if (close_pcap() == -1)
			printf("[ipsender] close_pcap failed\n");
#else
		if (close_sockpacket(sockpacket) == -1)
			perror("[ipsender] close(sockpacket)");
#endif /* ! OSTYPE_LINUX || FORCE_LIBPCAP */
		exit(1);
	}

	free(packet);

	sum_bytes += packetsize;
	sum_packets++;
}
