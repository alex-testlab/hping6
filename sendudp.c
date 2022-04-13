/* 
 * $smu-mark$ 
 * $name: sendudp.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:49 MET 1999$ 
 * $rev: 8$ 
 */ 

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>

#include "hping2.h"
#include "globals.h"

/* void hexdumper(unsigned char *packet, int size); */

void send_udp(void)
{
	int			packet_size;
	char			*packet, *data;
	struct myudphdr		*udp;
	struct pseudohdr *pseudoheader;
	struct pseudohdr6 *pseudoheader6;
	int			pslen;

	if(opt_ipv6)
		pslen = PSEUDOHDR6_SIZE;
	else
		pslen = PSEUDOHDR_SIZE;

	packet_size = UDPHDR_SIZE + data_size;
	packet = malloc(pslen + packet_size);
	if (packet == NULL) {
		perror("[send_udphdr] malloc()");
		return;
	}
	pseudoheader = (struct pseudohdr*) packet;
	pseudoheader6 = (struct pseudohdr6*) packet;
	udp =  (struct myudphdr*) (packet+pslen);
	data = (char*) (packet+pslen+UDPHDR_SIZE);
	
	memset(packet, 0, pslen+packet_size);

	/* udp pseudo header */
	if(opt_ipv6)
	{
		memcpy(&pseudoheader6->saddr, &ADDR6(&local).s6_addr, 16);
		memcpy(&pseudoheader6->daddr, &ADDR6(&remote).s6_addr, 16);
		pseudoheader6->protocol		= IPPROTO_UDP;
		pseudoheader6->lenght		= htons(packet_size);
	}
	else
	{
		memcpy(&pseudoheader->saddr, &ADDR4(&local).s_addr, 4);
		memcpy(&pseudoheader->daddr, &ADDR4(&remote).s_addr, 4);
		pseudoheader->protocol		= IPPROTO_UDP;
		pseudoheader->lenght		= htons(packet_size);
	}

	/* udp header */
	udp->uh_dport	= htons(dst_port);
	udp->uh_sport	= htons(src_port);
	udp->uh_ulen	= htons(packet_size);

	/* data */
	data_handler(data, data_size);

	/* compute checksum */
#ifdef STUPID_SOLARIS_CHECKSUM_BUG
	udp->uh_sum = packet_size;
#else
	udp->uh_sum = cksum((__u16*) packet, pslen + packet_size);
#endif

	/* adds this pkt in delaytable */
	delaytable_add(sequence, src_port, time(NULL), get_usec(), S_SENT);

	/* send packet */
	send_ip_handler(packet+pslen, packet_size);
	free(packet);

	sequence++;	/* next sequence number */

	if (!opt_keepstill)
		src_port = (sequence + initsport) % 65536;

	if (opt_force_incdport)
		dst_port++;
}
