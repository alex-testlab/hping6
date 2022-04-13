/* 
 * $smu-mark$ 
 * $name: sendtcp.c$ 
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

void send_tcp(void)
{
	int			packet_size;
	int			tcp_opt_size = 0;
	char			*packet, *data;
	struct mytcphdr		*tcp;
	struct pseudohdr	*pseudoheader;
	struct pseudohdr6	*pseudoheader6;
	unsigned char		*tstamp;
	int			pslen;

	if (opt_tcp_timestamp)
		tcp_opt_size = 12;

	if(opt_ipv6)
		pslen = PSEUDOHDR6_SIZE;
	else
		pslen = PSEUDOHDR_SIZE;

	packet_size = TCPHDR_SIZE + tcp_opt_size + data_size;
	packet = malloc(pslen + packet_size);
	if (packet == NULL) {
		perror("[send_tcphdr] malloc()");
		return;
	}
	pseudoheader = (struct pseudohdr*) packet;
	pseudoheader6 = (struct pseudohdr6*) packet;
	tcp =  (struct mytcphdr*) (packet+pslen);
	tstamp = (unsigned char*) (packet+pslen+TCPHDR_SIZE);
	data = (char*) (packet+pslen+TCPHDR_SIZE+tcp_opt_size);
	
	memset(packet, 0, pslen+packet_size);

	/* tcp pseudo header */
	if(opt_ipv6)
	{
		memcpy(&pseudoheader6->saddr, &ADDR6(&local).s6_addr, 16);
		memcpy(&pseudoheader6->daddr, &ADDR6(&remote).s6_addr, 16);
		pseudoheader6->protocol		= IPPROTO_TCP;
		pseudoheader6->lenght		= htons(packet_size);
	}
	else
	{
		memcpy(&pseudoheader->saddr, &ADDR4(&local).s_addr, 4);
		memcpy(&pseudoheader->daddr, &ADDR4(&remote).s_addr, 4);
		pseudoheader->protocol		= IPPROTO_TCP;
		pseudoheader->lenght		= htons(packet_size);
	}

	/* tcp header */
	tcp->th_dport	= htons(dst_port);
	tcp->th_sport	= htons(src_port);

	/* sequence number and ack are random if not set */
	tcp->th_seq = (set_seqnum) ? htonl(tcp_seqnum) : htonl(rand());
	tcp->th_ack = (set_ack) ? htonl(tcp_ack) : htonl(rand());

	tcp->th_off	= src_thoff + (tcp_opt_size >> 2);
	tcp->th_win	= htons(src_winsize);
	tcp->th_flags	= tcp_th_flags;

	/* tcp timestamp option */
	if (opt_tcp_timestamp) {
		__u32 randts = rand() ^ (rand() << 16);
		tstamp[0] = tstamp[1] = 1; /* NOOP */
		tstamp[2] = 8;
		tstamp[3] = 10; /* 10 bytes, kind+len+T1+T2 */
		memcpy(tstamp+4, &randts, 4); /* random */
		memset(tstamp+8, 0, 4); /* zero */
	}

	/* data */
	data_handler(data, data_size);

	/* compute checksum */
#ifdef STUPID_SOLARIS_CHECKSUM_BUG
	tcp->th_sum = packet_size;
#else
	tcp->th_sum = cksum((u_short*) packet, pslen + packet_size);
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
