/* 
 * $smu-mark$ 
 * $name: sendicmp6.c$ 
 * $author: Matyas Koszik <koszik@atw.hu>$
 * $copyright: Copyright (C) 2006 by Matyas Koszik$
 * $license: This software is under GPL version 2 of license$
 * $date: Sun Apr 16 05:51:38 CEST 2006$
 * $rev: 1$
 */ 


#include <sys/types.h> /* this should be not needed, but ip_icmp.h lacks it */
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <time.h>

#include "hping2.h"
#include "globals.h"

static int _icmp_seq = 0;

static void send_icmp6_echo(void);
static void send_icmp_other(void);

void send_icmp6(void)
{
	switch(opt_icmptype)
	{
		case ICMP6_ECHO:		/* type 128 */
		case ICMP6_ECHOREPLY:		/* type 129 */
			send_icmp6_echo();
			break;
		case ICMP6_DEST_UNREACH:	/* type 1 */
		case ICMP6_PACK_TOOBIG:		/* type 2 */
		case ICMP6_TIME_EXCEEDED:	/* type 3 */
		case ICMP6_PARAMETERPROB:	/* type 4 */
			send_icmp_other();
			break;
		default:
			if (opt_force_icmp) {
			    send_icmp_other();
			    break;
			} else {
			    printf("[send_icmp6] Unsupported icmp type %i!\n", opt_icmptype);
			    exit(1);
			}
	}
}

static void send_icmp6_echo(void)
{
	char *packet, *data;
	struct myicmphdr *icmp;
	struct pseudohdr6 *pseudoheader6;

	packet = malloc(PSEUDOHDR6_SIZE + ICMPHDR_SIZE + data_size);
	if (packet == NULL) {
		perror("[send_icmp] malloc");
		return;
	}

	memset(packet, 0, PSEUDOHDR6_SIZE + ICMPHDR_SIZE + data_size);

	icmp = (struct myicmphdr*)(packet + PSEUDOHDR6_SIZE);
	data = packet + PSEUDOHDR6_SIZE + ICMPHDR_SIZE;

	/* fill icmp hdr */
	icmp->type = opt_icmptype;	/* echo replay or echo request */
	icmp->code = opt_icmpcode;	/* should be indifferent */
	icmp->checksum = 0;
	icmp->un.echo.id = getpid() & 0xffff;
	icmp->un.echo.sequence = _icmp_seq;

	/* data */
	data_handler(data, data_size);

	pseudoheader6 = (struct pseudohdr6*)packet;
	memcpy(&pseudoheader6->saddr, &ADDR6(&local).s6_addr, 16);
	memcpy(&pseudoheader6->daddr, &ADDR6(&remote).s6_addr, 16);
	pseudoheader6->protocol		= 58;
	pseudoheader6->lenght		= htons(ICMPHDR_SIZE + data_size);

	/* icmp checksum */
	if (icmp_cksum == -1)
		icmp->checksum = cksum((u_short*)packet, ICMPHDR_SIZE + data_size + PSEUDOHDR6_SIZE);
	else
		icmp->checksum = icmp_cksum;

	/* adds this pkt in delaytable */
	if (opt_icmptype == ICMP6_ECHO)
		delaytable_add(_icmp_seq, 0, time(NULL), get_usec(), S_SENT);

	/* send packet */
	send_ip_handler(packet + PSEUDOHDR6_SIZE, ICMPHDR_SIZE + data_size);
	free (packet);

	_icmp_seq++;
}



static void send_icmp_other(void)
{
	char *packet, *data, *ph_buf;
	struct myicmphdr *icmp;
	struct myiphdr icmp_ip;
	struct myudphdr *icmp_udp;
	int udp_data_len = 0;
	struct pseudohdr *pseudoheader;
	int left_space = IPHDR_SIZE + UDPHDR_SIZE + data_size;

	packet = malloc(ICMPHDR_SIZE + IPHDR_SIZE + UDPHDR_SIZE + data_size);
	ph_buf = malloc(PSEUDOHDR_SIZE + UDPHDR_SIZE + udp_data_len);
	if (packet == NULL || ph_buf == NULL) {
		perror("[send_icmp] malloc");
		return;
	}

	memset(packet, 0, ICMPHDR_SIZE + IPHDR_SIZE + UDPHDR_SIZE + data_size);
	memset(ph_buf, 0, PSEUDOHDR_SIZE + UDPHDR_SIZE + udp_data_len);

	icmp = (struct myicmphdr*) packet;
	data = packet + ICMPHDR_SIZE;
	pseudoheader = (struct pseudohdr *) ph_buf;
	icmp_udp = (struct myudphdr *) (ph_buf + PSEUDOHDR_SIZE);

	/* fill icmp hdr */
	icmp->type = opt_icmptype;	/* ICMP_TIME_EXCEEDED */
	icmp->code = opt_icmpcode;	/* should be 0 (TTL) or 1 (FRAGTIME) */
	icmp->checksum = 0;
	icmp->un.gateway = 0;	/* not used, MUST be 0 */

	/* concerned packet headers */
	/* IP header */
	icmp_ip.version  = icmp_ip_version;		/* 4 */
	icmp_ip.ihl      = icmp_ip_ihl;			/* IPHDR_SIZE >> 2 */
	icmp_ip.tos      = icmp_ip_tos;			/* 0 */
	icmp_ip.tot_len  = htons((icmp_ip_tot_len ? icmp_ip_tot_len : (icmp_ip_ihl<<2) + UDPHDR_SIZE + udp_data_len));
	icmp_ip.id       = htons(getpid() & 0xffff);
	icmp_ip.frag_off = 0;				/* 0 */
	icmp_ip.ttl      = 64;				/* 64 */
	icmp_ip.protocol = icmp_ip_protocol;		/* 6 (TCP) */
	icmp_ip.check	 = 0;
	memcpy(&icmp_ip.saddr, &icmp_ip_src.sin_addr.s_addr, 4);
	memcpy(&icmp_ip.daddr, &icmp_ip_dst.sin_addr.s_addr, 4);
	icmp_ip.check	 = cksum((__u16 *) &icmp_ip, IPHDR_SIZE);

	/* UDP header */
	memcpy(&pseudoheader->saddr, &icmp_ip_src.sin_addr.s_addr, 4);
	memcpy(&pseudoheader->daddr, &icmp_ip_dst.sin_addr.s_addr, 4);
	pseudoheader->protocol = icmp_ip.protocol;
	pseudoheader->lenght = icmp_ip.tot_len;
	icmp_udp->uh_sport = htons(icmp_ip_srcport);
	icmp_udp->uh_dport = htons(icmp_ip_dstport);
	icmp_udp->uh_ulen  = htons(UDPHDR_SIZE + udp_data_len);
	icmp_udp->uh_sum   = cksum((__u16 *) ph_buf, PSEUDOHDR_SIZE + UDPHDR_SIZE + udp_data_len);

	/* filling icmp body with concerned packet header */

	/* fill IP */
	if (left_space == 0) goto no_space_left;
	memcpy(packet+ICMPHDR_SIZE, &icmp_ip, left_space);
	left_space -= IPHDR_SIZE;
	data += IPHDR_SIZE;
	if (left_space <= 0) goto no_space_left;

	/* fill UDP */
	memcpy(packet+ICMPHDR_SIZE+IPHDR_SIZE, icmp_udp, left_space);
	left_space -= UDPHDR_SIZE;
	data += UDPHDR_SIZE;
	if (left_space <= 0) goto no_space_left;

	/* fill DATA */
	data_handler(data, left_space);
no_space_left:

	/* icmp checksum */
	if (icmp_cksum == -1)
		icmp->checksum = cksum((u_short*)packet, ICMPHDR_SIZE + IPHDR_SIZE + UDPHDR_SIZE + data_size);
	else
		icmp->checksum = icmp_cksum;

	/* send packet */
	send_ip_handler(packet, ICMPHDR_SIZE + IPHDR_SIZE + UDPHDR_SIZE + data_size);
	free (packet);
	free (ph_buf);
}
