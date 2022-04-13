/* 
 * $smu-mark$ 
 * $name: sendudp.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:49 MET 1999$ 
 * $rev: 8$ 
 */ 

/* $Id: send.c,v 1.6 2003/08/01 14:53:08 antirez Exp $ */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include "hping2.h"
#include "globals.h"

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")
#endif

static void select_next_random_source(void)
{
	unsigned char ra[4];

	ra[0] = hp_rand() & 0xFF;
	ra[1] = hp_rand() & 0xFF;
	ra[2] = hp_rand() & 0xFF;
	ra[3] = hp_rand() & 0xFF;
	memcpy(&ADDR4(&local).s_addr, ra, 4);

	if (opt_debug)
		printf("DEBUG: the source address is %u.%u.%u.%u\n",
		    ra[0], ra[1], ra[2], ra[3]);
}

static void select_next_random_ipv6_source(void)
{	
	unsigned char ra[16];

	ra[0] = hp_rand() & 0xFF;
	ra[1] = hp_rand() & 0xFF;
	ra[2] = hp_rand() & 0xFF;
	ra[3] = hp_rand() & 0xFF;
	ra[4] = hp_rand() & 0xFF;
	ra[5] = hp_rand() & 0xFF;
	ra[6] = hp_rand() & 0xFF;
	ra[7] = hp_rand() & 0xFF;
	ra[8] = hp_rand() & 0xFF;
	ra[9] = hp_rand() & 0xFF;
	ra[10] = hp_rand() & 0xFF;
	ra[11] = hp_rand() & 0xFF;
	ra[12] = hp_rand() & 0xFF;
	ra[13] = hp_rand() & 0xFF;
	ra[14] = hp_rand() & 0xFF;
	ra[15] = hp_rand() & 0xFF;
	memcpy(&ADDR6(&local).s6_addr, ra, 16);

}

static void select_next_random_ipv6_dest(void)
{
	unsigned char ra[16];

	ra[0] = hp_rand() & 0xFF;
	ra[1] = hp_rand() & 0xFF;
	ra[2] = hp_rand() & 0xFF;
	ra[3] = hp_rand() & 0xFF;
	ra[4] = hp_rand() & 0xFF;
	ra[5] = hp_rand() & 0xFF;
	ra[6] = hp_rand() & 0xFF;
	ra[7] = hp_rand() & 0xFF;
	ra[8] = hp_rand() & 0xFF;
	ra[9] = hp_rand() & 0xFF;
	ra[10] = hp_rand() & 0xFF;
	ra[11] = hp_rand() & 0xFF;
	ra[12] = hp_rand() & 0xFF;
	ra[13] = hp_rand() & 0xFF;
	ra[14] = hp_rand() & 0xFF;
	ra[15] = hp_rand() & 0xFF;
	memcpy(&ADDR6(&remote).s6_addr, ra, 16);
}

static void select_next_random_ipv6_source_simple(void)
{	struct in6_addr rand6;

	rand6 = ipv6_rand("2200::",8);

	memcpy(&ADDR6(&local).s6_addr, rand6.s6_addr,16);

}

static void select_next_random_ipv6_dest_simple(void)
{
	struct in6_addr rand6;

	rand6 = ipv6_rand("2200::",8);

	memcpy(&ADDR6(&remote).s6_addr, rand6.s6_addr,16);
}

static void select_next_random_dest(void)
{
	unsigned char ra[4];
	char a[4], b[4], c[4], d[4];

	if (sscanf(targetname, "%4[^.].%4[^.].%4[^.].%4[^.]", a, b, c, d) != 4)
	{
		fprintf(stderr,
			"wrong --rand-dest target host, correct examples:\n"
			"  x.x.x.x, 192,168.x.x, 128.x.x.255\n"
			"you typed: %s\n", targetname);
		exit(1);
	}
	a[3] = b[3] = c[3] = d[3] = '\0';

	ra[0] = a[0] == 'x' ? (hp_rand() & 0xFF) : strtoul(a, NULL, 0);
	ra[1] = b[0] == 'x' ? (hp_rand() & 0xFF) : strtoul(b, NULL, 0);
	ra[2] = c[0] == 'x' ? (hp_rand() & 0xFF) : strtoul(c, NULL, 0);
	ra[3] = d[0] == 'x' ? (hp_rand() & 0xFF) : strtoul(d, NULL, 0);
	memcpy(&ADDR4(&remote).s_addr, ra, 4);

	if (opt_debug) {
		printf("DEBUG: the dest address is %u.%u.%u.%u\n",
				ra[0], ra[1], ra[2], ra[3]);
	}
}

long long sum_bytes;
unsigned int sum_packets;
/* The signal handler for SIGALRM will send the packets */
#define TDIFF(a,b) (((a).tv_usec - (b).tv_usec)/1000+((a).tv_sec - (b).tv_sec)*1000)
void send_packet (int signal_id)
{
	int errno_save = errno;
	struct timeval tv1, tv2;
	int lel = 0;

	gettimeofday(&tv1, NULL);
	do{
	if (opt_rand_dest){
		if(opt_ipv6) {
			select_next_random_ipv6_dest();
		} else {
			select_next_random_dest();
		}
	}
	if (opt_rand_source){
		if(opt_ipv6) {
			select_next_random_ipv6_source();
		} else {
			select_next_random_source();
		}
	}

	if (opt_rawipmode)	send_rawip();
	else if (opt_icmpmode){if(opt_ipv6)send_icmp6(); else send_icmp();}
	else if (opt_udpmode)	send_udp();
	else			send_tcp();

	sent_pkt++;
	if((opt_pps || opt_bps) && (sum_packets & 127) == 13)
	{
	    int el;

	    gettimeofday(&tv2, NULL);
	    el = TDIFF(tv2, tv1);
	    if(opt_bps)
	    {
		if(sum_bytes * 1000 / opt_bps > el)
		    usleep((sum_bytes * 1000 / opt_bps - el) * 1000);
	    }
	    else if(opt_pps)
	    {
		if(sum_packets * 1000 / opt_pps > el)
		    usleep((sum_packets * 1000 / opt_pps - el) * 1000);
	    }
	    if(el - lel > 100)
	    {
		    float bps, pps;
		    char *bpsc, *ppsc;

		    gettimeofday(&tv2, NULL);
		    el = TDIFF(tv2, tv1);
		    pps = (float)sum_packets*1000/el;
		    bps = (float)sum_bytes*8000/el;
		    bpsc = ppsc = "";
		    if(bps > 9999999999.0)
		    {
			bps /= 1000000000.0;
			bpsc = "G";
		    }
		    else if(bps > 9999999)
		    {
			bps /= 1000000;
			bpsc = "M";
		    }
		    else if(bps > 9999)
		    {
			bps /= 1000;
			bpsc = "k";
		    }

		    if(pps > 9999999)
		    {
			pps /= 1000000;
			ppsc = "M";
		    }
		    else if(pps > 9999)
		    {
			pps /= 1000;
			ppsc = "k";
		    }
		    
		    printf("\rt: %.2fs, %.1f %spps, %.1f %sbps    ", (float)el/1000.0, pps, ppsc, bps, bpsc);
		    fflush(stdout);
		    lel = el;
	    }
	}
	}while(opt_pps || opt_bps);
	Signal(SIGALRM, send_packet);

	if (count != -1 && count == sent_pkt) { /* count reached? */
		Signal(SIGALRM, print_statistics);
		alarm(COUNTREACHED_TIMEOUT);
	} else if (!opt_listenmode) {
		if (opt_waitinusec == FALSE)
			alarm(sending_wait);
		else
			setitimer(ITIMER_REAL, &usec_delay, NULL);
	}
	errno = errno_save;
}
