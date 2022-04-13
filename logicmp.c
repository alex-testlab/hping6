/* 
 * $smu-mark$ 
 * $name: logicmp.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:48 MET 1999$ 
 * $rev: 8$ 
 */ 

#include <stdio.h>
#include <sys/types.h> /* this should be not needed, but ip_icmp.h lacks it */

#include "hping2.h"
#include "globals.h"

void log_icmp_timeexc(const char *src_addr, unsigned short icmp_code)
{
	switch(icmp_code) {
	case ICMP_EXC_TTL:
		printf("TTL 0 during transit from ip=%s", src_addr);
		break;
	case ICMP_EXC_FRAGTIME:
		printf("TTL 0 during reassembly from ip=%s", src_addr);
		break;
	}
	if (opt_gethost) {
		char *hostn;

		fflush(stdout);
		hostn = get_hostname(src_addr);
		printf("name=%s", (hostn) ? hostn : "UNKNOWN");
	}
}
		
void log_icmp_unreach(const char *src_addr, unsigned short icmp_code)
{
	static char* icmp_unreach_msg[]={
	"Network Unreachable",		/* code 0 */
	"Host Unreachable",		/* code 1 */
	"Protocol Unreachable",		/* code 2 */
	"Port Unreachable",		/* code 3 */
	"Fragmentation Needed/DF set",	/* code 4 */
	"Source Route failed",		/* code 5 */
	NULL,					/* code 6 */
	NULL,					/* code 7 */
	NULL,					/* code 8 */
	NULL,					/* code 9 */
	NULL,					/* code 10 */
	NULL,					/* code 11 */
	NULL,					/* code 12 */
	"Packet filtered",			/* code 13 */
	"Precedence violation",		/* code 14 */
	"precedence cut off"		/* code 15 */
	};
	
	if (icmp_code < 16 && icmp_unreach_msg[icmp_code] != NULL)
		printf("ICMP %s from ip=%s", icmp_unreach_msg[icmp_code], src_addr);
	else
		printf("ICMP Unreachable type=%d from ip=%s",
			icmp_code, src_addr);

	if (opt_gethost) {
		char *hostn;

		fflush(stdout);
		hostn = get_hostname(src_addr);
		printf("name=%s", (hostn) ? hostn : "UNKNOWN");
	}
	putchar('\n');
}

void log_icmp6_unreach(const char *src_addr, unsigned short icmp_code)
{
	static char* icmp_unreach_msg[]={
	"Network Unreachable",			/* code 0 */
	"Packet Filtered",			/* code 1 */
	"Unreachable type=2",			/* code 2 */
	"Address Unreachable",			/* code 3 */
	"Port Unreachable",			/* code 4 */
	};
	
	if (icmp_code < 5)
		printf("ICMP6 %s from ip=%s", icmp_unreach_msg[icmp_code], src_addr);
	else
		printf("ICMP6 Unreachable type=%d from ip=%s",
			icmp_code, src_addr);

	if (opt_gethost) {
		char *hostn;

		fflush(stdout);
		hostn = get_hostname(src_addr);
		printf("name=%s", (hostn) ? hostn : "UNKNOWN");
	}
	putchar('\n');
}

void log_icmp6_ptb(const char *src_addr, __u32 mtu)
{
	printf("ICMP6 Packet Too Big, MTU=%d from ip=%s",
		mtu, src_addr);

	if (opt_gethost) {
		char *hostn;

		fflush(stdout);
		hostn = get_hostname(src_addr);
		printf("name=%s", (hostn) ? hostn : "UNKNOWN");
	}
	putchar('\n');
}
