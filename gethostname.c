/* 
 * $smu-mark$ 
 * $name: gethostname.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:47 MET 1999$ 
 * $rev: 8$ 
 */ 

#include <stdio.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "hping2.h"
#include "globals.h"

size_t strlcpy(char *dst, const char *src, size_t siz);

char *get_hostname(const char* addr)
{
	static char answer[1024];
	static char lastreq[1024] = {'\0'};	/* last request */
	struct hostent *he;
	struct in6_addr naddr6;
	static char *last_answerp = NULL;

	printf(" get hostname..."); fflush(stdout);
	printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b"
		"               "
		"\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");

	if (!strcmp(addr, lastreq))
		return last_answerp;

	strlcpy(lastreq, addr, 1024);
	inet_pton(opt_af, addr, &naddr6);
	he = gethostbyaddr((char*)&naddr6, sizeof(naddr6), opt_af);

	if (he == NULL) {
		last_answerp = NULL;
		return NULL;
	}

	strlcpy(answer, he->h_name, 1024);
	last_answerp = answer;

	return answer;
}

