/* waitpacket.c -- handle and print the incoming packet
 * Copyright(C) 1999-2001 Salvatore Sanfilippo
 * Under GPL, see the COPYING file for more information about
 * the license. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>

#include "hping2.h"
#include "globals.h"

static int icmp_unreach_rtt(void *quoted_ip, int size,
			    int *seqp, float *ms_delay);
static void print_tcp_timestamp(void *tcp, int tcpsize);
static int recv_icmp(void *packet, size_t size);
static int recv_udp(void *packet, size_t size);
static int recv_tcp(void *packet, size_t size);
static void hex_dump(void *packet, int size);
static void human_dump(void *packet, int size);
static void handle_hcmp(char *packet, int size);

static struct myiphdr *ip;
static struct myip6hdr *ip6;
static int ip_size;
static struct in_addr src, dst;
static struct in6_addr src6, dst6;

static int handle_ipv4(char *ip_packet, int ip_size);
static int handle_ipv6(char *ip_packet, int ip_size);
static int icmp6_unreach_rtt(void *quoted_ip, int size, int *seqp, float *ms_delay);
static int icmp_unreach_rtt(void *quoted_ip, int size, int *seqp, float *ms_delay);

static int notrace;

void wait_packet(void)
{
	int match = 0;
	int size;
	char packet [IP_MAX_SIZE+linkhdr_size];
	char *ip_packet;

	size = read_packet(packet, IP_MAX_SIZE+linkhdr_size);
	switch(size) {
		case 0:
			return;
		case -1:
			exit(1);
	}

	/* Check if the packet is shorter than the link header size */
	if (size < linkhdr_size) {
		if (opt_debug)
			printf("DEBUG: WARNING: packet size(%i) < linkhdr_size(%i)\n",
					size, linkhdr_size);
		return;
	}

	/* IP packet pointer and len */
	ip_packet = packet + linkhdr_size;
	ip_size = size - linkhdr_size;

	/* Truncated IP header? */
	if ((!opt_ipv6 && ip_size < IPHDR_SIZE) ||
	    (opt_ipv6 && ip_size < IP6HDR_SIZE)) {
		if (opt_debug)
			printf("[|ip fix]\n");
		return;
	}

	ip = (struct myiphdr*)(packet+linkhdr_size);
	if(ip->version == 4 && !opt_ipv6)
		match = handle_ipv4(ip_packet, ip_size);
	else if(ip->version == 6 && opt_ipv6)
	{
		ip6 = (struct myip6hdr*)(packet+linkhdr_size);
		match = handle_ipv6(ip_packet, ip_size);
	}

	if (match)
		recv_pkt++;

	/* Dump the packet in hex */
	if (opt_hexdump && match && !opt_quiet)
		hex_dump(ip_packet, ip_size);

	/* Dump printable characters inside the packet */
	if (opt_contdump && match && !opt_quiet)
		human_dump(ip_packet, ip_size);

	/* Display IP options */
	if (match && opt_rroute && !opt_quiet && !opt_ipv6)
		display_ipopt(ip_packet);

	/* --tr-stop stops hping in traceroute mode when the
	 * first not ICMP time exceeded packet is received */
	if (opt_traceroute && opt_tr_stop && notrace)
		print_statistics(0);

	/* if the count was reached exit now */
	if (count != -1 && count == recv_pkt)
		print_statistics(0);
}

static int
handle_ipv4(char *ip_packet, int ip_size)
{
	int iphdr_size, enc_size;
	char *enc_packet;

	iphdr_size = ip->ihl * 4;

	/* Bad IP header len? */
	if (iphdr_size > ip_size) {
		if (opt_debug)
			printf("[|iphdr size]\n");
		return 0;
	}

	/* Handle the HCMP for almost safe file transfer with hping */
	if (opt_sign)
		handle_hcmp(ip_packet, ip_size);

	/* Check if the dest IP address is the one of our interface */
	if (memcmp(&ip->daddr, &ADDR4(&local), sizeof(ip->daddr)))
		return 0;
	/* If the packet isn't an ICMP error it should come from
	 * our target IP addresss. We accept packets from all the
	 * source if the random destination option is active */
	if (ip->protocol != IPPROTO_ICMP && !opt_rand_dest) {
		if (memcmp(&ip->saddr, &ADDR4(&remote), sizeof(ip->saddr)))
			return 0;
	}

	/* Get the encapsulated protocol offset and size */
	enc_packet = ip_packet + iphdr_size;
	enc_size = ip_size - iphdr_size;

	/* Put the IP source and dest addresses in a struct in_addr */
	memcpy(&src, &(ip->saddr), sizeof(struct in_addr));
	memcpy(&dst, &(ip->daddr), sizeof(struct in_addr));

	switch(ip->protocol) {
		case IPPROTO_ICMP:
			return recv_icmp(enc_packet, enc_size);
			break;
		case IPPROTO_UDP:
			return recv_udp(enc_packet, enc_size);
			break;
		case IPPROTO_TCP:
			return recv_tcp(enc_packet, enc_size);
			break;
		default:
			return 0;
	}

}

static int
handle_ipv6(char *ip_packet, int ip_size)
{
	int enc_size;
	char *enc_packet;

	/* Check if the dest IP address is the one of our interface */
	if (memcmp(ip6->daddr, &ADDR6(&local), 16))
		return 0;
	/* If the packet isn't an ICMP error it should come from
	 * our target IP addresss. We accept packets from all the
	 * source if the random destination option is active */
	if (ip6->nextheader != 58 && !opt_rand_dest) {
		if (memcmp(ip6->saddr, &ADDR6(&remote), 16))
			return 0;
	}

	/* Get the encapsulated protocol offset and size */
	enc_packet = ip_packet + sizeof(*ip6);
	enc_size = ip_size - sizeof(*ip6);

	/* Put the IP source and dest addresses in a struct in_addr */
	memcpy(&src6, ip6->saddr, sizeof(struct in6_addr));
	memcpy(&dst6, ip6->daddr, sizeof(struct in6_addr));

	switch(ip6->nextheader) {
		case 58:
			return recv_icmp6(enc_packet, enc_size);
			break;
		case IPPROTO_UDP:
			return recv_udp(enc_packet, enc_size);
			break;
		case IPPROTO_TCP:
			return recv_tcp(enc_packet, enc_size);
			break;
		default:
			printf("xx %i\n", ip6->nextheader);
	}
	return 0;
}

static void
log_ipv4(int status, int sequence)
{
	int rel_id, ip_id;

	/* get ip->id */
	if (opt_winid_order)
		ip_id = ip->id;
	else
		ip_id = htons(ip->id);

	if (opt_relid)
		rel_id = relativize_id(sequence, &ip_id);
	else
		rel_id = 0;
	printf("len=%d ip=%s ttl=%d %sid%s%d ", ip_size, inet_ntoa(src),
			ip->ttl,
			(ntohs(ip->frag_off) ? "DF " : ""),
			(rel_id ? "=+" : "="), ip_id);
	if (opt_verbose && !opt_quiet)
		printf("tos=%x iplen=%u\n", ip->tos, htons(ip->tot_len));
}

static void
log_ipv6(int status, int sequence)
{
	char tmp[1024];

	printf("len=%d ip=%s ttl=%d ", ip_size, inet_ntop(opt_af, &src6, tmp, sizeof(tmp)),
			ip6->hoplimit);
	if (opt_verbose && !opt_quiet)
		printf("tc=%x flowlabel=%u\n", (ip6->tc1 << 4) | ip6->tc2, (ip6->flowlabel1 << 16) | ip6->flowlabel2);
}

static void
log_ip(int status, int sequence)
{
	if(status == S_RECV)
		printf("DUP! ");
	if(ip->version == 4)
		log_ipv4(status, sequence);
	else
		log_ipv6(status, sequence);
}


void log_icmp_ts(void *ts)
{
	struct icmp_tstamp_data icmp_tstamp;

	memcpy(&icmp_tstamp, ts, sizeof(icmp_tstamp));
	printf("ICMP timestamp: Originate=%u Receive=%u Transmit=%u\n",
		(unsigned int) ntohl(icmp_tstamp.orig),
		(unsigned int) ntohl(icmp_tstamp.recv),
		(unsigned int) ntohl(icmp_tstamp.tran));
	printf("ICMP timestamp RTT tsrtt=%lu\n\n",
		(long unsigned int) (get_midnight_ut_ms() 
                                     - ntohl(icmp_tstamp.orig)));
}

void log_icmp_addr(void *addrptr)
{
	unsigned char *addr = addrptr;
	printf("ICMP address mask: icmpam=%u.%u.%u.%u\n\n",
       		addr[0], addr[1], addr[2], addr[3]);
}

void log_traceroute(void *packet, int size, int icmp_code)
{
	static __u8 old_src_addr[16];
	int sequence = 0, retval;
	float rtt;
	char tmp[1024];

	if (!opt_ipv6 && !opt_tr_keep_ttl && !memcmp(&ip->saddr, old_src_addr, 4))
		return;
	if (opt_ipv6 && !opt_tr_keep_ttl && !memcmp(&ip6->saddr, old_src_addr, 16))
		return;

	if(opt_ipv6)
	retval = icmp6_unreach_rtt(packet+ICMPHDR_SIZE, size-ICMPHDR_SIZE,
					&sequence, &rtt);
	else
	retval = icmp_unreach_rtt(packet+ICMPHDR_SIZE, size-ICMPHDR_SIZE,
					&sequence, &rtt);
	printf("hop=%d ", src_ttl);
	fflush(stdout);

	if(!opt_ipv6)
	{
		memcpy(old_src_addr, &ip->saddr, sizeof(ip->saddr));
		log_icmp_timeexc(inet_ntop(opt_af, &src, tmp, sizeof(tmp)), icmp_code);
	}
	else
	{
		memcpy(old_src_addr, ip6->saddr, sizeof(ip6->saddr));
		log_icmp_timeexc(inet_ntop(opt_af, &src6, tmp, sizeof(tmp)), icmp_code);
	}
	if (retval != -1)
		printf(" hoprtt=%.1f ms", rtt);
	if (!opt_tr_keep_ttl)
		src_ttl++;
	putchar('\n');
}

int recv_icmp(void *packet, size_t size)
{
	struct myicmphdr *icmp;
	struct myiphdr quoted_ip;

	/* Check if the packet can contain the ICMP header */
	if (size < ICMPHDR_SIZE) {
		printf("[|icmp]\n");
		return 0;
	}
	icmp = (struct myicmphdr *)packet;

	/* --------------------------- *
	 * ICMP ECHO/TIMESTAMP/ADDRESS *
	 * --------------------------- */
	if ((icmp->type == ICMP_ECHOREPLY  ||
	     icmp->type == ICMP_TIMESTAMPREPLY ||
	     icmp->type == ICMP_ADDRESSREPLY) &&
		icmp->un.echo.id == (getpid() & 0xffff))
	{
		int icmp_seq = icmp->un.echo.sequence;
		int status;
		float ms_delay;

		/* obtain round trip time */
		status = rtt(&icmp_seq, 0, &ms_delay);
		log_ip(status, icmp_seq);

		printf("icmp_seq=%d rtt=%.1f ms\n", icmp_seq, ms_delay);
		if (icmp->type == ICMP_TIMESTAMPREPLY) {
			if ((size - ICMPHDR_SIZE) >= 12)
				log_icmp_ts(packet+ICMPHDR_SIZE);
			else
				printf("[|icmp timestamp]\n");
		} else if (icmp->type == ICMP_ADDRESSREPLY) {
			if ((size - ICMPHDR_SIZE) >= 4)
				log_icmp_addr(packet+ICMPHDR_SIZE);
			else
				printf("[|icmp subnet address]\n");
		}
		notrace = 1;
		return 1;
	}
	/* ------------------------------------ *
	 * ICMP DEST UNREACHABLE, TIME EXCEEDED *
	 * ------------------------------------ */
	else if (icmp->type == 3 || icmp->type == 11) {
		if ((size - ICMPHDR_SIZE) < sizeof(struct myiphdr)) {
			printf("[|icmp quoted ip]\n");
			return 0;
		}
		memcpy(&quoted_ip, packet+ICMPHDR_SIZE, sizeof(quoted_ip));
		if (memcmp(&quoted_ip.daddr, &ADDR4(&remote),
			sizeof(quoted_ip.daddr)) ||
		    memcmp(&ip->daddr, &ADDR4(&local), sizeof(ip->daddr)))
			return 0; /* addresses don't match */
		/* Now we can handle the specific type */
		switch(icmp->type) {
		case 3:
			if (!opt_quiet)
				log_icmp_unreach(inet_ntoa(src), icmp->code);
			notrace = 1;
			return 1;
		case 11:
			if (opt_traceroute)
				log_traceroute(packet, size, icmp->code);
			else
			{
				log_icmp_timeexc(inet_ntoa(src), icmp->code);
				putchar('\n');
				notrace = 1;
			}
			return 1;
		}
	}

	return 0; /* don't match */
}

int recv_icmp6(void *packet, size_t size)
{
	struct myicmphdr *icmp;
	struct myip6hdr *quoted_ip;
	char tmp[1024];

	/* Check if the packet can contain the ICMP header */
	if (size < ICMPHDR_SIZE) {
		printf("[|icmp]\n");
		return 0;
	}
	icmp = (struct myicmphdr *)packet;

	/* --------------------------- *
	 * ICMP ECHO/TIMESTAMP/ADDRESS *
	 * --------------------------- */
	if (icmp->type == ICMP6_ECHOREPLY &&
		icmp->un.echo.id == (getpid() & 0xffff))
	{
		int icmp_seq = icmp->un.echo.sequence;
		int status;
		float ms_delay;

		/* obtain round trip time */
		status = rtt(&icmp_seq, 0, &ms_delay);
		log_ip(status, icmp_seq);

		printf("icmp_seq=%d rtt=%.1f ms\n", icmp_seq, ms_delay);
		notrace = 1;
		return 1;
	}
	/* ------------------------------------ *
	 * ICMP DEST UNREACHABLE, TIME EXCEEDED *
	 * ------------------------------------ */
	if ((size - ICMPHDR_SIZE) < sizeof(struct myip6hdr)) {
		printf("[|icmp quoted ip]\n");
		return 0;
	}
	quoted_ip = (struct myip6hdr *)(packet + ICMPHDR_SIZE);
	if(memcmp(quoted_ip->daddr, &ADDR6(&remote),
		sizeof(quoted_ip->daddr)) ||
	    memcmp(ip6->daddr, &ADDR6(&local), sizeof(ip6->daddr)))
		return 0; /* addresses don't match */
	/* Now we can handle the specific type */
	switch(icmp->type) {
	case 1:
		if (!opt_quiet)
			log_icmp6_unreach(inet_ntop(opt_af, &src6, tmp, sizeof(tmp)), icmp->code);
		notrace = 1;
		return 1;
	case 2:
		if (!opt_quiet)
			log_icmp6_ptb(inet_ntop(opt_af, &src6, tmp, sizeof(tmp)), ntohl(icmp->un.mtu));
		notrace = 1;
		return 1;
	case 3:
		if (opt_traceroute)
			log_traceroute(packet, size, icmp->code);
		else
		{
			log_icmp_timeexc(inet_ntop(opt_af, &src6, tmp, sizeof(tmp)), icmp->code);
			putchar('\n');
			notrace = 1;
		}
		return 1;
	}

	return 0; /* don't match */
}

int recv_udp(void *packet, size_t size)
{
	struct myudphdr udp;
	int sequence = 0, status;
	float ms_delay;

	if (size < UDPHDR_SIZE) {
		printf("[|udp]\n");
		return 0;
	}
	memcpy(&udp, packet, sizeof(udp));

	/* check if the packet matches */
	if ((ntohs(udp.uh_sport) == dst_port) ||
	    (opt_force_incdport &&
	     (ntohs(udp.uh_sport) >= base_dst_port &&
	      ntohs(udp.uh_sport) <= dst_port)))
	{
		status = rtt(&sequence, ntohs(udp.uh_dport), &ms_delay);
		if (!opt_quiet) {
			log_ip(status, sequence);
			printf("seq=%d rtt=%.1f ms\n", sequence, ms_delay);
		}
		if (opt_incdport && !opt_force_incdport)
			dst_port++;
		notrace = 1;
		return 1;
	}
	return 0;
}

int recv_tcp(void *packet, size_t size)
{
	struct mytcphdr tcp;
	int sequence = 0, status;
	float ms_delay;
	char flags[16];

	if (size < TCPHDR_SIZE) {
		printf("[|tcp]\n");
		return 0;
	}
	memcpy(&tcp, packet, sizeof(tcp));

	/* check if the packet matches */
	if ((ntohs(tcp.th_sport) == dst_port) ||
	    (opt_force_incdport &&
	     (ntohs(tcp.th_sport) >= base_dst_port &&
	      ntohs(tcp.th_sport) <= dst_port)))
	{
		tcp_exitcode = tcp.th_flags;

		status = rtt(&sequence, ntohs(tcp.th_dport), &ms_delay);

		if (opt_seqnum) {
			static __u32 old_th_seq = 0;
			__u32 seq_diff, tmp;

			tmp = ntohl(tcp.th_seq);
			if (tmp >= old_th_seq)
				seq_diff = tmp - old_th_seq;
			else
				seq_diff = (4294967295U - old_th_seq)
					+ tmp;
			old_th_seq = tmp;
			printf("%10lu +%lu\n",
				(unsigned long) tmp,
				(unsigned long) seq_diff);
			goto out;
		}

		if (opt_quiet)
			goto out;

		flags[0] = '\0';
		if (tcp.th_flags & TH_RST)  strcat(flags, "R");
		if (tcp.th_flags & TH_SYN)  strcat(flags, "S");
		if (tcp.th_flags & TH_ACK)  strcat(flags, "A");
		if (tcp.th_flags & TH_FIN)  strcat(flags, "F");
		if (tcp.th_flags & TH_PUSH) strcat(flags, "P");
		if (tcp.th_flags & TH_URG)  strcat(flags, "U");
		if (tcp.th_flags & TH_X)    strcat(flags, "X");
		if (tcp.th_flags & TH_Y)    strcat(flags, "Y");
		if (flags[0] == '\0')    strcat(flags, "none");

		log_ip(status, sequence);
		printf("sport=%d flags=%s seq=%d win=%d rtt=%.1f ms\n",
			ntohs(tcp.th_sport), flags, sequence,
			ntohs(tcp.th_win), ms_delay);

		if (opt_verbose) {
			printf("seq=%lu ack=%lu sum=%x urp=%u\n\n",
					(unsigned long) ntohl(tcp.th_seq),
					(unsigned long) ntohl(tcp.th_ack),
					tcp.th_sum, ntohs(tcp.th_urp));
		}

		/* Get and log the TCP timestamp */
		if (opt_tcp_timestamp)
			print_tcp_timestamp(packet, size);
out:
		if (opt_incdport && !opt_force_incdport)
			dst_port++;
		notrace = 1;
		return 1;
	}
	return 0;
}

/* Try to extract information about the original packet from the
 * ICMP error to obtain the round time trip
 *
 * Note that size is the the packet size starting from the
 * IP packet quoted in the ICMP error, it may be negative
 * if the ICMP is broken */
static int
icmp_unreach_rtt(void *quoted_ip, int size, int *seqp, float *ms_delay)
{
	int src_port;
	int sequence = 0;
	int quoted_iphdr_size;
	struct myudphdr udp;
	struct myicmphdr icmp;
	struct myiphdr qip;

	/* The user specified --no-rtt */
	if (opt_tr_no_rtt)
		return -1;

	if (size < sizeof(struct myiphdr))
		return -1;
	memcpy(&qip, quoted_ip, sizeof(struct myiphdr));
	quoted_iphdr_size = qip.ihl << 2;
	/* Ok, enough room, try to get the rtt,
	 * but check if the original packet was an UDP/TCP one */
	if (qip.protocol == IPPROTO_TCP ||
	    qip.protocol == IPPROTO_UDP) {
		/* We need at least 2 bytes of the quoted UDP/TCP header
		 * for the source port */
		if ((size - quoted_iphdr_size) < 2)
			return -1;

		/* Use the UDP header for both UDP and TCP, they are
		* the same in the 4 first bytes (source and dest port) */
		memcpy(&udp, quoted_ip+quoted_iphdr_size, sizeof(udp));
		src_port = htons(udp.uh_sport);
		return rtt(&sequence, src_port, ms_delay);
	} else if (qip.protocol == IPPROTO_ICMP) {
		int s;

		/* We need the whole 8 byte ICMP header to get
		 * the sequence field, also the type must be
		 * ICMP_ECHO */
		memcpy(&icmp, quoted_ip+quoted_iphdr_size, sizeof(icmp));
		if ((size - quoted_iphdr_size) < 8 ||
		    icmp.type != ICMP_ECHO)
			return -1;

		s = icmp.un.echo.sequence;
		return rtt(&s, 0, ms_delay);
	}
	return -1; /* no way */
}

static int
icmp6_unreach_rtt(void *quoted_ip, int size, int *seqp, float *ms_delay)
{
	int src_port;
	int sequence = 0;
	struct myudphdr udp;
	struct myicmphdr icmp;
	struct myip6hdr *qip;

	/* The user specified --no-rtt */
	if (opt_tr_no_rtt)
		return -1;

	if (size < sizeof(struct myip6hdr))
		return -1;
	qip = (struct myip6hdr *)quoted_ip;

	/* Ok, enough room, try to get the rtt,
	 * but check if the original packet was an UDP/TCP one */
	if (qip->nextheader == IPPROTO_TCP ||
	    qip->nextheader == IPPROTO_UDP) {
		/* We need at least 2 bytes of the quoted UDP/TCP header
		 * for the source port */
		if ((size - IP6HDR_SIZE) < 2)
			return -1;

		/* Use the UDP header for both UDP and TCP, they are
		* the same in the 4 first bytes (source and dest port) */
		memcpy(&udp, quoted_ip + IP6HDR_SIZE, sizeof(udp));
		src_port = htons(udp.uh_sport);
		return rtt(&sequence, src_port, ms_delay);
	} else if (qip->nextheader == 58) {
		int s;

		/* We need the whole 8 byte ICMP header to get
		 * the sequence field, also the type must be
		 * ICMP_ECHO */
		memcpy(&icmp, quoted_ip + IP6HDR_SIZE, sizeof(icmp));
		if ((size - IP6HDR_SIZE) < 8 ||
		    icmp.type != ICMP6_ECHO)
			return -1;

		s = icmp.un.echo.sequence;
		return rtt(&s, 0, ms_delay);
	}
	return -1; /* no way */
}

void print_tcp_timestamp(void *tcp, int tcpsize)
{
	int optlen;
	unsigned char *opt;
	__u32 tstamp, echo;
	static __u32 last_tstamp = 0;
	struct mytcphdr tmptcphdr;
	unsigned int tcphdrlen;

	if (tcpsize < TCPHDR_SIZE)
		return;
	memcpy(&tmptcphdr, tcp, sizeof(struct mytcphdr));
	tcphdrlen = tmptcphdr.th_off * 4;

	/* bad len or no options in the TCP header */
	if (tcphdrlen <= 20 || tcphdrlen < tcpsize)
		return;
	optlen = tcphdrlen - TCPHDR_SIZE; 
	opt = (unsigned char*)tcp + TCPHDR_SIZE; /* skips the TCP fix header */
	while(optlen) {
		switch(*opt) {
		case 0: /* end of option */
			return;
		case 1: /* noop */
			opt++;
			optlen--;
			continue;
		default:
			if (optlen < 2)
				return;
			if (opt[1] > optlen)
				return;
			if (opt[0] != 8) { /* not timestamp */
				optlen -= opt[1];
				opt += opt[1];
				continue;
			}
			/* timestamp found */
			if (opt[1] != 10) /* bad len */
				return;
			memcpy(&tstamp, opt+2, 4);
			memcpy(&echo, opt+6, 4);
			tstamp = ntohl(tstamp);
			echo = ntohl(echo);
			goto found;
		}
	}
found:
	printf("  TCP timestamp: tcpts=%u\n", tstamp);
	if (last_tstamp && !opt_waitinusec) {
		int tsdiff = (tstamp - last_tstamp) / sending_wait;
		int hz_set[] = { 2, 10, 100, 1000, 0 };
		int hzdiff = -1;
		int hz = 0, sec;
		int days, hours, minutes;
		if (tsdiff > 0) {
			int i = 0;
			while(hz_set[i]) {
				if (hzdiff == -1) {
					hzdiff = ABS(tsdiff-hz_set[i]);
					hz = hz_set[i];
				} else if (hzdiff > ABS(tsdiff-hz_set[i])) {
					hzdiff = ABS(tsdiff-hz_set[i]);
					hz = hz_set[i];
				}
				i++;
			}
			printf("  HZ seems hz=%d\n", hz);
			sec = tstamp/hz; /* Get the uptime in seconds */
			days = sec / (3600*24);
			sec %= 3600*24;
			hours = sec / 3600;
			sec %= 3600;
			minutes = sec / 60;
			sec %= 60;
			printf("  System uptime seems: %d days, %d hours, "
			       "%d minutes, %d seconds\n",
			       		days, hours, minutes, sec);
		}
	}
	printf("\n");
	last_tstamp = tstamp;
}

/* This function is exported to listen.c also */
int read_packet(void *packet, int size)
{
#if (!defined OSTYPE_LINUX) || (defined FORCE_LIBPCAP)
	size = pcap_recv(packet, size);
	if (size == -1)
		perror("[wait_packet] pcap_recv()");
#else
	size = recv(sockpacket, packet, size, 0);
	if (size == -1) {
		if (errno != EINTR)
			perror("[wait_packet] recv");
		else
			return 0;
	}
#endif
	return size;
}

void hex_dump(void *packet, int size)
{
	unsigned char *byte = packet;
	int count = 0;

	printf("\t\t");
	for (; byte < (unsigned char*) (packet+size); byte++) {
		count++;
		printf("%02x", *byte);
		if (count % 2 == 0) printf(" ");
		if (count % 16 == 0) printf("\n\t\t");
	}
	printf("\n\n");
}

void human_dump(void *packet, int size)
{
	unsigned char *byte = packet;
	int count = 0;

	printf("\t\t");
	for (; byte < (unsigned char*) (packet+size); byte++) {
		count ++;
		if (isprint(*byte))
			printf("%c", *byte);
		else
			printf(".");
		if (count % 32 == 0) printf("\n\t\t");
	}
	printf("\n\n");
}

void handle_hcmp(char *packet, int size)
{
	char *p;
	struct hcmphdr hcmph;
	unsigned int seq;

	/* Search for the reverse signature inside the packet */
	if ((p = memstr(packet, rsign, size)) == NULL)
		return;

	if (opt_debug)
		fprintf(stderr, "DEBUG: HCMP received\n");

	p+=strlen(rsign);
	if ((size-(packet-p)) < sizeof(struct hcmphdr)) {
		if (opt_verbose || opt_debug)
			fprintf(stderr, "bad HCMP len received\n");
		return;
	}

	memcpy(&hcmph, p, sizeof(hcmph));

	switch(hcmph.type) {
	case HCMP_RESTART:
		seq = ntohs(hcmph.typedep.seqnum);
		src_id = seq; /* set the id */
		datafiller(NULL, seq); /* data seek */
		if (opt_debug)
			printf("DEBUG: HCMP restart from %d\n",
					seq);
		return;
	case HCMP_SOURCE_QUENCH:
	case HCMP_SOURCE_STIRUP:
		printf("HCMP source quench/stirup received\n");
		return;
	default:
		if (opt_verbose || opt_debug)
			fprintf(stderr, "bad HCMP type received\n");
		return;
	}
}
