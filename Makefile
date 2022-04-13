# $smu-mark$ 
# $name: Makefile.in$ 
# $author: Salvatore Sanfilippo 'antirez'$ 
# $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
# $license: This software is under GPL version 2 of license$ 
# $date: Sun Jul 25 17:56:15 MET DST 1999$ 
# $rev: 3$ 

CC= gcc
AR=/usr/bin/ar
RANLIB=/usr/bin/ranlib
CCOPT= -O2 -Wall 
DEBUG= -g
#uncomment the following if you need libpcap based build under linux
#(not raccomanded)
COMPILE_TIME= 
INSTALL_MANPATH=/usr/local/man


OBJ=	main.o getifname.o getlhs.o \
	linux_sockpacket.o parseoptions.o datafiller.o \
	datahandler.o gethostname.o \
	binding.o getusec.o opensockraw.o \
	logicmp.o waitpacket.o resolve.o \
	sendip.o sendip6.o sendicmp.o sendicmp6.o sendudp.o \
	sendtcp.o cksum.o statistics.o \
	usage.o version.o antigetopt.o \
	sockopt.o listen.o \
	sendhcmp.o memstr.o rtt.o \
	relid.o sendip_handler.o \
	libpcap_stuff.o memlockall.o memunlockall.o \
	memlock.o memunlock.o ip_opt_build.o \
	display_ipopt.o sendrawip.o signal.o send.o \
	strlcpy.o arsglue.o random.o random6.o scan.o \
	hstring.o libars.a

ARSOBJ = ars.o apd.o split.o

all: hping6

libars.a: $(ARSOBJ)
	$(AR) rc $@ $^
	$(RANLIB) $@

hping6: byteorder.h $(OBJ)
	$(CC) -o hping6 $(CCOPT) $(DEBUG) $(OBJ) $(PCAP) 
	@echo
	./hping6 -v
	@echo "use \`make strip' to strip hping6 binary"
	@echo "use \`make install' to install hping6"

byteorder.h:
	./configure

.c.o:
	$(CC) -c $(CCOPT) $(DEBUG) $(COMPILE_TIME) $<

clean:
	rm -rf hping6 *.o *.a
	-(cd utils; $(MAKE) clean)

distclean:
	rm -rf hping6 *.o *.a byteorder byteorder.h systype.h Makefile
	-(cd utils; $(MAKE) clean)

install: hping6
	mkdir -p ${prefix}/sbin/
	cp -f hping6 ${prefix}/sbin/
	chmod 755 ${prefix}/sbin/hping6
	@if [ -f ${prefix}/sbin/hping2 ]; then \
		rm ${prefix}/sbin/hping2; \
	fi

strip: hping6
	@ls -l ./hping6
	strip hping6
	@ls -l ./hping6
