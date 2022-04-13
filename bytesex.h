/* Original code from the Linux C library */
/* Copyright (C) 2000,2001 Salvatore Sanfilippo <antirez@invece.org>
 * This code is under the original GNU C library license (GPL) */

/* $Id: bytesex.h,v 1.3 2003/07/28 09:00:55 njombart Exp $ */

#ifndef ARS_BYTESEX_H
#define ARS_BYTESEX_H

#include <endian.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define BYTE_ORDER_LITTLE_ENDIAN
#elif __BYTE_ORDER == __BIG_ENDIAN
#define BYTE_ORDER_BIG_ENDIAN
#else
# error can not find the byte order for this architecture, fix bytesex.h
#endif

#endif /* ARS_BYTESEX_H */
