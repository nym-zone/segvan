/**
 * By nullius <nullius@nym.zone>
 *
 * PGP:		0xC2E91CD74A4C57A105F6C21B5A00591B2F307E0C	(Ed25519)
 *		0xA232750664CC39D61CE5D61536EBB4AB699A10EE	(RSA)
 * Bitcoin:	bc1qnullnymefa273hgss63kvtvr0q7377kjza0607
 *		35segwitgLKnDi2kn7unNdETrZzHD2c5xh
 *
 * Copyright (c) 2018.  All rights reserved.
 *
 * The Antiviral License (AVL) v0.0.1, with added Bitcoin Consensus Clause:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of the source code must retain the above copyright
 *    and credit notices, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    and credit notices, this list of conditions, and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 * 3. Derivative works hereof MUST NOT be redistributed under any license
 *    containing terms which require derivative works and/or usages to
 *    publish source code, viz. what is commonly known as a "copyleft"
 *    or "viral" license.
 * 4. Derivative works hereof which have any functionality related to
 *    digital money (so-called "cryptocurrency") MUST EITHER adhere to
 *    consensus rules fully compatible with Bitcoin Core, OR use a name
 *    which does not contain the word "Bitcoin".
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#define	_POSIX_C_SOURCE	200809L

#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#include <assert.h>
#include <errno.h>
#include <locale.h>

#define	__BSD_VISIBLE 1
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <regex.h>

#include "secp256k1/include/secp256k1.h"

#include "segwit_addr.h"

#define LCRYPTO_OPS
#include "test_test_test.h"
#undef LCRYPTO_OPS

/*#ifdef __linux*/
#include <openssl/ripemd.h>
#include <openssl/sha.h>
/*#elif defined(__FreeBSD__)
#include <ripemd.h>
#include <sha256.h>*/
/*
#else
#error "I don't know which hash library headers to include."
#endif
*/

/*
 * From Electrum 3.0 Release Notes
 * https://github.com/spesmilo/electrum/blob/2774126db6c258807d95921936eb13af07047d97/RELEASE-NOTES
 */

#define	WIF_P2PKH	0x80
#define	WIF_P2WPKH	0x81
#define	WIF_P2WPKH_P2SH	0x82
#define	WIF_P2SH	0x85
#define	WIF_P2WSH	0x86
#define	WIF_P2WSH_P2SH	0x87

/*
 * Evil global option mask for whether to use those.
 * Currently defaults to YES; default may be changed.
 */
static unsigned char wifvmask = 0xff;

#define	WIFV(v)		((v) & wifvmask)

/*
 * Unlike OpenSSL, the Core secp256k1 library developers clearly state
 * if a context object can be shared as read-only between threads, and
 * in what circumstances.  This global is just fine, and will remain so
 * when threading support is added.
 */
static secp256k1_context *secp256k1ctx = NULL;

static int stopme = 0;
static int tellme = 0;

/* XXX: global */
static const char *notifier = NULL;

static void
catchme(int sig)
{

	stopme = 1;
}

static void
inform(int sig)
{

	tellme = 1;
}

static void
notify(const char *addr)
{

	if (notifier != NULL) {
		fprintf(stderr, "%s\n", addr);
		system(notifier);
	}
}

static void
zeroize(void *buf, size_t size)
{

#ifdef notyet
	explicit_bzero(buf, size);
#else
	/* A little hack which the compiler CANNOT remove: */
	memset(buf, 0, size);
	write(-1, buf, size);
#endif
}

static void
hash160(void *out, const void *in, size_t inlen)
{
	SHA256_CTX shactx;
	RIPEMD160_CTX ripectx;
	unsigned char buf[32];

	SHA256_Init(&shactx);
	SHA256_Update(&shactx, in, inlen);
	SHA256_Final(buf, &shactx);

	RIPEMD160_Init(&ripectx);
	RIPEMD160_Update(&ripectx, buf, sizeof(buf));
	RIPEMD160_Final(out, &ripectx);
}

static void
doublesha(void *out, size_t outlen, const void *in, size_t inlen)
{
	SHA256_CTX shactx;
	unsigned char buf[32];

	SHA256_Init(&shactx);
	SHA256_Update(&shactx, in, inlen);
	SHA256_Final(buf, &shactx);

	SHA256_Init(&shactx);
	SHA256_Update(&shactx, buf, sizeof(buf));
	SHA256_Final(buf, &shactx);

	zeroize(&shactx, sizeof(shactx));

	memcpy(out, buf, outlen > sizeof(buf)? sizeof(buf) : outlen);

	zeroize(buf, sizeof(buf));
}

/*
 * base58enc() is adapted from code bearing this notice:
 *
 * Copyright 2012-2014 Luke Dashjr
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the standard MIT license.  See COPYING for more details.
 */

static ssize_t
base58enc(char *b58, size_t *b58sz, const void *data, size_t binsz)
{
	const char b58digits_ordered[] =
		"123456789ABCDEFGHJKLMNPQRSTUVWXYZ"
		"abcdefghijkmnopqrstuvwxyz";
	const uint8_t *bin = data;
	int carry, error = 0;
	ssize_t i, j, high, zcount = 0;
	size_t size;

	while (zcount < binsz && !bin[zcount])
		++zcount;

	size = (binsz - zcount) * 138 / 100 + 1;
	uint8_t buf[size];
	memset(buf, 0, size);

	for (i = zcount, high = size - 1; i < binsz; ++i, high = j) {
		for (carry = bin[i], j = size - 1; (j > high) || carry; --j) {
			carry += 256 * buf[j];
			buf[j] = carry % 58;
			carry /= 58;
		}
	}

	for (j = 0; j < size && !buf[j]; ++j);

	if (*b58sz <= zcount + size - j) {
		*b58sz = zcount + size - j + 1;
		error = -1;
		goto done;
	}

	if (zcount)
		memset(b58, '1', zcount);
	for (i = zcount; j < size; ++i, ++j)
		b58[i] = b58digits_ordered[buf[j]];
	b58[i] = '\0';
	*b58sz = i + 1;

done:
	zeroize(buf, size);
	return (error);
}

static int
b58chk_enc(char *b58, size_t *b58sz, const void *ver, size_t verlen,
	const void *data, size_t binsz)
{
	unsigned char *buf, *cur;
	size_t len;
	int error;

	len = binsz + verlen + 4;
	buf = malloc(len);
	if (buf == NULL)
		return (-1);

	cur = buf;

	if (ver != NULL)
		memcpy(cur, ver, verlen), cur += verlen;
	else
		assert(verlen == 0);

	memcpy(cur, data, binsz), cur += binsz;

	doublesha(cur, 4, buf, binsz + verlen);
	cur = NULL;

	error = base58enc(b58, b58sz, buf, len);

	zeroize(buf, len);
	free(buf);

	return (error);
}

static int
mkpubkey(void *h160 /*[20]*/, const void *seckey /*[32]*/)
{
	int error = 0;
	unsigned char serpubkey[33];
	size_t keylen;
	secp256k1_pubkey pubkey;

	error = secp256k1_ec_pubkey_create(secp256k1ctx, &pubkey, seckey);
	/* Watch out: Inverted returns. */
	if (!error) {
		errno = EINVAL;
		/*return (SECP256K1_INVALID_KEY);*/
		return (-1);
	}

	keylen = sizeof(serpubkey); /* 33 */
	secp256k1_ec_pubkey_serialize(secp256k1ctx,
		serpubkey, &keylen, &pubkey, SECP256K1_EC_COMPRESSED);

	hash160(h160, serpubkey, keylen);

	return (error);
}

static int
mkwif(char *wif, size_t *wifsz, unsigned char ver, const void *skey)
{
	unsigned char buf[33];
	int error;

	memcpy(buf, skey, 32);
	buf[32] = 0x01;

	error = b58chk_enc(wif, wifsz, &ver, 1, buf, sizeof(buf));

	zeroize(buf, sizeof(buf));
	return (error);
}

/*
 * This was added long after Segwit, as an extra feature.
 * I put it first so that readers can see the progression of
 * how things developed.
 */
static int
oldstyle(char *addr, size_t *addrsz, char *wif, size_t *wifsz,
	const void *h160, const void *skey)
{
	int error;

	error = b58chk_enc(addr, addrsz, "", 1, h160, 20);
	if (error)
		return (error);

	error = mkwif(wif, wifsz, WIFV(WIF_P2PKH), skey);

	return (error);
}

static int
segwit_nested(char *addr, size_t *addrsz, char *wif, size_t *wifsz,
	const void *h160, const void *skey)
{
	unsigned char buf[22];
	int error;

	buf[0] = 0x00, buf[1] = 0x14;
	memcpy(buf + 2, h160, 20);

	hash160(buf, buf, 22);

	error = b58chk_enc(addr, addrsz, "\x05", 1, buf, 20);
	if (error) {
		zeroize(buf, sizeof(buf));
		return (error);
	}

	error = mkwif(wif, wifsz, WIFV(WIF_P2WPKH_P2SH), skey);

	return (error);
}

static int
segwit_bech32(char *addr, size_t *addrsz, char *wif, size_t *wifsz,
	const void *h160, const void *skey)
{
	unsigned char buf[32];
	int error;

	/* WARNING: Inverted error. */
	error = segwit_addr_encode(addr, "bc", 0, h160, 20);
	if (error != 1) {
		fprintf(stderr, "segwit_addr() returned %d\n", error);
		return (-99);
	}

	error = mkwif(wif, wifsz, WIFV(WIF_P2WPKH), skey);
	if (error)
		fprintf(stderr, "mkwif() failed\n");

	return (error);
}

/*
 * The following were added to verify that results were the same when
 * doing secp256k1 calculations with OpenSSL and with Core's secp256k1.
 * The OpenSSL code (libcrypto, LCRYPTO_OPS) has since been ripped out.
 */
/*#ifndef LCRYPTO_OPS*/
#if 0
static void
gentests(void)
{
	unsigned char h160[20];
	char oldaddr[40], bech32[75], wif0[128], wif1[128];
	size_t oldaddrsz, bech32sz, wif0sz, wif1sz;

	for (int i = 0; i < NTESTCASES; ++i) {
		mkpubkey(h160, testcase[i].seckey);
		segwit_nested(oldaddr, &oldaddrsz, wif0, &wif0sz, h160,
			testcase[i].seckey);
		segwit_bech32(bech32, &bech32sz, wif1, &wif1sz, h160,
			testcase[i].seckey);
		printf("%s\n%s\n%s\n%s\n", bech32, wif1, oldaddr, wif0);
	}
}
#else /*!LCRYPTO_OPS*/
static void
selftest(void)
{
	int error = 0, err1;
	unsigned char h160[20], save_wifvmask;
	char oldaddr[40], bech32[75], wif0[128], wif1[128];
	size_t oldaddrsz, bech32sz, wif0sz, wif1sz;

	assert(secp256k1ctx != NULL);

	/* XXX not threadsafe (but would be called before any threads start */
	save_wifvmask = wifvmask;
	wifvmask = 0xff;

	for (int i = 0; i < NTESTCASES; ++i) {
		assert(testcase[i].bech32addr != NULL &&
			testcase[i].nested3addr != NULL &&
			testcase[i].bech32wif != NULL &&
			testcase[i].nested3wif != NULL);

		mkpubkey(h160, testcase[i].seckey);

		bech32sz = sizeof(bech32), wif1sz = sizeof(wif1),
		oldaddrsz = sizeof(oldaddr), wif0sz = sizeof(wif0);

		err1 = segwit_nested(oldaddr, &oldaddrsz, wif0, &wif0sz, h160,
			testcase[i].seckey);

		if (err1) {
			fprintf(stderr, "Selftest %d: segwit_nested() err %d\n",
				i, err1);
			error = 1;
		}

		err1 = segwit_bech32(bech32, &bech32sz, wif1, &wif1sz, h160,
			testcase[i].seckey);
		if (err1) {
			fprintf(stderr, "Selftest %d: segwit_bech32() err %d\n",
				i, err1);
			error = 1;
		}
		if (strncmp(oldaddr, testcase[i].nested3addr, sizeof(oldaddr)-1)) {
			fprintf(stderr, "Selftest %d failed on nested3addr "
				"(testcase: \"%s\"; trial: \"%s\")\n",
				i, testcase[i].nested3addr, oldaddr);
			error = 1;
		}
		if (strncmp(wif0, testcase[i].nested3wif, sizeof(wif0)-1)) {
			fprintf(stderr, "Selftest %d failed on nested3wif "
				"(testcase: \"%s\"; trial: \"%s\")\n",
				i, testcase[i].nested3wif, wif0);
			error = 1;
		}
		if (strncmp(bech32, testcase[i].bech32addr, sizeof(bech32)-1)) {
			fprintf(stderr, "Selftest %d failed on bech32addr "
				"(testcase: \"%s\"; trial: \"%s\")\n",
				i, testcase[i].bech32addr, bech32);
			error = 1;
		}
		if (strncmp(wif1, testcase[i].bech32wif, sizeof(wif1)-1)) {
			fprintf(stderr, "Selftest %d failed on bech32wif "
				"(testcase: \"%s\"; trial: \"%s\")\n",
				i, testcase[i].bech32wif, wif1);
			error = 1;
		}
	}

	if (error)
		abort();

	wifvmask = save_wifvmask;
}
#endif /*LCRYPTO_OPS*/

static int
mkvanity(int rndfd, unsigned nsearch, const char **regex, int *i_flag,
	int (**afunc)(char*, size_t*, char*, size_t*, const void*, const void*),
	int v_flag)
{
#define	NTYPES	3
	regex_t preg[NTYPES];
	regmatch_t pmatch[128];
	char errbuf[128];
	size_t errbuf_size;
	int error;
	size_t rbytes;
	unsigned long long ctr = 0;
	struct timespec ts[2];
	double times[2];

	unsigned char skbuf[32], h160[20];
	char addr[NTYPES][128], wif[NTYPES][128];
	unsigned nmatch;
	size_t addrsz, wifsz;

	assert(sizeof(addr[0]) == 128);

	if (nsearch == 0)
		return (0);
	else if (nsearch > sizeof(preg)/sizeof(*preg))
		return (-1);

	for (int i = 0; i < nsearch; ++i) {
		error = regcomp(&preg[i], regex[i],
			REG_EXTENDED | (i_flag[i]? REG_ICASE : 0) | REG_NOSUB);
		if (error) {
			errbuf_size = sizeof(errbuf);
			regerror(error, &preg[i], errbuf, errbuf_size);
			fprintf(stderr, "regcomp(\"%s\"): %s (%d)\n",
				regex[i], errbuf, error);
		}
		if (error || preg[i].re_nsub >= sizeof(pmatch)/sizeof(*pmatch)){
			if (i > 0)
				for (int j = 0; j < i; ++j)
					regfree(&preg[j]);
			return (-1);
		}
		fprintf(stderr, "compiled (%jd): '%s'\n",
			(intmax_t)preg[i].re_nsub, regex[i]);
	}

	/*if (v_flag) {*/
		clock_gettime(CLOCK_MONOTONIC, &ts[0]);
		times[0] = ts[0].tv_sec + ts[0].tv_nsec/1000000000.0;
		/*fprintf(stderr, "debug: start marker %.8f\n", times[0]);*/
	/*}*/

	while (!stopme) {
		nmatch = 0;

		rbytes = read(rndfd, skbuf, 32);
		if (rbytes != 32)
			return (4);

		mkpubkey(h160, skbuf);

		for (int i = 0, j = 0; i < nsearch; ++i) {
			addrsz = sizeof(addr[0]), wifsz = sizeof(wif[0]);
			error = afunc[i](addr[nmatch], &addrsz, wif[nmatch],
				&wifsz, h160, skbuf);

			if (error) {
				error = -1;
				goto end;
			}

			/*
			 * XXX: ad hoc hardcode of desired feature
			 * Only for old-style addresses; but it's cheap, and
			 * it will not affect Bech32 Witness v0 addresses.
			 */
			if (strlen(addr[nmatch]) < 32) {
				++nmatch;
				continue;
			}

			/*error = regexec(&preg[i], addr, 0, NULL, 0);*/
			error = regexec(&preg[i], addr[nmatch],
				preg[i].re_nsub + 1, pmatch, 0);

			if (!error)
				++nmatch;
			else if (error != REG_NOMATCH) {
				fprintf(stderr, "Unknown regex error\n");
				error = -1;
				goto end;
			}
		}

		if (nmatch > 0) {
			if (nmatch == 1) {
				printf("%s\t%s\n", addr[0], wif[0]);
				notify(addr[0]);
			} else {
				char *prnbuf, *cur;
				size_t prnbuflen = 0, len;

				for (int i = 0; i < nmatch; ++i)
					prnbuflen += 1 + strlen(addr[i]) + 1 +
						strlen(wif[i]) + 1;

				prnbuf = malloc(prnbuflen);
				if (prnbuf == NULL)
					abort(); /* XXX FIXME */

				cur = prnbuf, len = prnbuflen;
				for (int i = 0; i < nmatch; ++i) {
					int wbytes; /*yes, it returns int :-( */

					wbytes = snprintf(cur, len, ":%s\t%s\t",
						addr[i], wif[i]);
					cur += wbytes, len -= wbytes;
				}
				/*
				 * According to cstd, snprintf() must discard
				 * the last tab:
				 */
				assert(prnbuf[prnbuflen - 1] == '\0');

				printf("%s\n", prnbuf);

				cur = prnbuf, len = prnbuflen;
				for (int i = 0; i < nmatch; ++i) {
					int wbytes;

					wbytes = snprintf(cur, len, ":%s\t",
						addr[i]);
					cur += wbytes, len -= wbytes;
				}
				*(cur - 1) = '\0'; /* tab not discarded here */

				notify(prnbuf);

				zeroize(prnbuf, prnbuflen);
				free(prnbuf);
			}
		}

		++ctr;

		if (tellme || (v_flag && stopme) ||
			(v_flag > 1 && ctr % 10000000 == 0)) {
			double passed;

			if (tellme)
				tellme = 0;

			clock_gettime(CLOCK_MONOTONIC, &ts[1]);
			times[1] = ts[1].tv_sec + ts[1].tv_nsec/1000000000.0;
			passed = times[1] - times[0];
			fprintf(stderr, "%'llu keys checked in %'.8f seconds, %'.8f keys/sec\n",
				ctr, passed, ctr/passed);
		}
	}

end:
	for (int i = 0; i < nsearch; ++i)
		regfree(&preg[i]);
	return (error);
}

int
main(int argc, char *argv[])
{
	int ch, error,
		rndfd = -1,
		retval = 0,
		i_flag = 1,
		T_flag = 0,
		v_flag = 0,
		n_nested = 0, n_bech32 = 0, n_oldstyle = 0;
	const char *nested_regex = NULL, *bech32_regex = NULL,
		*oldstyle_regex = NULL;
	ssize_t rbytes;

	unsigned char skbuf[32], h160[20];

	char oldaddr[40], bech32[75], wif[64];
	size_t oldaddrsz, bech32sz, wifsz;

	while ((ch = getopt(argc, argv, "0:1:3:EIN:R:Tb:eir:v")) > -1) {
		switch (ch) {
		case '0':
			n_oldstyle = atoi(optarg);
			break;
		case '1':
			oldstyle_regex = optarg;
			break;
		case '3':
			/* XXX: atoi(), LOL.  With no error checks!  FIXME */
			n_nested = atoi(optarg);
			break;
		case 'E':
			wifvmask = 0x80;
			break;
		case 'I':
			i_flag = 0;
			break;
		case 'N':
			notifier = optarg;
			break;
		case 'R':
			nested_regex = optarg;
			break;
		case 'T':
			T_flag = 1;
			break;
		case 'b':
			n_bech32 = atoi(optarg);
			break;
		case 'e':
			wifvmask = 0xff;
			break;
		case 'i':
			i_flag = 1;
			break;
		case 'r':
			bech32_regex = optarg;
			break;
		case 'v':
			++v_flag;
			break;
		default:
			return (1);
		}
	}

	if (v_flag)
		setlocale(LC_NUMERIC, "");

	if ((n_nested > 0 || n_bech32 > 0 || n_oldstyle > 0) &&
		(nested_regex != NULL || bech32_regex != NULL ||
		oldstyle_regex != NULL)) {
		return (1);
	}

	if (n_nested == 0 && n_bech32 == 0 && n_oldstyle == 0 &&
		nested_regex == NULL && bech32_regex == NULL &&
		oldstyle_regex == NULL && !T_flag) {
		return (0);
	}

	secp256k1ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
	if (secp256k1ctx == NULL) {
		fprintf(stderr, "Context creation failure!\n");
		exit(64);
	}

	rndfd = open("/dev/urandom", O_RDONLY);
	if (rndfd < 0)
		return (2);

	rbytes = read(rndfd, skbuf, 32);
	if (rbytes != 32)
		return (4);
	if (!secp256k1_context_randomize(secp256k1ctx, skbuf)) {
		fprintf(stderr, "Failed to randomize context!\n");
		exit(64);
	}

	signal(SIGINT, catchme);
#ifndef __linux
	signal(SIGINFO, inform);
#else
	signal(SIGUSR1, inform);
#endif

	selftest();

	if (T_flag) {
#ifdef compile_broken_stuff
		gentests();
#endif
		goto done;
	}

	while (n_nested-- > 0) {
		rbytes = read(rndfd, skbuf, 32);
		if (rbytes != 32)
			return (4);

		mkpubkey(h160, skbuf);

		oldaddrsz = sizeof(oldaddr), wifsz = sizeof(wif);
		segwit_nested(oldaddr, &oldaddrsz, wif, &wifsz, h160, skbuf);

		printf("%s %s\n", oldaddr, wif);
	}

	while (n_bech32-- > 0) {
		rbytes = read(rndfd, skbuf, 32);
		if (rbytes != 32)
			return (4);

		mkpubkey(h160, skbuf);

		bech32sz = sizeof(bech32), wifsz = sizeof(wif);
		error = segwit_bech32(bech32, &bech32sz, wif, &wifsz, h160, skbuf);

		if (error)
			fprintf(stderr, "bad 1 %d\n", error);

		printf("%s %s\n", bech32, wif);
	}

	while (n_oldstyle-- > 0) {
		rbytes = read(rndfd, skbuf, 32);
		if (rbytes != 32)
			return (4);

		mkpubkey(h160, skbuf);

		oldaddrsz = sizeof(oldaddr), wifsz = sizeof(wif);
		oldstyle(oldaddr, &oldaddrsz, wif, &wifsz, h160, skbuf);

		printf("%s %s\n", oldaddr, wif);
	}

	if (nested_regex != NULL || bech32_regex != NULL || oldstyle_regex !=NULL){
		unsigned nsearch = 0;
		const char *regexes[3];
		int i_flags[3];
		int (*afunc[3])(char*, size_t*, char*, size_t*, const void*, const void*);

		/* XXX: errors ignored */
		setvbuf(stdout, NULL, _IOLBF, 0);

		if (nested_regex != NULL)
			regexes[nsearch] = nested_regex, i_flags[nsearch] = i_flag, afunc[nsearch] = segwit_nested,
				++nsearch;

		if (bech32_regex != NULL)
			regexes[nsearch] = bech32_regex, i_flags[nsearch] = 1, afunc[nsearch] = segwit_bech32,
				++nsearch;

		if (oldstyle_regex != NULL)
			regexes[nsearch] = oldstyle_regex, i_flags[nsearch] = i_flag, afunc[nsearch] = oldstyle,
				++nsearch;

		assert(nsearch > 0 && nsearch <= 3);
		mkvanity(rndfd, nsearch, regexes, i_flags, afunc, v_flag);
	}

	close(rndfd);

done:
	secp256k1_context_destroy(secp256k1ctx);
	secp256k1ctx = NULL;

	return (0);
}
