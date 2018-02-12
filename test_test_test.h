#ifndef _TEST_TEST_TEST_H_
#define _TEST_TEST_TEST_H_

struct testcase {
	const char *bech32addr;
	const char *nested3addr;
	const char *bech32wif;
	const char *nested3wif;
	const unsigned char seckey[32];
};

#define	NTESTCASES	8

#define	TESTSEC_LOWEST	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01

#define	TESTSEC_HIGHEST	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, \
			0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, \
			0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40

#define	TESTSEC_0	0x3d, 0x6a, 0x59, 0x34, 0x69, 0x32, 0xcc, 0xb9, \
			0xbd, 0x82, 0x4a, 0xf6, 0x26, 0x41, 0x47, 0xac, \
			0xcd, 0x26, 0x8a, 0x73, 0x08, 0x35, 0x56, 0xae, \
			0xac, 0xe7, 0x4b, 0x5c, 0xd7, 0x83, 0x3f, 0x70

#define	TESTSEC_1	0xea, 0xaf, 0x4c, 0xeb, 0x41, 0x26, 0x1d, 0x71, \
			0x2d, 0x9b, 0x4e, 0xd5, 0x8a, 0xae, 0x25, 0xc7, \
			0x1e, 0x27, 0xa9, 0x64, 0xfa, 0x5a, 0x80, 0x97, \
			0xa4, 0xf9, 0x1c, 0x1f, 0xf9, 0x83, 0xd7, 0xdb

#define	TESTSEC_2	0x6d, 0x95, 0xeb, 0x47, 0x30, 0x7f, 0x9c, 0x49, \
			0xda, 0xc5, 0xff, 0xab, 0x59, 0x4c, 0xb9, 0x0f, \
			0xf3, 0xd1, 0x6b, 0x33, 0xb1, 0x72, 0x56, 0x1d, \
			0xd1, 0x09, 0xea, 0xec, 0xf6, 0x9f, 0x5a, 0xf6

#define	TESTSEC_3	0xe9, 0xd7, 0xb3, 0xbb, 0xd8, 0xb1, 0x2f, 0x73, \
			0xdb, 0xcc, 0x0b, 0x36, 0x21, 0x81, 0x6a, 0x7f, \
			0xd7, 0x24, 0xdf, 0x1c, 0x1a, 0x5a, 0xc1, 0x94, \
			0x92, 0xdb, 0x02, 0x42, 0xeb, 0x45, 0xc0, 0x31

#define	TESTSEC_4	0x1a, 0x74, 0x24, 0x6c, 0x30, 0xf3, 0x4c, 0xd6, \
			0xce, 0xaa, 0xd1, 0xc9, 0x21, 0x84, 0x33, 0xe9, \
			0x07, 0x68, 0x8d, 0x23, 0xc5, 0xe0, 0xb1, 0xd6, \
			0x29, 0xed, 0xba, 0x45, 0xae, 0x6e, 0x3c, 0x6f

#define	TESTSEC_5	0x02, 0x08, 0x0c, 0x28, 0x33, 0x93, 0x27, 0xfc, \
			0xd1, 0x68, 0xb7, 0x60, 0xbc, 0x4a, 0x2a, 0x5e, \
			0xed, 0x92, 0xc4, 0x9b, 0x4a, 0xb5, 0x59, 0x5a, \
			0x94, 0xa6, 0x91, 0x44, 0x1c, 0x0a, 0x14, 0xae

static const struct testcase testcase[NTESTCASES] = {
	{
#ifdef LCRYPTO_OPS
		.bech32addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
		.nested3addr = "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN",
		.bech32wif = "L5oLkpV3aqBjhki6LmvChTCq73v9gyymzzMpBbhDLjDpLCfkwaDM",
		.nested3wif = "LENyKyqwkz6sgGirtrK6VdJKMV7oXQFWARywk43JqCyXcXx1uyaB",
#else
		.bech32addr = NULL,
		.nested3addr = NULL,
		.bech32wif = NULL,
		.nested3wif = NULL,
#endif
		.seckey = { TESTSEC_LOWEST }
	},
	{
#ifdef LCRYPTO_OPS
		.bech32addr = "bc1q4h0ycu78h88wzldxc7e79vhw5xsde0n8jk4wl5",
		.nested3addr = "38Kw57SDszoUEikRwJNBpypPSdpbAhToeD",
		.bech32wif = "LENyKyqwkz6sgGirtrK6VdHyMEqXeUiFWXso2UcvKMqTXfp4RDLE",
		.nested3wif = "LNxbu9Cqw921enjdSvhzHoPTbg3BUtyyfyVvavy1oqbAozzjwAne",
#else
		.bech32addr = NULL,
		.nested3addr = NULL,
		.bech32wif = NULL,
		.nested3wif = NULL,
#endif
		.seckey = { TESTSEC_HIGHEST }
	},
	{
#ifdef LCRYPTO_OPS
		.bech32addr = "bc1qpc703tdttncs09r4q9pcq8aujx7av9uq4sh92r",
		.nested3addr = "3BBKbcdzfWp2PMibzh6nRRuewnjGr8qsnY",
		.bech32wif = "L7rj17HYWWcfH9ZmA5GCwP71TC9GQf19CHUd5TyFWCnywugZRPRE",
		.nested3wif = "LGSMaGeSgfXoFfaXi9f6jZCVhdLvF5GsMj6kdvKLzgYhEEpKfCZZ",
#else
		.bech32addr = NULL,
		.nested3addr = NULL,
		.bech32wif = NULL,
		.nested3wif = NULL,
#endif
		.seckey = { TESTSEC_0 }
	},
	{
#ifdef LCRYPTO_OPS
		.bech32addr = "bc1qnhtdvtplh9wh6d4sg7tjnrcnlhzcgegzmgvrec",
		.nested3addr = "3C8ZgkS4NxdS1B3LR5URAUifLH6Egyp9pJ",
		.bech32wif = "LDfY9v23QbHYmbo36LZfqEUUtaaZimAtazCV8GA28bzMbFb4uuZF",
		.nested3wif = "LNFAj5NwakCgk7ooeQxZdQZy91nDZBSckRpcgiW7d5k4saoKKjBS",
#else
		.bech32addr = NULL,
		.nested3addr = NULL,
		.bech32wif = NULL,
		.nested3wif = NULL,
#endif
		.seckey = { TESTSEC_1 }
	},
	{
#ifdef LCRYPTO_OPS
		.bech32addr = "bc1q2zzpsregwl82mvn00x0ra8t3vqvsx6j93t55h2",
		.nested3addr = "39pYxHYFH92v1vgkQN3zGMupgQE2GTxKTe",
		.bech32wif = "L9UMvXfDF5aL6qY76ZiLUtgsedo4cvyBhukxpojLoR2qJ1PTtXfT",
		.nested3wif = "LJ3zVh27REVU5MYsee7EH4nMu4ziTMEusMP6PG5SHtnYaLYJYX8w",
#else
		.bech32addr = NULL,
		.nested3addr = NULL,
		.bech32wif = NULL,
		.nested3wif = NULL,
#endif
		.seckey = { TESTSEC_2 }
	},
	{
#ifdef LCRYPTO_OPS
		.bech32addr = "bc1q8jnjuhamh7eadjw48teasldz9dn095uug5xcr2",
		.nested3addr = "3JQJj5BvtdpSEx27GghfPnrWpAhy8rYp4s",
		.bech32wif = "LDduCk5ybgaF3DgYq5ePBrsQ6C4KpX96RaSVYo7MwKgtGeXVpH4b",
		.nested3wif = "LNDXmuSsmqVP1jhKPA3Gz2xtLdFyewQpb24d7FTTRoSbYyj3EwLb",
#else
		.bech32addr = NULL,
		.nested3addr = NULL,
		.bech32wif = NULL,
		.nested3wif = NULL,
#endif
		.seckey = { TESTSEC_3 }
	},
	{
#ifdef LCRYPTO_OPS
		.bech32addr = "bc1qqvw25wffvtt3779ah5apnfq0jjq4rs3d6f79zn",
		.nested3addr = "3F7eHv7jkF2fa3GyGfwrvyCorHFxjz2W7r",
		.bech32wif = "L6gmG72fPGCX94mLDLGqueRzj4K93mSPNhrPDEq4N6ZTqrQ2H2uk",
		.nested3wif = "LFGPqGPZZR7f7an6mQfjhpXUyVWntBi7Y9UWmhB9raKB8BeFGXP3",
#else
		.bech32addr = NULL,
		.nested3addr = NULL,
		.bech32wif = NULL,
		.nested3wif = NULL,
#endif
		.seckey = { TESTSEC_4 }
	},
	{
#ifdef LCRYPTO_OPS
		.bech32addr = "bc1q6u937pkurxe0u6ew8wneyylr63uty9xjufcjmw",
		.nested3addr = "3My6khAmGGdg2qiKj1ynGfgvnWxFtppVi9",
		.bech32wif = "L5sHnjZVMxM47WVwhiLS19aXEy5fBjfQMkhcavRVdVDqjdQufWKj",
		.nested3wif = "LESvMtvPY7GC62WiFnjKoKg1VQHK29w8XCKk9Nmb7xyZ1xZ46VTs",
#else
		.bech32addr = NULL,
		.nested3addr = NULL,
		.bech32wif = NULL,
		.nested3wif = NULL,
#endif
		.seckey = { TESTSEC_5 }
	}
};

#endif /*!_TEST_TEST_TEST_H_*/
