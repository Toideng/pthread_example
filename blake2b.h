#ifndef BLAKE2B_H
#define BLAKE2B_H

/*
 * Define BLAKE2B_IMPLEMENTATION before `#include "blake2b.h"` to include
 * implementation.
 */



#include "xtypes.h"



enum blake2b_constant
{
	BLAKE2B_BLOCKBYTES    = 128,
	BLAKE2B_OUTBYTES      = 64,
	BLAKE2B_KEYBYTES      = 64,
	BLAKE2B_SALTBYTES     = 16,
	BLAKE2B_PERSONALBYTES = 16,
};

struct blake2b_state
{
	u64    h[8];
	u64    t[2];
	u64    f[2];
	byte   buf[BLAKE2B_BLOCKBYTES];
	size_t buflen;
	size_t outlen;
	byte   last_node;
};

struct blake2b_param
{
	byte  digest_length;                    /* 1 */
	byte  key_length;                       /* 2 */
	byte  fanout;                           /* 3 */
	byte  depth;                            /* 4 */
	u32   leaf_length;                      /* 8 */
	u32   node_offset;                      /* 12 */
	u32   xof_length;                       /* 16 */
	byte  node_depth;                       /* 17 */
	byte  inner_length;                     /* 18 */
	byte  reserved[14];                     /* 32 */
	byte  salt[BLAKE2B_SALTBYTES];          /* 48 */
	byte  personal[BLAKE2B_PERSONALBYTES];  /* 64 */
};

/* Padded structs result in a compile-time error */
enum
{
	BLAKE2_DUMMY = 1/(sizeof(struct blake2b_param) == BLAKE2B_OUTBYTES),
};



int blake2b_init(
	struct blake2b_state *S,
	size_t outlen
);

int blake2b_init_key(
	struct blake2b_state *S,
	size_t outlen,
	void const *key,
	size_t keylen
);

int blake2b_init_salt(
	struct blake2b_state *S,
	size_t outlen,
	byte const salt[BLAKE2B_SALTBYTES]
);

int blake2b_init_key_salt(
	struct blake2b_state *S,
	size_t outlen,
	void const *key,
	size_t keylen,
	byte const salt[BLAKE2B_SALTBYTES]
);

int blake2b_init_param(
	struct blake2b_state *S,
	struct blake2b_param const *P
);

int blake2b_update(
	struct blake2b_state *S,
	void const *in,
	size_t inlen
);

int blake2b_final(
	struct blake2b_state *S,
	void *out,
	size_t outlen
);



int blake2b(
	void *out,
	size_t outlen,
	void const *in,
	size_t inlen,
	void const *key,
	size_t keylen,
	byte const salt[BLAKE2B_SALTBYTES]
);



char *blake2b_of_cstr(
	size_t outlen,
	char const *cstr_in,
	void const *key,
	size_t keylen
);










#ifdef BLAKE2B_IMPLEMENTATION
#include <string.h>
#include <stdio.h>

static inline u32
blake2b_internal_load32(
	void const *src)
{
#if defined(NATIVE_LITTLE_ENDIAN)
	u32 w;
	memcpy(&w, src, sizeof w);
	return w;
#else
	byte const *p = (byte const *)src;
	return ((u32)(p[0]) <<  0) |
	       ((u32)(p[1]) <<  8) |
	       ((u32)(p[2]) << 16) |
	       ((u32)(p[3]) << 24) ;
#endif
}

static inline u64
blake2b_internal_load64(
	void const *src)
{
#if defined(NATIVE_LITTLE_ENDIAN)
	u64 w;
	memcpy(&w, src, sizeof w);
	return w;
#else
	byte const *p = (byte const *)src;
	return ((u64)(p[0]) <<  0) |
	       ((u64)(p[1]) <<  8) |
	       ((u64)(p[2]) << 16) |
	       ((u64)(p[3]) << 24) |
	       ((u64)(p[4]) << 32) |
	       ((u64)(p[5]) << 40) |
	       ((u64)(p[6]) << 48) |
	       ((u64)(p[7]) << 56) ;
#endif
}

static inline u16
blake2b_internal_load16(
	void const *src)
{
#if defined(NATIVE_LITTLE_ENDIAN)
	u16 w;
	memcpy(&w, src, sizeof w);
	return w;
#else
	byte const *p = (byte const * )src;
	return (u16)(((u32)(p[0]) <<  0) |
	             ((u32)(p[1]) <<  8));
#endif
}

static inline void
blake2b_internal_store16(
	void *dst,
	u16 w)
{
#if defined(NATIVE_LITTLE_ENDIAN)
	memcpy(dst, &w, sizeof w);
#else
	byte *p = (byte *)dst;
	*p++ = (byte)w;
	w >>= 8;
	*p++ = (byte)w;
#endif
}

static inline void
blake2b_internal_store32(
	void *dst,
	u32 w)
{
#if defined(NATIVE_LITTLE_ENDIAN)
	memcpy(dst, &w, sizeof w);
#else
	byte *p = (byte *)dst;
	p[0] = (byte)(w >>  0);
	p[1] = (byte)(w >>  8);
	p[2] = (byte)(w >> 16);
	p[3] = (byte)(w >> 24);
#endif
}

static inline void
blake2b_internal_store64(
	void *dst,
	uint64_t w)
{
#if defined(NATIVE_LITTLE_ENDIAN)
	memcpy(dst, &w, sizeof w);
#else
	byte *p = (byte *)dst;
	p[0] = (byte)(w >>  0);
	p[1] = (byte)(w >>  8);
	p[2] = (byte)(w >> 16);
	p[3] = (byte)(w >> 24);
	p[4] = (byte)(w >> 32);
	p[5] = (byte)(w >> 40);
	p[6] = (byte)(w >> 48);
	p[7] = (byte)(w >> 56);
#endif
}

static inline u64
blake2b_internal_load48(
	void const *src)
{
	byte const *p = (byte const *)src;
	return ((u64)(p[0]) <<  0) |
	       ((u64)(p[1]) <<  8) |
	       ((u64)(p[2]) << 16) |
	       ((u64)(p[3]) << 24) |
	       ((u64)(p[4]) << 32) |
	       ((u64)(p[5]) << 40) ;
}

static inline void
blake2b_internal_store48(
	void *dst,
	uint64_t w)
{
	byte *p = (byte *)dst;
	p[0] = (byte)(w >>  0);
	p[1] = (byte)(w >>  8);
	p[2] = (byte)(w >> 16);
	p[3] = (byte)(w >> 24);
	p[4] = (byte)(w >> 32);
	p[5] = (byte)(w >> 40);
}

static inline u32
blake2b_internal_rotr32(
	u32 const w,
	u32 const c)
{
	return ( w >> c ) | ( w << ( 32 - c ) );
}

static inline u64
blake2b_internal_rotr64(
	u64 const w,
	u32 const c)
{
	return ( w >> c ) | ( w << ( 64 - c ) );
}

/* prevents compiler optimizing out memset() */
static inline void
blake2b_internal_secure_zero_memory(
	void *v,
	size_t n)
{
	static void *(*const volatile memset_v)(void *, int, size_t) = &memset;
	memset_v(v, 0, n);
}

static const uint64_t blake2b_IV[8] =
{
	0x6A09E667F3BCC908ull,
	0xBB67AE8584CAA73Bull,
	0x3C6EF372FE94F82Bull,
	0xA54FF53A5F1D36F1ull,
	0x510E527FADE682D1ull,
	0x9B05688C2B3E6C1Full,
	0x1F83D9ABFB41BD6Bull,
	0x5BE0CD19137E2179ull,
};

static const uint8_t blake2b_sigma[12][16] =
{
	{  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
	{ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
	{  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
	{  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
	{  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
	{ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
	{ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
	{  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
	{ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
	{  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
};



static void
blake2b_set_lastnode(
	struct blake2b_state *S)
{
	S->f[1] = (u64)-1;
}

static int
blake2b_is_lastblock(
	struct blake2b_state const *S)
{
	return S->f[0] != 0;
}

static void
blake2b_set_lastblock(
	struct blake2b_state *S)
{
	if (S->last_node)
		blake2b_set_lastnode(S);
	S->f[0] = (u64)-1;
}

static void
blake2b_increment_counter(
	struct blake2b_state *S,
	u64 const inc)
{
	S->t[0] += inc;
	S->t[1] += (S->t[0] < inc);
}

static void
blake2b_init0(
	struct blake2b_state *S)
{
	size_t i;
	memset(S, 0, sizeof(struct blake2b_state));
	for (i = 0;  i < 8;  ++i)
		S->h[i] = blake2b_IV[i];
}

int
blake2b_init_param(
	struct blake2b_state *S,
	struct blake2b_param const *P)
{
	byte const *p = (byte const*)P;
	size_t i;

	blake2b_init0(S);
	for (i = 0;  i < 8;  ++i)
		S->h[i] ^= blake2b_internal_load64(p + sizeof(S->h[i]) * i);
	S->outlen = P->digest_length;
	return 0;
}

int
blake2b_init(
	struct blake2b_state *S,
	size_t outlen)
{
	struct blake2b_param P;
	if ((!outlen)  ||  (outlen > BLAKE2B_OUTBYTES))
		return -1;

	P.digest_length = (byte)outlen;
	P.key_length    = 0;
	P.fanout        = 1;
	P.depth         = 1;
	P.leaf_length   = 0;
	P.node_offset   = 0;
	P.xof_length    = 0;
	P.node_depth    = 0;
	P.inner_length  = 0;
	memset(P.reserved, 0, sizeof(P.reserved));
	memset(P.salt,     0, sizeof(P.salt));
	memset(P.personal, 0, sizeof(P.personal));
	return blake2b_init_param(S, &P);
}

int
blake2b_init_key(
	struct blake2b_state *S,
	size_t outlen,
	void const *key,
	size_t keylen)
{
	struct blake2b_param P;
	if ((!outlen)  ||  (outlen > BLAKE2B_OUTBYTES))
		return -1;
	if ((!key) || (!keylen) || (keylen > BLAKE2B_KEYBYTES))
		return -1;

	P.digest_length = (byte)outlen;
	P.key_length    = (byte)keylen;
	P.fanout        = 1;
	P.depth         = 1;
	P.leaf_length   = 0;
	P.node_offset   = 0;
	P.xof_length    = 0;
	P.node_depth    = 0;
	P.inner_length  = 0;
	memset(P.reserved, 0, sizeof(P.reserved));
	memset(P.salt,     0, sizeof(P.salt));
	memset(P.personal, 0, sizeof(P.personal));

	if (blake2b_init_param(S, &P) < 0)
	{
		return -1;
	}

	{
		byte block[BLAKE2B_BLOCKBYTES];
		memset(block, 0, BLAKE2B_BLOCKBYTES);
		memcpy(block, key, keylen);
		blake2b_update(S, block, BLAKE2B_BLOCKBYTES);
		blake2b_internal_secure_zero_memory(block, BLAKE2B_BLOCKBYTES); /* Burn the key from stack */
	}

	return 0;
}

int
blake2b_init_salt(
	struct blake2b_state *S,
	size_t outlen,
	byte const salt[BLAKE2B_SALTBYTES])
{
	struct blake2b_param P;
	if ((!outlen)  ||  (outlen > BLAKE2B_OUTBYTES))
		return -1;

	P.digest_length = (byte)outlen;
	P.key_length    = 0;
	P.fanout        = 1;
	P.depth         = 1;
	P.leaf_length   = 0;
	P.node_offset   = 0;
	P.xof_length    = 0;
	P.node_depth    = 0;
	P.inner_length  = 0;
	memset(P.reserved, 0, sizeof(P.reserved));
	memcpy(P.salt, salt, BLAKE2B_SALTBYTES);
	memset(P.personal, 0, sizeof(P.personal));
	return blake2b_init_param(S, &P);
}

int
blake2b_init_key_salt(
	struct blake2b_state *S,
	size_t outlen,
	void const *key,
	size_t keylen,
	byte const salt[BLAKE2B_SALTBYTES])
{
	struct blake2b_param P;
	if ((!outlen)  ||  (outlen > BLAKE2B_OUTBYTES))
		return -1;
	if ((!key) || (!keylen) || (keylen > BLAKE2B_KEYBYTES))
		return -1;

	P.digest_length = (byte)outlen;
	P.key_length    = (byte)keylen;
	P.fanout        = 1;
	P.depth         = 1;
	P.leaf_length   = 0;
	P.node_offset   = 0;
	P.xof_length    = 0;
	P.node_depth    = 0;
	P.inner_length  = 0;
	memset(P.reserved, 0, sizeof(P.reserved));
	memcpy(P.salt, salt, BLAKE2B_SALTBYTES);
	memset(P.personal, 0, sizeof(P.personal));

	if (blake2b_init_param(S, &P) < 0)
	{
		return -1;
	}

	{
		byte block[BLAKE2B_BLOCKBYTES];
		memset(block, 0, BLAKE2B_BLOCKBYTES);
		memcpy(block, key, keylen);
		blake2b_update(S, block, BLAKE2B_BLOCKBYTES);
		blake2b_internal_secure_zero_memory(block, BLAKE2B_BLOCKBYTES); /* Burn the key from stack */
	}

	return 0;
}



#define G(r, i, a, b, c, d)                             \
	do                                              \
	{                                               \
		a = a + b + m[blake2b_sigma[r][2*i+0]]; \
		d = blake2b_internal_rotr64(d ^ a, 32); \
		c = c + d;                              \
		b = blake2b_internal_rotr64(b ^ c, 24); \
		a = a + b + m[blake2b_sigma[r][2*i+1]]; \
		d = blake2b_internal_rotr64(d ^ a, 16); \
		c = c + d;                              \
		b = blake2b_internal_rotr64(b ^ c, 63); \
	} while(0)

#define ROUND(r)                                \
	do                                      \
	{                                       \
		G(r,0,v[ 0],v[ 4],v[ 8],v[12]); \
		G(r,1,v[ 1],v[ 5],v[ 9],v[13]); \
		G(r,2,v[ 2],v[ 6],v[10],v[14]); \
		G(r,3,v[ 3],v[ 7],v[11],v[15]); \
		G(r,4,v[ 0],v[ 5],v[10],v[15]); \
		G(r,5,v[ 1],v[ 6],v[11],v[12]); \
		G(r,6,v[ 2],v[ 7],v[ 8],v[13]); \
		G(r,7,v[ 3],v[ 4],v[ 9],v[14]); \
	} while(0)



static void
blake2b_compress(
	struct blake2b_state *S,
	byte const block[BLAKE2B_BLOCKBYTES])
{
	u64 m[16];
	u64 v[16];
	size_t i;

	for (i = 0;  i < 16;  i++)
		m[i] = blake2b_internal_load64(block + i * sizeof(m[i]));
	for (i = 0;  i < 8;  i++)
		v[i] = S->h[i];
	v[ 8] = blake2b_IV[0];
	v[ 9] = blake2b_IV[1];
	v[10] = blake2b_IV[2];
	v[11] = blake2b_IV[3];
	v[12] = blake2b_IV[4] ^ S->t[0];
	v[13] = blake2b_IV[5] ^ S->t[1];
	v[14] = blake2b_IV[6] ^ S->f[0];
	v[15] = blake2b_IV[7] ^ S->f[1];

	ROUND( 0);
	ROUND( 1);
	ROUND( 2);
	ROUND( 3);
	ROUND( 4);
	ROUND( 5);
	ROUND( 6);
	ROUND( 7);
	ROUND( 8);
	ROUND( 9);
	ROUND(10);
	ROUND(11);

	for (i = 0;  i < 8;  ++i)
		S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];
}

#undef G
#undef ROUND



int blake2b_update(
	struct blake2b_state *S,
	void const *pin,
	size_t inlen)
{
	byte const *in = (byte const *)pin;
	if (inlen > 0)
	{
		size_t left = S->buflen;
		size_t fill = BLAKE2B_BLOCKBYTES - left;
		if (inlen > fill)
		{
			S->buflen = 0;
			memcpy(S->buf + left, in, fill);
			blake2b_increment_counter(S, BLAKE2B_BLOCKBYTES);
			blake2b_compress(S, S->buf);
			in += fill;
			inlen -= fill;
			while (inlen > BLAKE2B_BLOCKBYTES)
			{
				blake2b_increment_counter(S, BLAKE2B_BLOCKBYTES);
				blake2b_compress(S, in);
				in += BLAKE2B_BLOCKBYTES;
				inlen -= BLAKE2B_BLOCKBYTES;
			}
		}
		memcpy(S->buf + S->buflen, in, inlen);
		S->buflen += inlen;
	}
	return 0;
}



int
blake2b_final(
	struct blake2b_state *S,
	void *out,
	size_t outlen)
{
	byte buffer[BLAKE2B_OUTBYTES] = {0};
	size_t i;
	if (!out || outlen < S->outlen)
		return -1;
	if (blake2b_is_lastblock(S))
		return -1;

	blake2b_increment_counter(S, S->buflen);
	blake2b_set_lastblock(S);
	memset(S->buf + S->buflen, 0, BLAKE2B_BLOCKBYTES - S->buflen);
	blake2b_compress(S, S->buf);

	for (i = 0;  i < 8;  i++)
		blake2b_internal_store64(buffer + sizeof(S->h[i]) * i, S->h[i]);

	memcpy(out, buffer, S->outlen);
	blake2b_internal_secure_zero_memory(buffer, sizeof(buffer));
	return 0;
}



int
blake2b(
	void *out,
	size_t outlen,
	void const *in,
	size_t inlen,
	void const *key,
	size_t keylen,
	byte const salt[BLAKE2B_SALTBYTES])
{
	struct blake2b_state S;

	if ((!in && inlen > 0)
	 || (!out)
	 || (!key && keylen > 0)
	 || (!outlen || outlen > BLAKE2B_OUTBYTES)
	 || (keylen > BLAKE2B_KEYBYTES))
	{
		return -1;
	}

//	fprintf(stderr,
//		"blake2b(<0x%016lx>, %lu, <0x%016lx>, %lu, <0x%016lx>, %lu)\xa",
//		(size_t)out, outlen,
//		(size_t)in, inlen,
//		(size_t)key, keylen);

	if (keylen && salt)
	{
		if (blake2b_init_key_salt(&S, outlen, key, keylen, salt) < 0)
			return -1;
	}
	else if (keylen)
	{
		if (blake2b_init_key(&S, outlen, key, keylen) < 0)
			return -1;
	}
	else if (salt)
	{
		if (blake2b_init_salt(&S, outlen, salt) < 0)
			return -1;
	}
	else
	{
		if (blake2b_init(&S, outlen) < 0)
			return -1;
	}

	blake2b_update(&S, (byte const *)in, inlen);
	blake2b_final(&S, out, outlen);
	return 0;
}



char *blake2b_of_cstr(
	size_t outlen,
	char const *cstr_in,
	void const *key,
	size_t keylen)
{
	static char output[] =
		"00010203040506070809"
		"10010203040506070809"
		"20010203040506070809"
		"30010203040506070809"
		"40010203040506070809"
		"50010203040506070809"
		"60010203\x0";

	enum { dummy = (1 / (sizeof(output) == BLAKE2B_OUTBYTES * 2 + 1 + 1)), };

	size_t inlen = strlen(cstr_in);
	byte out[64] = {0};
	if (!outlen || outlen > 64)
		return 0;
	if (blake2b(out, outlen, cstr_in, inlen, key, keylen, 0) < 0)
		return 0;

	for (size_t i = 0;  i < outlen;  i++)
	{
		output[2 * i + 0] = "0123456789abcdef"[(out[i] >> 4) & 0xf];
		output[2 * i + 1] = "0123456789abcdef"[(out[i] >> 0) & 0xf];
	}
	output[2 * outlen] = 0;

	return output;
}
#endif /* BLAKE2B_IMPLEMENTATION */










#endif /* BLAKE2B_H */
