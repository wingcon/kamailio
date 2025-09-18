/*
 * Copyright (C) 2025 WINGcon AG, info(at)wingcon(dot)com
 *
 * This code extends the HTTP Digest Access Authentication implementation
 * based on RFC-2617 originally written by Dragos Vingarzan at the Fraunhofer
 * FOKUS Institute, and ported/maintained/improved by Jason Penton and
 * Richard Good at Smile Communications, Pty. Ltd.
 * It adds support for RFC-7616, including SHA-256 and SHA-512/256 hashing.
 * 
 * Author: Tobias Tress
 * Author: Uzay Durdu
 *
 * NB: A lot of this code was originally part of OpenIMSCore,
 * Fraunhofer FOKUS.
 * Copyright (C) 2004-2006 FhG FOKUS
 * Thanks for the great work! This effort breaks apart the various CSCF
 * functions into logically separate components to improve architecture
 * and maintainability in the Kamailio/SR environment.
 *
 * Special thanks to Jason Penton and Richard Good at Smile Communications
 * for their contributions and improvements.
 *
 * This file is part of Kamailio, a free SIP server.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Kamailio is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Kamailio is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

#include "rfc7616.h"
#include "../../core/crypto/md5.h"
#include "../../core/crypto/sha256.h"
#include "../../core/dprint.h"

/*
 * calculate H(A1) for MD5 hash algorithm as per spec
 */
static inline void calc_HA1_MD5(ha_alg_t _alg, str *_username, str *_realm, str *_password,
		str *_nonce, str *_cnonce, HASHHEX _sess_key)
{
    MD5_CTX Md5Ctx;
	HASH HA1;

	MD5Init(&Md5Ctx);
	MD5Update(&Md5Ctx, _username->s, _username->len);
	MD5Update(&Md5Ctx, ":", 1);
	MD5Update(&Md5Ctx, _realm->s, _realm->len);
	MD5Update(&Md5Ctx, ":", 1);
	MD5Update(&Md5Ctx, _password->s, _password->len);
	MD5Final(HA1, &Md5Ctx);

	if(_alg == HA_MD5_SESS) {
		MD5Init(&Md5Ctx);
		MD5Update(&Md5Ctx, HA1, MD5HASHLEN);
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, _nonce->s, _nonce->len);
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, _cnonce->s, _cnonce->len);
		MD5Final(HA1, &Md5Ctx);
	};

	cvt_hex(HA1, _sess_key, MD5HASHLEN, MD5HASHHEXLEN);
}

/*
 * calculate H(A1) for SHA-256 hash algorithm as per spec
 */
static inline void calc_HA1_SHA256(ha_alg_t _alg, str *_username, str *_realm, str *_password,
		str *_nonce, str *_cnonce, HASHHEX _sess_key)
{
    SHA256_CTX Sha256Ctx;
	HASH HA1;

    sr_SHA256_Init(&Sha256Ctx);
    sr_SHA256_Update(&Sha256Ctx, _username->s, _username->len);
    sr_SHA256_Update(&Sha256Ctx, ":", 1);
    sr_SHA256_Update(&Sha256Ctx, _realm->s, _realm->len);
    sr_SHA256_Update(&Sha256Ctx, ":", 1);
    sr_SHA256_Update(&Sha256Ctx, _password->s, _password->len);
    sr_SHA256_Final(HA1, &Sha256Ctx);

    if(_alg == HA_SHA256_SESS) {
        sr_SHA256_Init(&Sha256Ctx);
        sr_SHA256_Update(&Sha256Ctx, HA1, SHA256HASHLEN);
        sr_SHA256_Update(&Sha256Ctx, ":", 1);
        sr_SHA256_Update(&Sha256Ctx, _nonce->s, _nonce->len);
        sr_SHA256_Update(&Sha256Ctx, ":", 1);
        sr_SHA256_Update(&Sha256Ctx, _cnonce->s, _cnonce->len);
        sr_SHA256_Final(HA1, &Sha256Ctx);
    }

	cvt_hex(HA1, _sess_key, SHA256HASHLEN, SHA256HASHHEXLEN);
}

/*
 * calculate H(entity-body) for MD5 hash algorithm as per spec
 */
static inline void calc_H_MD5(str *ent, HASHHEX hash)
{
	MD5_CTX Md5Ctx;
	HASH HA1;
	MD5Init(&Md5Ctx);
	MD5Update(&Md5Ctx, ent->s, ent->len);
	MD5Final(HA1, &Md5Ctx);
	cvt_hex(HA1, hash, MD5HASHLEN, MD5HASHHEXLEN);
}

/*
 * calculate H(entity-body) for SHA-256 hash algorithm as per spec
 */
static inline void calc_H_SHA256(str *ent, HASHHEX hash)
{
	SHA256_CTX Sha256Ctx;
	HASH HA1;
    sr_SHA256_Init(&Sha256Ctx);
    sr_SHA256_Update(&Sha256Ctx, ent->s, ent->len);
    sr_SHA256_Final(HA1, &Sha256Ctx);
	cvt_hex(HA1, hash, SHA256HASHLEN, SHA256HASHHEXLEN);
}

/*
 * calculate request-digest/response-digest for MD5 as per HTTP Digest spec
 */
static inline void calc_response_MD5(HASHHEX _ha1, /* H(A1) */
		str *_nonce,			                   /* nonce from server */
		str *_nc,				 /* 8 hex digits */
		str *_cnonce,			 /* client nonce */
		str *_qop,				 /* qop-value: "", "auth", "auth-int" */
		int _auth_int,			 /* 1 if auth-int is used */
		str *_method,			 /* method from the request */
		str *_uri,				 /* requested URL */
		HASHHEX _hentity,		 /* H(entity body) if qop="auth-int" */
		HASHHEX _response)	     /* request-digest or response-digest */
{
	LM_DBG("calc_response(_ha1=%.*s, _nonce=%.*s, _nc=%.*s,_cnonce=%.*s, "
		   "_qop=%.*s, _auth_int=%d,_method=%.*s,_uri=%.*s,_algorithm=%.*s,_hentity=%.*s)\n",
			MD5HASHHEXLEN, _ha1, _nonce->len, _nonce->s, _nc->len, _nc->s,
			_cnonce->len, _cnonce->s, _qop->len, _qop->s, _auth_int,
			_method ? _method->len : 4, _method ? _method->s : "null",
			_uri->len, _uri->s, _auth_int ? MD5HASHHEXLEN : 0, "MD5", _hentity);

	MD5_CTX Md5Ctx;
	HASH HA2;
	HASH RespHash;
	HASHHEX HA2Hex;

	/* calculate H(A2) */
	MD5Init(&Md5Ctx);
	if(_method) { /* _method is NULL when calculating H(A2) for rspauth in Authentication-Info */
		MD5Update(&Md5Ctx, _method->s, _method->len);
	}
	MD5Update(&Md5Ctx, ":", 1);
	MD5Update(&Md5Ctx, _uri->s, _uri->len);

	if(_auth_int) {
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, _hentity, MD5HASHHEXLEN);
	};

	MD5Final(HA2, &Md5Ctx);
	cvt_hex(HA2, HA2Hex, MD5HASHLEN, MD5HASHHEXLEN);

	/* calculate response */
	MD5Init(&Md5Ctx);
	MD5Update(&Md5Ctx, _ha1, MD5HASHHEXLEN);
	MD5Update(&Md5Ctx, ":", 1);
	MD5Update(&Md5Ctx, _nonce->s, _nonce->len);
	MD5Update(&Md5Ctx, ":", 1);

	if(_qop->len) {
		MD5Update(&Md5Ctx, _nc->s, _nc->len);
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, _cnonce->s, _cnonce->len);
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, _qop->s, _qop->len);
		MD5Update(&Md5Ctx, ":", 1);
	};
	MD5Update(&Md5Ctx, HA2Hex, MD5HASHHEXLEN);
	MD5Final(RespHash, &Md5Ctx);
	cvt_hex(RespHash, _response, MD5HASHLEN, MD5HASHHEXLEN);
	LM_DBG("H(A1) = %.*s, H(A2) = %.*s, rspauth = %.*s\n", MD5HASHHEXLEN, _ha1,
			MD5HASHHEXLEN, HA2Hex, MD5HASHHEXLEN, _response);
}

/*
 * calculate request-digest/response-digest for SHA-256 as per HTTP Digest spec
 */
static inline void calc_response_SHA256(HASHHEX _ha1, /* H(A1) */
		str *_nonce,			                      /* nonce from server */
		str *_nc,				 /* 8 hex digits */
		str *_cnonce,			 /* client nonce */
		str *_qop,				 /* qop-value: "", "auth", "auth-int" */
		int _auth_int,			 /* 1 if auth-int is used */
		str *_method,			 /* method from the request */
		str *_uri,				 /* requested URL */
		HASHHEX _hentity,		 /* H(entity body) if qop="auth-int" */
		HASHHEX _response)		 /* request-digest or response-digest */
{
	LM_DBG("calc_response(_ha1=%.*s, _nonce=%.*s, _nc=%.*s,_cnonce=%.*s, "
		   "_qop=%.*s, _auth_int=%d,_method=%.*s,_uri=%.*s,_algorithm=%.*s,_hentity=%.*s)\n",
			MD5HASHHEXLEN, _ha1, _nonce->len, _nonce->s, _nc->len, _nc->s,
			_cnonce->len, _cnonce->s, _qop->len, _qop->s, _auth_int,
			_method ? _method->len : 4, _method ? _method->s : "null",
			_uri->len, _uri->s, _auth_int ? MD5HASHHEXLEN : 0, "SHA-256", _hentity);

	SHA256_CTX Sha256Ctx;
    HASH HA2;
    HASH RespHash;
    HASHHEX HA2Hex;

    /* calculate H(A2) */
    sr_SHA256_Init(&Sha256Ctx);
    if(_method) { /* _method is NULL when calculating H(A2) for rspauth in Authentication-Info */
        sr_SHA256_Update(&Sha256Ctx, _method->s, _method->len);
    }
    sr_SHA256_Update(&Sha256Ctx, ":", 1);
    sr_SHA256_Update(&Sha256Ctx, _uri->s, _uri->len);

    if(_auth_int) {
        sr_SHA256_Update(&Sha256Ctx, ":", 1);
        sr_SHA256_Update(&Sha256Ctx, _hentity, SHA256HASHHEXLEN);
    }

    sr_SHA256_Final(HA2, &Sha256Ctx);
    cvt_hex(HA2, HA2Hex, SHA256HASHLEN, SHA256HASHHEXLEN);

    /* calculate response */
    sr_SHA256_Init(&Sha256Ctx);
    sr_SHA256_Update(&Sha256Ctx, _ha1, SHA256HASHHEXLEN);
    sr_SHA256_Update(&Sha256Ctx, ":", 1);
    sr_SHA256_Update(&Sha256Ctx, _nonce->s, _nonce->len);
    sr_SHA256_Update(&Sha256Ctx, ":", 1);

    if(_qop->len) {
        sr_SHA256_Update(&Sha256Ctx, _nc->s, _nc->len);
        sr_SHA256_Update(&Sha256Ctx, ":", 1);
        sr_SHA256_Update(&Sha256Ctx, _cnonce->s, _cnonce->len);
        sr_SHA256_Update(&Sha256Ctx, ":", 1);
        sr_SHA256_Update(&Sha256Ctx, _qop->s, _qop->len);
        sr_SHA256_Update(&Sha256Ctx, ":", 1);
    }
    sr_SHA256_Update(&Sha256Ctx, HA2Hex, SHA256HASHHEXLEN);
    sr_SHA256_Final(RespHash, &Sha256Ctx);
	cvt_hex(RespHash, _response, SHA256HASHLEN, SHA256HASHHEXLEN);
	LM_DBG("H(A1) = %.*s, H(A2) = %.*s, rspauth = %.*s\n", SHA256HASHHEXLEN, _ha1,
			SHA256HASHHEXLEN, HA2Hex, SHA256HASHHEXLEN, _response);
}

/*
 * Convert to hex form
 */
void cvt_hex(HASH _b, HASHHEX _h, size_t HASHLEN, size_t HASHHEXLEN)
{
	unsigned short i;
	unsigned char j;

	for(i = 0; i < HASHLEN; i++) {
		j = (_b[i] >> 4) & 0xf;
		if(j <= 9) {
			_h[i * 2] = (j + '0');
		} else {
			_h[i * 2] = (j + 'a' - 10);
		}

		j = _b[i] & 0xf;

		if(j <= 9) {
			_h[i * 2 + 1] = (j + '0');
		} else {
			_h[i * 2 + 1] = (j + 'a' - 10);
		}
	};

	_h[HASHHEXLEN] = '\0';
}

/*
 * calculate H(A1) as per spec
 */
void calc_HA1(ha_alg_t _alg, str *_username, str *_realm, str *_password,
		str *_nonce, str *_cnonce, HASHHEX _sess_key)
{
	switch(_alg) {
        case HA_MD5:
        case HA_MD5_SESS:
            calc_HA1_MD5(_alg, _username, _realm, _password, _nonce, _cnonce, _sess_key);
            break;
        case HA_SHA512_256_SESS:
        case HA_SHA512_256:
        case HA_SHA256_SESS:
        case HA_SHA256:
            calc_HA1_SHA256(_alg, _username, _realm, _password, _nonce, _cnonce, _sess_key);
            break;
        default:
            calc_HA1_MD5(_alg, _username, _realm, _password, _nonce, _cnonce, _sess_key);
            break;
    }
}

void calc_H(ha_alg_t _alg, str *ent, HASHHEX hash)
{
    switch(_alg) {
        case HA_MD5:
        case HA_MD5_SESS:
            calc_H_MD5(ent, hash);
            break;
        case HA_SHA512_256_SESS:
        case HA_SHA512_256:
        case HA_SHA256_SESS:
        case HA_SHA256:
            calc_H_SHA256(ent, hash);
            break;
        default:
            calc_H_MD5(ent, hash);
            break;
    }
}

/*
 * calculate request-digest/response-digest as per HTTP Digest spec
 */
void calc_response(ha_alg_t _alg,/* Type of algorithm   */
        HASHHEX _ha1,            /* H(A1) */
		str *_nonce,			 /* nonce from server */
		str *_nc,				 /* 8 hex digits */
		str *_cnonce,			 /* client nonce */
		str *_qop,				 /* qop-value: "", "auth", "auth-int" */
		int _auth_int,			 /* 1 if auth-int is used */
		str *_method,			 /* method from the request */
		str *_uri,				 /* requested URL */
		HASHHEX _hentity,		 /* H(entity body) if qop="auth-int" */
		HASHHEX _response)		 /* request-digest or response-digest */
{
	switch(_alg) {
        case HA_MD5:
        case HA_MD5_SESS:
            calc_response_MD5(_ha1, _nonce, _nc, _cnonce, _qop, _auth_int, _method, _uri, _hentity, _response);
            break;
        case HA_SHA512_256_SESS:
        case HA_SHA512_256:
        case HA_SHA256_SESS:
        case HA_SHA256:
            calc_response_SHA256(_ha1, _nonce, _nc, _cnonce, _qop, _auth_int, _method, _uri, _hentity, _response);
            break;
        default:
            calc_response_MD5(_ha1, _nonce, _nc, _cnonce, _qop, _auth_int, _method, _uri, _hentity, _response);
            break;
    }
}