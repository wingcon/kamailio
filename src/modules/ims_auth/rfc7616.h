/*
 * Copyright (C) 2025 WINGcon AG, tobias.tress@wingcon.com
 * Copyright (C) 2025 WINGcon AG, uzay.durdu@wingcon.com
 *
 * This code extends the HTTP Digest Access Authentication implementation
 * based on RFC-2617 originally written by Dragos Vingarzan at the Fraunhofer
 * FOKUS Institute, and ported/maintained/improved by Jason Penton and
 * Richard Good at Smile Communications, Pty. Ltd.
 * It adds support for RFC-7616, including SHA-256 and SHA-512/256 hashing.
 * 
 * Author: Tobias Tress (tobias(dot)tress(at)wingcon(dot)com)
 * Author: Uzay Durdu (uzay(dot)durdu(at)wingcon(dot)com)
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

#ifndef RFC7616_H
#define RFC7616_H

#include "../../core/str.h"

/* MD5 */
#define MD5HASHLEN 16
#define MD5HASHHEXLEN 32

/* SHA-256, SHA-512/256 */
#define SHA256HASHLEN 32
#define SHA256HASHHEXLEN 64

/* Maximum-sized buffer for each algorithm */
typedef unsigned char HASH[SHA256HASHLEN];
typedef unsigned char HASHHEX[SHA256HASHHEXLEN + 1];

/*
 * Type of algorithm used
 */
typedef enum
{
    HA_MD5,		 /* Plain MD5 */
	HA_MD5_SESS, /* MD5-Session */
	HA_SHA256,		 /* Plain SHA-256 */
	HA_SHA256_SESS, /* SHA-256-Session */
    HA_SHA512_256,		 /* Plain SHA-512/256 */
	HA_SHA512_256_SESS, /* SHA-512/256-Session */
} ha_alg_t;

/*
 * Convert to hex form
 */
void cvt_hex(HASH Bin, HASHHEX Hex, size_t HASHLEN, size_t HASHHEXLEN);

/*
 * calculate H(A1) as per HTTP Digest spec
 */
typedef void (*calc_HA1_t)(ha_alg_t _alg, /* Type of algorithm */
		str *_username,					  /* username */
		str *_realm,					  /* realm */
		str *_password,					  /* password */
		str *_nonce,					  /* nonce string */
		str *_cnonce,					  /* cnonce */
		HASHHEX _sess_key);				  /* Result will be stored here */
void calc_HA1(ha_alg_t _alg,			  /* Type of algorithm */
		str *_username,					  /* username */
		str *_realm,					  /* realm */
		str *_password,					  /* password */
		str *_nonce,					  /* nonce string */
		str *_cnonce,					  /* cnonce */
		HASHHEX _sess_key);				  /* Result will be stored here */

void calc_H(ha_alg_t _alg, str *ent, HASHHEX hash);

/* calculate request-digest/response-digest as per HTTP Digest spec */
typedef void (*calc_response_t)(ha_alg_t _alg, /* Type of algorithm */
        HASHHEX _ha1,                          /* H(A1) */
		str *_nonce,			               /* nonce from server */
		str *_nc,				 /* 8 hex digits */
		str *_cnonce,			 /* client nonce */
		str *_qop,				 /* qop-value: "", "auth", "auth-int" */
		int _auth_int,			 /* 1 if auth-int is used */
		str *_method,			 /* method from the request */
		str *_uri,				 /* requested URL */
		HASHHEX _hentity,		 /* H(entity body) if qop="auth-int" */
		HASHHEX _response);		 /* request-digest or response-digest */
void calc_response(ha_alg_t _alg,/* Type of algorithm */
        HASHHEX _ha1,            /* H(A1) */
		str *_nonce,			 /* nonce from server */
		str *_nc,				 /* 8 hex digits */
		str *_cnonce,			 /* client nonce */
		str *_qop,				 /* qop-value: "", "auth", "auth-int" */
		int _auth_int,			 /* 1 if auth-int is used */
		str *_method,			 /* method from the request */
		str *_uri,				 /* requested URL */
		HASHHEX _hentity,		 /* H(entity body) if qop="auth-int" */
		HASHHEX _response);		 /* request-digest or response-digest */


#endif /* RFC7616_H */