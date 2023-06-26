/**
 * @file digest.c  HTTP Digest authentication (RFC 7616)
 *                 RFC 2617 is obsolete
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <time.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_base64.h>
#include <re_mbuf.h>
#include <re_mem.h>
#include <re_md5.h>
#include <re_sha.h>
#include <re_sys.h>
#include <re_httpauth.h>

#define DEBUG_MODULE "httpauth_digest"
#define DEBUG_LEVEL 6
#include <re_dbg.h>

enum {
	NONCE_EXPIRES = 300,
	CNONCE_NC_LENGTH = 9, /*8 charaters + '\0'*/
};

typedef void (digest_decode_h)(const struct pl *name, const struct pl *val,
			       void *arg);


static const struct pl param_realm     = PL("realm");
static const struct pl param_domain    = PL("domain");
static const struct pl param_nonce     = PL("nonce");
static const struct pl param_opaque    = PL("opaque");
static const struct pl param_stale     = PL("stale");
static const struct pl param_algorithm = PL("algorithm");
static const struct pl param_qop       = PL("qop");
static const struct pl param_charset   = PL("charset");
static const struct pl param_userhash  = PL("userhash");

static const struct pl param_cnonce    = PL("cnonce");
static const struct pl param_nc        = PL("nc");
static const struct pl param_response  = PL("response");
static const struct pl param_uri       = PL("uri");
static const struct pl param_username  = PL("username");


static void challenge_decode(const struct pl *name, const struct pl *val,
			     void *arg)
{
	struct httpauth_digest_chall *chall = arg;

	if (!pl_casecmp(name, &param_realm))
		chall->realm = *val;
	if (!pl_casecmp(name, &param_domain))
		chall->domain = *val;
	else if (!pl_casecmp(name, &param_nonce))
		chall->nonce = *val;
	else if (!pl_casecmp(name, &param_opaque))
		chall->opaque= *val;
	else if (!pl_casecmp(name, &param_stale))
		(void) pl_bool(&chall->stale, val);
	else if (!pl_casecmp(name, &param_algorithm))
		chall->algorithm = *val;
	else if (!pl_casecmp(name, &param_qop))
		chall->qop = *val;
	else if (!pl_casecmp(name, &param_charset))
		chall->charset = *val;
	else if (!pl_casecmp(name, &param_userhash))
		(void) pl_bool(&chall->userhash, val);
}


static void response_decode(const struct pl *name, const struct pl *val,
			    void *arg)
{
	struct httpauth_digest_resp *resp = arg;

	if (!pl_casecmp(name, &param_realm))
		resp->realm = *val;
	else if (!pl_casecmp(name, &param_nonce))
		resp->nonce = *val;
	else if (!pl_casecmp(name, &param_response))
		resp->response = *val;
	else if (!pl_casecmp(name, &param_username))
		resp->username = *val;
	else if (!pl_casecmp(name, &param_uri))
		resp->uri = *val;
	else if (!pl_casecmp(name, &param_nc))
		resp->nc = *val;
	else if (!pl_casecmp(name, &param_cnonce))
		resp->cnonce = *val;
	else if (!pl_casecmp(name, &param_qop))
		resp->qop = *val;
	else if (!pl_casecmp(name, &param_algorithm))
		resp->algorithm = *val;
	else if (!pl_casecmp(name, &param_opaque))
		resp->opaque = *val;
	else if (!pl_casecmp(name, &param_userhash))
		(void) pl_bool(&resp->userhash, val);
	else if (!pl_casecmp(name, &param_charset))
		resp->charset = *val;
}


static int digest_decode(const struct pl *hval, digest_decode_h *dech,
			 void *arg)
{
	struct pl r = *hval, start, end, name, val;

	if (re_regex(r.p, r.l, "[ \t\r\n]*Digest[ \t\r\n]+", &start, &end) ||
	    start.p != r.p)
		return EBADMSG;

	pl_advance(&r, end.p - r.p);

	while (!re_regex(r.p, r.l,
			 "[ \t\r\n,]+[a-z]+[ \t\r\n]*=[ \t\r\n]*[~ \t\r\n,]*",
			 NULL, &name, NULL, NULL, &val)) {

		pl_advance(&r, val.p + val.l - r.p);

		dech(&name, &val, arg);
	}

	return 0;
}


static void response_destructor(void *data)
{
	struct httpauth_digest_resp *resp = data;

	mem_deref(resp->mb);
}


/**
 * Decode a Digest challenge
 *
 * @param chall Digest challenge object to decode into
 * @param hval  Header value to decode from
 *
 * @return 0 if successfully decoded, otherwise errorcode
 */
int httpauth_digest_challenge_decode(struct httpauth_digest_chall *chall,
				     const struct pl *hval)
{
	int err;

	if (!chall || !hval)
		return EINVAL;

	memset(chall, 0, sizeof(*chall));

	err = digest_decode(hval, challenge_decode, chall);
	if (err)
		return err;

	if (!chall->realm.p || !chall->nonce.p)
		return EBADMSG;

	return 0;
}


/**
 * Decode a Digest response
 *
 * @param resp Digest response object to decode into
 * @param hval Header value to decode from
 *
 * @return 0 if successfully decoded, otherwise errorcode
 */
int httpauth_digest_response_decode(struct httpauth_digest_resp *resp,
				    const struct pl *hval)
{
	int err;

	if (!resp || !hval)
		return EINVAL;

	memset(resp, 0, sizeof(*resp));

	err = digest_decode(hval, response_decode, resp);
	if (err)
		return err;

	if (!resp->realm.p    ||
	    !resp->nonce.p    ||
	    !resp->response.p ||
	    !resp->username.p ||
	    !resp->uri.p)
		return EBADMSG;

	return 0;
}


/**
 * Authenticate a digest response
 *
 * @param resp   Digest response
 * @param method Request method
 * @param ha1    HA1 value from MD5(username:realm:password)
 *
 * @return 0 if successfully authenticated, otherwise errorcode
 */
int httpauth_digest_response_auth(const struct httpauth_digest_resp *resp,
				  const struct pl *method, const uint8_t *ha1)
{
	uint8_t ha2[MD5_SIZE], digest[MD5_SIZE], response[MD5_SIZE];
	const char *p;
	uint32_t i;
	int err;

	if (!resp || !method || !ha1)
		return EINVAL;

	if (resp->response.l != 32)
		return EAUTH;

	err = md5_printf(ha2, "%r:%r", method, &resp->uri);
	if (err)
		return err;

	if (pl_isset(&resp->qop))
		err = md5_printf(digest, "%w:%r:%r:%r:%r:%w",
				 ha1, (size_t)MD5_SIZE,
				 &resp->nonce,
				 &resp->nc,
				 &resp->cnonce,
				 &resp->qop,
				 ha2, sizeof(ha2));
	else
		err = md5_printf(digest, "%w:%r:%w",
				 ha1, (size_t)MD5_SIZE,
				 &resp->nonce,
				 ha2, sizeof(ha2));
	if (err)
		return err;

	for (i=0, p=resp->response.p; i<sizeof(response); i++) {
		response[i]  = ch_hex(*p++) << 4;
		response[i] += ch_hex(*p++);
	}

	if (memcmp(digest, response, MD5_SIZE))
		return EAUTH;

	return 0;
}


static uint32_t nc = 1;

int httpauth_digest_make_response(struct httpauth_digest_resp **presp,
		const struct httpauth_digest_chall *chall,
		const char *path, const char *method, const char *user,
		const char *pwd, struct mbuf *body)
{
	struct httpauth_digest_resp *resp;
	size_t p1, p2;
	uint8_t ha1[MD5_SIZE], ha2[MD5_SIZE], response[MD5_SIZE];
	uint32_t cnonce;
	struct mbuf *mb = NULL;
	int err;

	if (!presp || !chall || !method || !user || !path || !pwd)
		return EINVAL;

	resp = mem_zalloc(sizeof(*resp), response_destructor);
	if (!resp) {
		return ENOMEM;
	}

	mb = mbuf_alloc(256);
	if (!mb) {
		err = ENOMEM;
		goto out;
	}

	resp->realm = chall->realm;
	resp->nonce = chall->nonce;
	pl_set_str(&resp->username, user);
	pl_set_str(&resp->uri, path);
	resp->qop = chall->qop;

	err = mbuf_printf(mb, "%x", nc);
	err |= mbuf_write_u8(mb, 0);
	if (err)
		goto out;

	/* Client nonce should change, so we use random value. */
	cnonce = rand_u32();
	p1 = mb->pos;
	err = mbuf_printf(mb, "%x", cnonce);
	err |= mbuf_write_u8(mb, 0);
	if (err)
		goto out;

	/* compute response */
	/* HA1 = MD5(username:realm:password) */
	p2 = mb->pos;
	err = mbuf_printf(mb, "%r:%r:%s", &resp->username, &resp->realm,
			pwd);
	if (err)
		goto out;

	mbuf_set_pos(mb, p2);
	md5(mbuf_buf(mb), mbuf_get_left(mb), ha1);
	mbuf_skip_to_end(mb);
	if (0 == pl_strcmp(&chall->algorithm, "MD5-sess")) {
		/* HA1 = MD5(HA1:nonce:cnonce) */
		p2 = mb->pos;
		err = mbuf_printf(mb, "%w:%r:%x", ha1, sizeof(ha1),
				&resp->nonce, cnonce);
		if (err)
			goto out;

		mbuf_set_pos(mb, p2);
		md5(mbuf_buf(mb), mbuf_get_left(mb), ha1);
		mbuf_skip_to_end(mb);
	}

	/* HA2 */
	p2 = mb->pos;
	if (0 == pl_strcmp(&resp->qop, "auth-int") && mbuf_get_left(body)) {
		/* HA2 = MD5(method:digestURI:MD5(entityBody)) */
		err = mbuf_write_mem(mb, mbuf_buf(body), mbuf_get_left(body));
		if (err)
			goto out;

		mbuf_set_pos(mb, p2);
		md5(mbuf_buf(mb), mbuf_get_left(mb), ha2);
		mbuf_skip_to_end(mb);
		p2 = mb->pos;
		err = mbuf_printf(mb, "%s:%r:%w", method, &resp->uri,
				ha2, sizeof(ha2));
	}
	else {
		/* HA2 = MD5(method:digestURI) */
		err = mbuf_printf(mb, "%s:%r", method, &resp->uri);

	}

	if (err)
		goto out;

	mbuf_set_pos(mb, p2);
	md5(mbuf_buf(mb), mbuf_get_left(mb), ha2);
	mbuf_skip_to_end(mb);

	/* response */
	p2 = mb->pos;
	if (0 == pl_strcmp(&resp->qop, "auth-int") ||
			0 == pl_strcmp(&resp->qop, "auth")) {
	/* response = MD5(HA1:nonce:nonceCount:cnonce:qop:HA2) */
		err = mbuf_printf(mb, "%w:%r:%x:%x:%r:%w",
				ha1, sizeof(ha1), &resp->nonce, nc, cnonce,
				&resp->qop, ha2, sizeof(ha2));
	}
	else {
	/* response = MD5(HA1:nonce:HA2) */
		err = mbuf_printf(mb, "%w:%r:%w", ha1, sizeof(ha1),
				&resp->nonce, ha2, sizeof(ha2));
	}

	if (err)
		goto out;

	mbuf_set_pos(mb, p2);
	md5(mbuf_buf(mb), mbuf_get_left(mb), response);
	mbuf_skip_to_end(mb);

	p2 = mb->pos;
	err = mbuf_printf(mb, "%w", response, sizeof(response));
	err |= mbuf_write_u8(mb, 0);
	if (err)
		goto out;

	++nc;
	mbuf_set_pos(mb, 0);
	pl_set_str(&resp->nc, (const char*) mbuf_buf(mb));
	mbuf_set_pos(mb, p1);
	pl_set_str(&resp->cnonce, (const char*) mbuf_buf(mb));
	mbuf_set_pos(mb, p2);
	pl_set_str(&resp->response, (const char*) mbuf_buf(mb));
out:
	resp->mb = mb;
	if (err)
		mem_deref(resp);
	else
		*presp = resp;

	return err;
}


int httpauth_digest_response_encode(const struct httpauth_digest_resp *resp,
				  struct mbuf *mb)
{
	int err;
	size_t s;

	if (!resp || !mb)
		return EINVAL;

	/* length of string literals */
	s = 93;
	if (pl_isset(&resp->qop))
		s += 26;

	/* length of values */
	s += resp->username.l + resp->realm.l + resp->nonce.l + resp->uri.l;
	s += resp->response.l;
	if (pl_isset(&resp->qop))
		s += resp->qop.l + resp->nc.l + resp->cnonce.l;

	if (s > mb->size) {
		err = mbuf_resize(mb, s);
		if (err)
			return err;
	}

	err = mbuf_write_str(mb, "Authorization: ");
	err |= mbuf_printf(mb, "Digest username=\"%r\"", &resp->username);
	err |= mbuf_printf(mb, ", realm=\"%r\"", &resp->realm);
	err |= mbuf_printf(mb, ", nonce=\"%r\"", &resp->nonce);
	err |= mbuf_printf(mb, ", uri=\"%r\"", &resp->uri);
	err |= mbuf_printf(mb, ", response=\"%r\"", &resp->response);

	if (pl_isset(&resp->qop)) {
		err |= mbuf_printf(mb, ", qop=%r", &resp->qop);
		err |= mbuf_printf(mb, ", nc=%r", &resp->nc);
		err |= mbuf_printf(mb, ", cnonce=\"%r\"", &resp->cnonce);
	}

	mbuf_set_pos(mb, 0);
	return err;
}

/* HTTPAUTH DIGEST RESPONSE */

static void httpauth_digest_response_destructor(void *arg)
{
	struct httpauth_digest_resp *resp = arg;

	mem_deref(resp->cnonce_str);
	mem_deref(resp->nc_str);
	mem_deref(resp->response_str);
	mem_deref(resp->username_str);
}


int httpauth_digest_response_print(struct re_printf *pf,
	const struct httpauth_digest_resp *resp)
{
	int err = 0;

	if (!resp)
		return EINVAL;

	/* historical reason quoted strings:   */
	/*   username, realm, nonce, uri,      */
	/*   response, cnonce, opaque          */

	/* historical reason unquoted strings: */
	/*   qop, algorithm, nc                */

	err = re_hprintf(pf, "Digest realm=\"%r\","
		" nonce=\"%r\", username=\"%r\", uri=\"%r\","
		" response=\"%s\"",
		&resp->realm, &resp->nonce, &resp->username, &resp->uri,
		resp->response);

	if (pl_isset(&resp->opaque))
		err |= re_hprintf(pf, ", opaque=\"%r\"", &resp->opaque);
	if (pl_isset(&resp->algorithm))
		err |= re_hprintf(pf, ", algorithm=%r", &resp->algorithm);
	if (pl_isset(&resp->qop)) {
		err |= re_hprintf(pf, ", qop=%r, cnonce=\"%r\", nc=%r",
			&resp->qop, &resp->cnonce, &resp->nc);
	}

	if (resp->userhash)
		err |= re_hprintf(pf, ", userhash=true");
	if (pl_isset(&resp->charset))
		err |= re_hprintf(pf, ", charset=\"%r\"", &resp->charset);

	return err;
}


static int digest_response(struct httpauth_digest_resp *resp,
	const struct httpauth_digest_chall *chall,
	void (*hash_function)(const uint8_t *, size_t, uint8_t *),
	unsigned int hashlength, const struct pl *method,
	const char *user, const char *passwd, const char *entitybody,
	const bool sess)
{
	uint8_t *hash1 = NULL;
	uint8_t *hash2 = NULL;
	struct mbuf *mb = NULL;
	int hashstringlen = (hashlength * 2) + 1;
	int err = 0, n = 0;

	mb = mbuf_alloc(str_len(user) + str_len(passwd) + chall->realm.l + 2);
	hash1 = mem_zalloc(hashlength, NULL);
	hash2 = mem_zalloc(hashlength, NULL);
	resp->response_str = mem_zalloc(hashstringlen, NULL);
	if (resp->userhash)
		resp->username_str = mem_zalloc(hashstringlen, NULL);
	else
		resp->username_str = mem_zalloc(str_len(user) + 1, NULL);

	if (!mb || !hash1 || !hash2 ||
		!resp->response_str || !resp->username_str) {
		err = ENOMEM;
		goto out;
	}

	/* HASH A2 */
	if (pl_isset(&resp->qop) &&
		pl_strcasecmp(&resp->qop, "auth-int") == 0) {
		if (!entitybody || str_casecmp(entitybody, "") == 0) {
			(*hash_function)((uint8_t *)"", str_len(""), hash1);
		}
		else {
			(*hash_function)((uint8_t *)entitybody,
				str_len(entitybody), hash1);
		}
		err = mbuf_printf(mb, "%r:%r:%w",
			method, &resp->uri, hash1, hashlength);
	}
	else {
		err = mbuf_printf(mb, "%r:%r", method, &resp->uri);
	}

	if (err)
		goto out;

	(*hash_function)(mb->buf, mb->end, hash2);
	mbuf_rewind(mb);

	/* HASH A1 */
	if (resp->userhash) {
		err = mbuf_printf(mb, "%s:%r", user, &chall->realm);
		if (err)
			goto out;

		(*hash_function)(mb->buf, mb->end, hash1);
		n = re_snprintf(resp->username_str, hashstringlen,
			"%w", hash1, hashlength);
		if (n == -1 || n != hashstringlen - 1) {
			err = ERANGE;
			goto out;
		}

		err = 0;
		mbuf_rewind(mb);
		err = mbuf_printf(mb, "%w:%r:%s", hash1, hashlength,
			&chall->realm, passwd);
	}
	else {
		err = mbuf_printf(mb, "%s:%r:%s", user, &chall->realm, passwd);
		str_ncpy(resp->username_str, user, str_len(user) + 1);
	}
	if (err)
		goto out;

	pl_set_str(&resp->username, resp->username_str);

	(*hash_function)(mb->buf, mb->end, hash1);
	mbuf_rewind(mb);

	if (sess) {
		err = mbuf_printf(mb, "%w:%r:%r", hash1, hashlength,
			&resp->nonce, &resp->cnonce);
		if (err)
			goto out;

		(*hash_function)(mb->buf, mb->end, hash1);
		mbuf_rewind(mb);
	}

	/* DIGEST */
	if (pl_isset(&resp->qop)) {
		err = mbuf_printf(mb, "%w:%r:%s:%s:%r:%w",
			hash1, hashlength, &resp->nonce,
			resp->nc_str, resp->cnonce_str,
			&resp->qop, hash2, hashlength);
	}
	else {
		err = mbuf_printf(mb, "%w:%r:%w", hash1, hashlength,
			&resp->nonce, hash2, hashlength);
	}

	if (err)
		goto out;

	(*hash_function)(mb->buf, mb->end, hash1);
	n = re_snprintf(resp->response_str, hashstringlen,
		"%w", hash1, hashlength);
	if (n == -1 || n != hashstringlen - 1) {
		err = ERANGE;
		goto out;
	}

	err = 0;
	pl_set_str(&resp->response, resp->response_str);

out:
	mem_deref(hash1);
	mem_deref(hash2);
	mem_deref(mb);

	return err;
}


/**
 * Create a digest response according to the received challenge
 *
 * @param presp        httpauth_digest_resp object pointer
 * @param chall        received challenge
 * @param method       used method
 * @param uri          accessed uri
 * @param user         username
 * @param passwd       user password
 * @param qop          quality of protection
 * @param entitybody   entity body if qop=auth-int
 * @param userhash     enable hashed usernames
 * @param charset      used character set (only UTF-8 or NULL allowed)
 * @param fixed_cnonce disable random cnonce and nc auto increment
 *
 * @return 0 if successfully, otherwise errorcode
 */
int httpauth_digest_response_priv(struct httpauth_digest_resp **presp,
	const struct httpauth_digest_chall *chall, const struct pl *method,
	const char *uri, const char *user, const char *passwd, const char *qop,
	const char *entitybody, const bool userhash, const char *charset,
	const bool fixed_cnonce)
{
	struct httpauth_digest_resp *resp = NULL;
	uint32_t cnonce = rand_u32();
	int err = 0, n = 0;

	if (!presp || !chall || !method || !uri || !user || !passwd)
		return EINVAL;

	resp = mem_zalloc(sizeof(*resp), httpauth_digest_response_destructor);
	if (!resp)
		return ENOMEM;

	resp->cnonce_str = mem_zalloc(CNONCE_NC_LENGTH, NULL);
	resp->nc_str = mem_zalloc(CNONCE_NC_LENGTH, NULL);
	if (!resp->cnonce_str || !resp->nc_str) {
		err = ENOMEM;
		goto out;
	}

	/* copied fields */
	memcpy(&resp->realm, &chall->realm, sizeof(struct pl));
	memcpy(&resp->nonce, &chall->nonce, sizeof(struct pl));
	memcpy(&resp->opaque, &chall->opaque, sizeof(struct pl));

	/* userhash supported by server? */
	if (chall->userhash && userhash)
		resp->userhash = userhash;

	/* only allowed qop Nothing or "auth" or "auth-int" */
	if (qop && (str_casecmp(qop, "auth") &&
		str_casecmp(qop, "auth-int"))) {
		err = EPROTONOSUPPORT;
		goto out;
	}

	/* qop supported by server? */
	if (pl_isset(&chall->qop) && qop && pl_strstr(&chall->qop, qop))
		pl_set_str(&resp->qop, qop);

	/* only allowed charset Nothing or "UTF-8" */
	if (charset && str_casecmp(charset, "UTF-8")) {
		err = EPROTONOSUPPORT;
		goto out;
	}

	/* charset supported by server? */
	if (pl_isset(&chall->charset) &&
		charset && pl_strstr(&chall->charset, charset) == 0)
		pl_set_str(&resp->charset, charset);

	/* set uri */
	pl_set_str(&resp->uri, uri);

	/* disabled random cnonce & nc auto increment */
	if (fixed_cnonce) {
		nc = 0x00000001;
		cnonce = 0xdeadbeef;
	}

	/* cnonce creation & nc */
	n = re_snprintf(resp->cnonce_str, CNONCE_NC_LENGTH,
		"%08"PRIx32"", cnonce);
	if (n == -1 || n != CNONCE_NC_LENGTH - 1) {
		err = ERANGE;
		goto out;
	}

	n = re_snprintf(resp->nc_str, CNONCE_NC_LENGTH,
		"%08"PRIx32"", nc);
	if (n == -1 || n != CNONCE_NC_LENGTH - 1) {
		err = ERANGE;
		goto out;
	}

	pl_set_str(&resp->cnonce, resp->cnonce_str);
	pl_set_str(&resp->nc, resp->nc_str);

	/* RESPONSE CALCULATION */
	if (pl_strstr(&chall->algorithm, "SHA256-sess")) {
		err = digest_response(resp, chall,
			&sha256, SHA256_DIGEST_LENGTH,
			method, user, passwd, entitybody, true);
		pl_set_str(&resp->algorithm, "SHA256-sess");
	}
	else if (pl_strstr(&chall->algorithm, "SHA256")) {
		err = digest_response(resp, chall,
			&sha256, SHA256_DIGEST_LENGTH,
			method, user, passwd, entitybody, false);
		pl_set_str(&resp->algorithm, "SHA256");
	}
	else if (pl_strstr(&chall->algorithm, "SHA1-sess")) {
		err = digest_response(resp, chall,
			&sha1, SHA_DIGEST_LENGTH,
			method, user, passwd, entitybody, true);
		pl_set_str(&resp->algorithm, "SHA1-sess");
	}
	else if (pl_strstr(&chall->algorithm, "SHA1")) {
		err = digest_response(resp, chall,
			&sha1, SHA_DIGEST_LENGTH,
			method, user, passwd, entitybody, false);
		pl_set_str(&resp->algorithm, "SHA1");
	}
	else if (pl_strstr(&chall->algorithm, "MD5-sess")) {
		err = digest_response(resp, chall,
			&md5, MD5_SIZE,
			method, user, passwd, entitybody, true);
		pl_set_str(&resp->algorithm, "MD5-sess");
	}
	else if (!pl_isset(&chall->algorithm) ||
		pl_strstr(&chall->algorithm, "MD5")) {
		err = digest_response(resp, chall,
			&md5, MD5_SIZE,
			method, user, passwd, entitybody, false);
		pl_set_str(&resp->algorithm, "MD5");
	}
	else {
		err = EPROTONOSUPPORT;
		goto out;
	}

out:
	if (err) {
		mem_deref(resp);
	}
	else {
		++nc;
		*presp = resp;
	}

	return err;
}


/**
 * Wrapper of httpauth_digest_respnse_priv for normal usage
 *
 * @param presp        httpauth_digest_resp object pointer
 * @param chall        received challenge
 * @param method       used method
 * @param uri          accessed uri
 * @param user         username
 * @param passwd       user password
 * @param qop          quality of protection
 * @param entitybody   entity body if qop=auth-int
 * @param userhash     enable hashed usernames
 * @param charset      used character set (only UTF-8 or NULL allowed)
 *
 * @return 0 if successfully, otherwise errorcode
 */
int httpauth_digest_response(struct httpauth_digest_resp **presp,
	const struct httpauth_digest_chall *chall, const struct pl *method,
	const char *uri, const char *user, const char *passwd, const char *qop,
	const char *entitybody, const bool userhash, const char *charset)
{
	return httpauth_digest_response_priv(presp, chall, method, uri, user,
		passwd, qop, entitybody, userhash, charset, false);
}


/* HTTPAUTH DIGEST REQUESTS - VERIFICATION */

static void httpauth_digest_request_destructor(void *arg)
{
	struct httpauth_digest_req *req = arg;

	mem_deref(req->realm);
	mem_deref(req->domain);
	mem_deref(req->nonce);
	mem_deref(req->opaque);
	mem_deref(req->algorithm);
	mem_deref(req->qop);
	mem_deref(req->charset);
}

static int generate_nonce(char **pnonce, const time_t ts,
	const char *etag, const char *secret)
{
	struct mbuf *mb = NULL;
	char *nonce = NULL;
	uint8_t *hash = NULL;
	uint8_t hashlen = SHA256_DIGEST_LENGTH;
	int err = 0;

	mb = mbuf_alloc(32);
	if (!mb)
		return ENOMEM;

	if (secret && str_len(secret))
		err = mbuf_printf(mb, "%lu:%s:%s", ts, etag, secret);
	else
		err = mbuf_printf(mb, "%lu:%s", ts, etag);
	if (err)
		goto out;

	hash = mem_zalloc(hashlen, NULL);
	if (!hash) {
		err = ENOMEM;
		goto out;
	}

	sha256(mb->buf, mb->end, hash);
	mbuf_rewind(mb);
	/*create hashed nonce + timestamp as hex*/
	err = mbuf_printf(mb, "%w%016lx", hash, hashlen, ts);
	if (err)
		goto out;

	mbuf_set_pos(mb, 0);
	err = mbuf_strdup(mb, &nonce, mbuf_get_left(mb));

out:
	if (err)
		mem_deref(nonce);
	else
		*pnonce = nonce;

	mem_deref(mb);
	mem_deref(hash);

	return err;
}


static int check_nonce(const char *req_nonce,
	const struct pl *resp_nonce, const char *etag, bool ts_check)
{
	struct pl pl = PL_INIT;
	time_t ts;
	char *renonce = NULL;
	int err = 0;

	if (!req_nonce || !resp_nonce || !etag)
		return EINVAL;

	pl = *resp_nonce;
	pl.p = pl.p + (pl.l - 16);
	pl.l = 16;
	ts = (time_t) pl_x64(&pl);
	if (ts_check && (time(NULL) - ts > NONCE_EXPIRES)) {
		err =  ETIMEDOUT;
		goto out;
	}

	err = generate_nonce(&renonce, ts, etag, NULL);
	if (err)
		goto out;

	if (str_casecmp(req_nonce, renonce))
		err = EAUTH;

out:
	mem_deref(renonce);
	return err;
}


static int digest_verification(struct httpauth_digest_req *req,
	struct httpauth_digest_resp *resp,
	void (*hash_function)(const uint8_t *, size_t, uint8_t *),
	unsigned int hashlength, bool sess, const struct pl *method,
	const char *user, const char *passwd, const char *entitybody)
{
	uint8_t *hash1 = NULL;
	uint8_t *hash2 = NULL;
	struct mbuf *mb = NULL;
	int err = 0;

	mb = mbuf_alloc(str_len(user) + str_len(passwd) +
		str_len(req->realm) + 2);
	hash1 = mem_zalloc(hashlength, NULL);
	hash2 = mem_zalloc(hashlength, NULL);
	if (!mb || !hash1 || !hash2) {
		err = ENOMEM;
		goto out;
	}

	/* HASH A2 */
	if (pl_strstr(&resp->qop, "auth-int")) {
		if (!entitybody || str_casecmp(entitybody, "") == 0) {
			(*hash_function)((uint8_t *)"", str_len(""), hash1);
		}
		else {
			(*hash_function)((uint8_t *)entitybody,
				str_len(entitybody), hash1);
		}
		err = mbuf_printf(mb, "%r:%r:%w",
			method, &resp->uri, hash1, hashlength);
	}
	else {
		err = mbuf_printf(mb, "%r:%r", method, &resp->uri);
	}

	if (err)
		goto out;

	(*hash_function)(mb->buf, mb->end, hash2);
	mbuf_rewind(mb);

	/* HASH A1 */
	if (pl_strcmp(&resp->username, user) != 0) {
		err = EACCES;
		goto out;
	}

	err = mbuf_printf(mb, "%s:%r:%s", user, &resp->realm, passwd);
	if (err)
		goto out;

	(*hash_function)(mb->buf, mb->end, hash1);
	mbuf_rewind(mb);

	if (sess) {
		err = mbuf_printf(mb, "%w:%r:%r",
			hash1, hashlength, &resp->nonce, &resp->cnonce);
		if (err)
			goto out;

		(*hash_function)(mb->buf, mb->end, hash1);
		mbuf_rewind(mb);
	}

	/* DIGEST */
	if (pl_isset(&resp->qop)) {
		err = mbuf_printf(mb, "%w:%r:%r:%r:%r:%w",
			hash1, hashlength, &resp->nonce, &resp->nc,
			&resp->cnonce, &resp->qop, hash2, hashlength);
	}
	else {
		err = mbuf_printf(mb, "%w:%s:%w",
			hash1, hashlength, req->nonce,
			hash2, hashlength);
	}

	if (err)
		goto out;

	(*hash_function)(mb->buf, mb->end, hash1);
	mbuf_rewind(mb);

	/* VERIFICATION */
	err = pl_hex(&resp->response, hash2, hashlength);
	if (err)
		goto out;

	err = mem_seccmp(hash1, hash2, hashlength) == 0 ? 0 : EACCES;
out:
	mem_deref(hash1);
	mem_deref(hash2);
	mem_deref(mb);
	return err;
}


/**
 * Verify a digest response
 *
 * @param req        httpauth_digest_req object
 * @param hval       Authorization heder field
 * @param method     Access method
 * @param etag       changing data for nonce creation
 *                   HTTP ETag Header / SIP msg src address
 * @param user       username, if userhash==true -> must be hashstring
 * @param passwd     user password
 * @param entitybody entity body of the message
 * @param ts_check   enable timestamp freshness verification
 *
 * @return 0 if successfully authenticated, otherwise errorcode
 */
int httpauth_digest_verify_priv(struct httpauth_digest_req *req,
	const struct pl *hval, const struct pl *method,
	const char *etag, const char *user, const char *passwd,
	const char *entitybody, const bool ts_check)
{
	struct httpauth_digest_resp resp;
	int err = 0;

	if (!req || !hval || !user || !passwd)
		return EINVAL;

	err = httpauth_digest_response_decode(&resp, hval);
	if (err)
		return err;

	if (pl_strcasecmp(&resp.realm, req->realm))
		return EINVAL;

	err = check_nonce(req->nonce, &resp.nonce, etag, ts_check);
	if (err == ETIMEDOUT || err == EAUTH) {
		req->stale = true;
		return EAUTH;
	}
	else if (err) {
		return err;
	}

	if (pl_strstr(&resp.algorithm, "SHA256-sess")) {
		/* use SHA256-sess */
		err = digest_verification(req, &resp,
			&sha256, SHA256_DIGEST_LENGTH,
			true, method, user, passwd, entitybody);
	}
	else if (pl_strstr(&resp.algorithm, "SHA256")) {
		/* use SHA256 */
		err = digest_verification(req, &resp,
			&sha256, SHA256_DIGEST_LENGTH,
			false, method, user, passwd, entitybody);
	}
	else if (pl_strstr(&resp.algorithm, "SHA1-sess")) {
		/* use SHA1-sess */
		err = digest_verification(req, &resp,
			&sha1, SHA_DIGEST_LENGTH,
			true, method, user, passwd, entitybody);
	}
	else if (pl_strstr(&resp.algorithm, "SHA1")) {
		/* use SHA1 */
		err = digest_verification(req, &resp,
			&sha1, SHA_DIGEST_LENGTH,
			false, method, user, passwd, entitybody);
	}
	else if (pl_strstr(&resp.algorithm, "MD5-sess")){
		/* use MD5-sess */
		err = digest_verification(req, &resp,
			&md5, MD5_SIZE,
			true, method, user, passwd, entitybody);
	}
	else {
		/* use MD5 as fallback */
		err = digest_verification(req, &resp,
			&md5, MD5_SIZE,
			false, method, user, passwd, entitybody);
	}

	return err;
}


/**
 * Wrapper for httpauth_digest_respnse_priv
 *
 * @param req        httpauth_digest_req object
 * @param hval       Authorization heder field
 * @param method     Access method
 * @param etag       changing data for nonce creation
 *                   HTTP ETag Header / SIP msg src address
 * @param user       username, if userhash==true -> must be hashstring
 * @param passwd     user password
 * @param entitybody entity body of the message
 *
 * @return 0 if successfully authenticated, otherwise errorcode
 */
int httpauth_digest_verify(struct httpauth_digest_req *req,
	const struct pl *hval, const struct pl *method,
	const char *etag, const char *user, const char *passwd,
	const char *entitybody)
{
	return httpauth_digest_verify_priv(req, hval, method,
		etag, user, passwd, entitybody, true);
}


int httpauth_digest_request_print(struct re_printf *pf,
	const struct httpauth_digest_req *req)
{
	int err = 0;

	if (!req)
		return EINVAL;

	/* historical reason quoted strings:   */
	/*   realm, domain, nonce, opaque, qop */
	/* historical reason unquoted strings: */
	/*   stale, algorithm */

	err = re_hprintf(pf, "Digest realm=\"%s\", "
		"qop=\"%s\", nonce=\"%s\", algorithm=%s",
		req->realm, req->qop, req->nonce, req->algorithm);

	if (str_isset(req->opaque))
		err |= re_hprintf(pf, ", opaque=\"%s\"", req->opaque);
	if (str_isset(req->domain))
		err |= re_hprintf(pf, ", domain=\"%s\"", req->domain);
	if (req->stale)
		err |= re_hprintf(pf, ", stale=true");
	if (str_isset(req->charset))
		err |= re_hprintf(pf, ", charset=\"%s\"", req->charset);
	if (req->userhash)
		err |= re_hprintf(pf, ", userhash=true");

	return err;
}


/**
 * Create a Digest Authentication Request
 *
 * @param preq     httpauth_digest_req object ptr
 * @param realm    realm
 * @param domain   domain (not used in SIP)
 * @param etag     changing data for nonce creation
 *                 (HTTP ETag header / SIP msg src address)
 * @param opaque   opaque
 * @param stale    stale
 * @param algo     supported algorithm (MD5,SHA1,SHA256 and sess variants)
 * @param qop      quality of protection
 * @param charset  character set used (not used in SIP)
 * @param userhash userhash support (not used in SIP)
 *
 * @return 0 if successfully created, otherwise errorcode
 */
int httpauth_digest_request(struct httpauth_digest_req **preq,
	const char *realm, const char *domain, const char *etag,
	const char *opaque, const bool stale, const char *algo,
	const char *qop, const char *charset, const bool userhash)
{
	struct httpauth_digest_req *req = NULL;
	int err = 0;

	if (!preq || !realm || !etag || !qop)
		return EINVAL;

	req = mem_zalloc(sizeof(*req), httpauth_digest_request_destructor);
	if (!req)
		return ENOMEM;

	req->stale = stale;
	req->userhash = userhash;
	err = str_dup(&req->realm, realm);
	err |= str_dup(&req->qop, qop);

	if (!str_isset(algo))
		err |= str_dup(&req->algorithm, "MD5");
	else
		err |= str_dup(&req->algorithm, algo);

	if (str_isset(domain))
		err |= str_dup(&req->domain, domain);
	if (str_isset(opaque))
		err |= str_dup(&req->opaque, opaque);
	if (str_isset(charset) && str_casecmp(charset, "UTF-8") == 0)
		err |= str_dup(&req->charset, charset);

	if (err)
		goto out;

	err = generate_nonce(&req->nonce, time(NULL), etag, NULL);
	if (err)
		goto out;

out:
	if (err)
		mem_deref(req);
	else
		*preq = req;

	return err;
}
