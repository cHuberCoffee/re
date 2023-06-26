/**
 * @file re_httpauth.h  Interface to HTTP Authentication
 *
 * Copyright (C) 2010 Creytiv.com
 */


/** HTTP Digest Request Challenge*/
struct httpauth_digest_req {
	char *realm;
	char *domain;
	char *nonce;
	char *opaque;
	bool stale;
	char *algorithm;
	char *qop;

	/* optional */
	char *charset;
	bool userhash;
};

/** HTTP Digest Challenge */
struct httpauth_digest_chall {
	struct pl realm;
	struct pl domain;
	struct pl nonce;
	struct pl opaque;
	bool stale;
	struct pl algorithm;
	struct pl qop;

	/* optional */
	struct pl charset;
	bool userhash;
};

/** HTTP Digest response */
struct httpauth_digest_resp {
	struct pl realm;
	struct pl nonce;
	struct pl opaque;
	struct pl algorithm;
	struct pl qop;

	/* optional */
	struct pl charset;
	bool userhash;

	/* response specific*/
	char *response_str;
	struct pl response;        /* deprecated, future remove */
	char *username_str;
	struct pl username;        /* deprecated, future remove */
	struct pl username_star;   /* currently not allowed */
	struct pl uri;
	char *cnonce_str;
	struct pl cnonce;          /* deprecated, future remove */
	char *nc_str;
	struct pl nc;              /* deprecated, future remove */

	struct mbuf *mb;           /* deprecated, future remove */
};


/** HTTP Basic */
struct httpauth_basic {
	struct mbuf *mb;
	struct pl realm;
	struct pl auth;
};

struct httpauth_basic_req {
	char *realm;

	/* optional */
	char *charset;
};


/* deprecated functions*/
int httpauth_digest_response_encode(const struct httpauth_digest_resp *resp,
				  struct mbuf *mb);
int httpauth_digest_response_auth(const struct httpauth_digest_resp *resp,
				  const struct pl *method, const uint8_t *ha1);
int httpauth_digest_make_response(struct httpauth_digest_resp **resp,
		const struct httpauth_digest_chall *chall,
		const char *path, const char *method, const char *user,
		const char *pwd, struct mbuf *body);


int httpauth_digest_challenge_decode(struct httpauth_digest_chall *chall,
				     const struct pl *hval);
int httpauth_digest_response_decode(struct httpauth_digest_resp *resp,
				    const struct pl *hval);


int httpauth_digest_response_print(struct re_printf *pf,
	const struct httpauth_digest_resp *resp);
int httpauth_digest_response_priv(struct httpauth_digest_resp **presp,
	const struct httpauth_digest_chall *chall, const struct pl *method,
	const char *uri, const char *user, const char *passwd, const char *qop,
	const char *entitybody, const bool userhash, const char *charset,
	const bool fixed_cnonce);
int httpauth_digest_response(struct httpauth_digest_resp **presp,
	const struct httpauth_digest_chall *chall, const struct pl *method,
	const char *uri, const char *user, const char *passwd, const char *qop,
	const char *entitybody, const bool userhash, const char *charset);


int httpauth_digest_request_print(struct re_printf *pf,
	const struct httpauth_digest_req *req);
int httpauth_digest_verify_priv(struct httpauth_digest_req *req,
	const struct pl *hval, const struct pl *method, const char *etag,
	const char *user, const char *passwd, const char* entitybody,
	const bool ts_check);
int httpauth_digest_verify(struct httpauth_digest_req *req,
	const struct pl *hval, const struct pl *method, const char *etag,
	const char *user, const char *passwd, const char* entitybody);
int httpauth_digest_request(struct httpauth_digest_req **preq,
	const char *realm, const char *domain, const char *etag,
	const char *opaque, const bool stale, const char *algo,
	const char *qop, const char *charset, const bool userhash);


struct httpauth_basic *httpauth_basic_alloc(void);
int httpauth_basic_decode(struct httpauth_basic *basic,
		const struct pl *hval);
int httpauth_basic_make_response(struct httpauth_basic *basic,
		const char *user, const char *pwd);
int httpauth_basic_encode(const struct httpauth_basic *basic, struct mbuf *mb);


int httpauth_basic_request_print(struct re_printf *pf,
	const struct httpauth_basic_req *req);
int httpauth_basic_verify(const struct httpauth_basic_req *req,
	const struct pl *hval, const char *user, const char *passwd);
int httpauth_basic_request(struct httpauth_basic_req **preq,
	const char *realm, const char *charset);
