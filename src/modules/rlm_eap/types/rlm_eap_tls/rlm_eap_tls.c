/*
 * rlm_eap_tls.c  contains the interfaces that are called from eap
 *
 * Version:     $Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 * Copyright 2003  Alan DeKok <aland@freeradius.org>
 * Copyright 2006  The FreeRADIUS server project
 *
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/autoconf.h>
#include "rlm_eap.h"

#ifdef HAVE_OPENSSL_RAND_H
#include <openssl/rand.h>
#endif

#ifdef HAVE_OPENSSL_EVP_H
#include <openssl/evp.h>
#endif

#include <openssl/x509.h>

#include "rlm_eap_tls.h"
#include "config.h"

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_OPENSSL_OCSP_H
#include <openssl/ocsp.h>
#endif

#include <freeradius-devel/portnox/portnox_auth.h>

static CONF_PARSER cache_config[] = {
	{ "enable", PW_TYPE_BOOLEAN,
	  offsetof(EAP_TLS_CONF, session_cache_enable), NULL, "no" },
	{ "lifetime", PW_TYPE_INTEGER,
	  offsetof(EAP_TLS_CONF, session_timeout), NULL, "24" },
	{ "max_entries", PW_TYPE_INTEGER,
	  offsetof(EAP_TLS_CONF, session_cache_size), NULL, "255" },
	{ "name", PW_TYPE_STRING_PTR,
	  offsetof(EAP_TLS_CONF, session_id_name), NULL, NULL},
 	{ NULL, -1, 0, NULL, NULL }           /* end the list */
};

static CONF_PARSER verify_config[] = {
	{ "use_script", PW_TYPE_BOOLEAN,
	  offsetof(EAP_TLS_CONF, use_script), NULL, "no" },
	{ "tmpdir", PW_TYPE_STRING_PTR,
	  offsetof(EAP_TLS_CONF, verify_tmp_dir), NULL, NULL},
	{ "client", PW_TYPE_STRING_PTR,
	  offsetof(EAP_TLS_CONF, verify_client_cert_cmd), NULL, NULL},
 	{ NULL, -1, 0, NULL, NULL }           /* end the list */
};

#ifdef HAVE_OPENSSL_OCSP_H
static CONF_PARSER ocsp_config[] = {
	{ "enable", PW_TYPE_BOOLEAN,
	  offsetof(EAP_TLS_CONF, ocsp_enable), NULL, "no"},
	{ "override_cert_url", PW_TYPE_BOOLEAN,
	  offsetof(EAP_TLS_CONF, ocsp_override_url), NULL, "no"},
	{ "url", PW_TYPE_STRING_PTR,
	  offsetof(EAP_TLS_CONF, ocsp_url), NULL, NULL },
	{ "use_nonce", PW_TYPE_BOOLEAN,
	  offsetof(EAP_TLS_CONF, ocsp_use_nonce), NULL, "yes"},
	{ "timeout", PW_TYPE_INTEGER,
	  offsetof(EAP_TLS_CONF, ocsp_timeout), NULL, "0" },
	{ "softfail", PW_TYPE_BOOLEAN,
	  offsetof(EAP_TLS_CONF, ocsp_softfail), NULL, "no"},
 	{ NULL, -1, 0, NULL, NULL }           /* end the list */
};
#endif

static CONF_PARSER module_config[] = {
	{ "rsa_key_exchange", PW_TYPE_BOOLEAN,
	  offsetof(EAP_TLS_CONF, rsa_key), NULL, "no" },
	{ "dh_key_exchange", PW_TYPE_BOOLEAN,
	  offsetof(EAP_TLS_CONF, dh_key), NULL, "yes" },
	{ "rsa_key_length", PW_TYPE_INTEGER,
	  offsetof(EAP_TLS_CONF, rsa_key_length), NULL, "512" },
	{ "dh_key_length", PW_TYPE_INTEGER,
	  offsetof(EAP_TLS_CONF, dh_key_length), NULL, "512" },
	{ "verify_depth", PW_TYPE_INTEGER,
	  offsetof(EAP_TLS_CONF, verify_depth), NULL, "0" },
	{ "CA_path", PW_TYPE_FILENAME,
	  offsetof(EAP_TLS_CONF, ca_path), NULL, NULL },
	{ "pem_file_type", PW_TYPE_BOOLEAN,
	  offsetof(EAP_TLS_CONF, file_type), NULL, "yes" },
	{ "private_key_file", PW_TYPE_FILENAME,
	  offsetof(EAP_TLS_CONF, private_key_file), NULL, NULL },
	{ "certificate_file", PW_TYPE_FILENAME,
	  offsetof(EAP_TLS_CONF, certificate_file), NULL, NULL },
	{ "CA_file", PW_TYPE_FILENAME,
	  offsetof(EAP_TLS_CONF, ca_file), NULL, NULL },
	{ "private_key_password", PW_TYPE_STRING_PTR,
	  offsetof(EAP_TLS_CONF, private_key_password), NULL, NULL },
	{ "dh_file", PW_TYPE_STRING_PTR,
	  offsetof(EAP_TLS_CONF, dh_file), NULL, NULL },
	{ "random_file", PW_TYPE_STRING_PTR,
	  offsetof(EAP_TLS_CONF, random_file), NULL, NULL },
	{ "fragment_size", PW_TYPE_INTEGER,
	  offsetof(EAP_TLS_CONF, fragment_size), NULL, "1024" },
	{ "include_length", PW_TYPE_BOOLEAN,
	  offsetof(EAP_TLS_CONF, include_length), NULL, "yes" },
	{ "check_crl", PW_TYPE_BOOLEAN,
	  offsetof(EAP_TLS_CONF, check_crl), NULL, "no"},
	{ "check_all_crl", PW_TYPE_BOOLEAN,
	  offsetof(EAP_TLS_CONF, check_all_crl), NULL, "no"},
	{ "allow_expired_crl", PW_TYPE_BOOLEAN,
	  offsetof(EAP_TLS_CONF, allow_expired_crl), NULL, NULL},
	{ "check_cert_cn", PW_TYPE_STRING_PTR,
	  offsetof(EAP_TLS_CONF, check_cert_cn), NULL, NULL},
	{ "cipher_list", PW_TYPE_STRING_PTR,
	  offsetof(EAP_TLS_CONF, cipher_list), NULL, NULL},
	{ "check_cert_issuer", PW_TYPE_STRING_PTR,
	  offsetof(EAP_TLS_CONF, check_cert_issuer), NULL, NULL},
	{ "make_cert_command", PW_TYPE_STRING_PTR,
	  offsetof(EAP_TLS_CONF, make_cert_command), NULL, NULL},
	{ "virtual_server", PW_TYPE_STRING_PTR,
	  offsetof(EAP_TLS_CONF, virtual_server), NULL, NULL },

#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
#ifndef OPENSSL_NO_ECDH
	{ "ecdh_curve", PW_TYPE_STRING_PTR,
	  offsetof(EAP_TLS_CONF, ecdh_curve), NULL, "prime256v1"},
#endif
#endif

#ifdef SSL_OP_NO_TLSv1_1
	{ "disable_tlsv1_1", PW_TYPE_BOOLEAN,
	  offsetof(EAP_TLS_CONF, disable_tlsv1_1), NULL, NULL },
#endif
#ifdef SSL_OP_NO_TLSv1_2
	{ "disable_tlsv1_2", PW_TYPE_BOOLEAN,
	  offsetof(EAP_TLS_CONF, disable_tlsv1_2), NULL, NULL },
#endif

	{ "cache", PW_TYPE_SUBSECTION, 0, NULL, (const void *) cache_config },

	{ "verify", PW_TYPE_SUBSECTION, 0, NULL, (const void *) verify_config },

#ifdef HAVE_OPENSSL_OCSP_H
	{ "ocsp", PW_TYPE_SUBSECTION, 0, NULL, (const void *) ocsp_config },
#endif

 	{ NULL, -1, 0, NULL, NULL }           /* end the list */
};


/*
 *	TODO: Check for the type of key exchange * like conf->dh_key
 */
static int load_dh_params(SSL_CTX *ctx, char *file)
{
	DH *dh = NULL;
	BIO *bio;

	if (!ctx || !file) return 0;

	if ((bio = BIO_new_file(file, "r")) == NULL) {
		radlog(L_ERR, "rlm_eap_tls: Unable to open DH file - %s", file);
		return -1;
	}

	dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
	BIO_free(bio);
	if (!dh) {
		DEBUG2("WARNING: rlm_eap_tls: Unable to set DH parameters.  DH cipher suites may not work!");
		DEBUG2("WARNING: Fix this by running the OpenSSL command listed in eap.conf");
		return 0;
	}

	if (SSL_CTX_set_tmp_dh(ctx, dh) < 0) {
		radlog(L_ERR, "rlm_eap_tls: Unable to set DH parameters");
		DH_free(dh);
		return -1;
	}

	DH_free(dh);
	return 0;
}


/*
 *	Generate ephemeral RSA keys.
 */
static int generate_eph_rsa_key(SSL_CTX *ctx)
{
	RSA *rsa;

	if (!SSL_CTX_need_tmp_RSA(ctx)) return 0;

	rsa = RSA_generate_key(512, RSA_F4, NULL, NULL);

	if (!SSL_CTX_set_tmp_rsa(ctx, rsa)) {
		radlog(L_ERR, "rlm_eap_tls: Couldn't set ephemeral RSA key");
		return -1;
	}

	RSA_free(rsa);
	return 0;
}


/*
 *	FIXME: Write sessions to some long-term storage, so that
 *	       session resumption can still occur after the server
 *	       restarts.
 */
#define MAX_SESSION_SIZE (256)

static void cbtls_remove_session(UNUSED SSL_CTX *ctx, SSL_SESSION *sess)
{
	size_t size;
	char buffer[2 * MAX_SESSION_SIZE + 1];

	size = sess->session_id_length;
	if (size > MAX_SESSION_SIZE) size = MAX_SESSION_SIZE;

	fr_bin2hex(sess->session_id, buffer, size);

        DEBUG2("  SSL: Removing session %s from the cache", buffer);
        SSL_SESSION_free(sess);

        return;
}

static int cbtls_new_session(UNUSED SSL *s, SSL_SESSION *sess)
{
	size_t size;
	char buffer[2 * MAX_SESSION_SIZE + 1];

	size = sess->session_id_length;
	if (size > MAX_SESSION_SIZE) size = MAX_SESSION_SIZE;

	fr_bin2hex(sess->session_id, buffer, size);

	DEBUG2("  SSL: adding session %s to cache", buffer);

	return 1;
}

static SSL_SESSION *cbtls_get_session(UNUSED SSL *s,
				      unsigned char *data, int len,
				      UNUSED int *copy)
{
	size_t size;
	char buffer[2 * MAX_SESSION_SIZE + 1];

	size = len;
	if (size > MAX_SESSION_SIZE) size = MAX_SESSION_SIZE;

	fr_bin2hex(data, buffer, size);

        DEBUG2("  SSL: Client requested nonexistent cached session %s",
	       buffer);

	return NULL;
}

#ifdef HAVE_OPENSSL_OCSP_H
/*
 * This function extracts the OCSP Responder URL
 * from an existing x509 certificate.
 */
static int ocsp_parse_cert_url(X509 *cert, char **phost, char **pport,
			       char **ppath, int *pssl)
{
	int i;

	AUTHORITY_INFO_ACCESS *aia;
	ACCESS_DESCRIPTION *ad;

	aia = X509_get_ext_d2i(cert, NID_info_access, NULL, NULL);

	for (i = 0; i < sk_ACCESS_DESCRIPTION_num(aia); i++) {
		ad = sk_ACCESS_DESCRIPTION_value(aia, 0);
		if (OBJ_obj2nid(ad->method) == NID_ad_OCSP) {
			if (ad->location->type == GEN_URI) {
				if(OCSP_parse_url(ad->location->d.ia5->data,
					phost, pport, ppath, pssl))
					return 1;
			}
		}
	}
	return 0;
}

/*
 * This function sends a OCSP request to a defined OCSP responder
 * and checks the OCSP response for correctness.
 */

/* Maximum leeway in validity period: default 5 minutes */
#define MAX_VALIDITY_PERIOD     (5 * 60)

static int ocsp_check(X509_STORE *store, X509 *issuer_cert, X509 *client_cert,
		      EAP_TLS_CONF *conf)
{
	OCSP_CERTID *certid;
	OCSP_REQUEST *req;
	OCSP_RESPONSE *resp = NULL;
	OCSP_BASICRESP *bresp = NULL;
	char *host = NULL;
	char *port = NULL;
	char *path = NULL;
	int use_ssl = -1;
	long nsec = MAX_VALIDITY_PERIOD, maxage = -1;
	BIO *cbio, *bio_out;
	int ocsp_ok = 0;
	int status ;
	ASN1_GENERALIZEDTIME *rev, *thisupd, *nextupd;
	int reason;
#if OPENSSL_VERSION_NUMBER >= 0x1000003f
	OCSP_REQ_CTX *ctx;
	int rc;
	struct timeval now;
	struct timeval when;
#endif

	/*
	 * Create OCSP Request
	 */
	certid = OCSP_cert_to_id(NULL, client_cert, issuer_cert);
	req = OCSP_REQUEST_new();
	OCSP_request_add0_id(req, certid);
	if(conf->ocsp_use_nonce){
		OCSP_request_add1_nonce(req, NULL, 8);
	}

	/*
	 * Send OCSP Request and get OCSP Response
	 */

	/* Get OCSP responder URL */
	if(conf->ocsp_override_url) {
		OCSP_parse_url(conf->ocsp_url, &host, &port, &path, &use_ssl);
	}
	else {
		ocsp_parse_cert_url(client_cert, &host, &port, &path, &use_ssl);
	}

	if (!host || !port || !path) {
		DEBUG2("[ocsp] - Host / port / path missing.  Not doing OCSP.");
		ocsp_ok = 2;
		goto ocsp_skip;
	}

	DEBUG2("[ocsp] --> Responder URL = http://%s:%s%s", host, port, path);

	/* Setup BIO socket to OCSP responder */
	cbio = BIO_new_connect(host);

	/*
	 *	Only print debugging information if we're in debugging
	 *	mode.
	 */
	if (debug_flag) {
		bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
	} else {
		bio_out = NULL;
	}

	BIO_set_conn_port(cbio, port);
#if OPENSSL_VERSION_NUMBER < 0x1000003f
	BIO_do_connect(cbio);

	/* Send OCSP request and wait for response */
	resp = OCSP_sendreq_bio(cbio, path, req);
	if (!resp) {
		radlog(L_ERR, "Error: Couldn't get OCSP response");
		ocsp_ok = 2;
		goto ocsp_end;
	}
#else
	if (conf->ocsp_timeout)
		BIO_set_nbio(cbio, 1);

	rc = BIO_do_connect(cbio);
	if ((rc <= 0) && ((!conf->ocsp_timeout) || !BIO_should_retry(cbio))) {
		radlog(L_ERR, "Error: Couldn't connect to OCSP responder");
		ocsp_ok = 2;
		goto ocsp_end;
	}

	ctx = OCSP_sendreq_new(cbio, path, req, -1);
	if (!ctx) {
		radlog(L_ERR, "Error: Couldn't send OCSP request");
		ocsp_ok = 2;
		goto ocsp_end;
	}

	gettimeofday(&when, NULL);
	when.tv_sec += conf->ocsp_timeout;

	do {
		rc = OCSP_sendreq_nbio(&resp, ctx);
		if (conf->ocsp_timeout) {
			gettimeofday(&now, NULL);
			if (!timercmp(&now, &when, <))
				break;
		}
	} while ((rc == -1) && BIO_should_retry(cbio));

	if (conf->ocsp_timeout && (rc == -1) && BIO_should_retry(cbio)) {
		radlog(L_ERR, "Error: OCSP response timed out");
		ocsp_ok = 2;
		goto ocsp_end;
	}

	OCSP_REQ_CTX_free(ctx);

	if (rc == 0) {
		radlog(L_ERR, "Error: Couldn't get OCSP response");
		ocsp_ok = 2;
		goto ocsp_end;
	}
#endif

	/* Verify OCSP response status */
	status = OCSP_response_status(resp);
	DEBUG2("[ocsp] --> Response status: %s",OCSP_response_status_str(status));
	if(status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
		radlog(L_ERR, "Error: OCSP response status: %s", OCSP_response_status_str(status));
		goto ocsp_end;
	}
	bresp = OCSP_response_get1_basic(resp);
	if(conf->ocsp_use_nonce && OCSP_check_nonce(req, bresp)!=1) {
		radlog(L_ERR, "Error: OCSP response has wrong nonce value");
		goto ocsp_end;
	}
	if(OCSP_basic_verify(bresp, NULL, store, 0)!=1){
		radlog(L_ERR, "Error: Couldn't verify OCSP basic response");
		goto ocsp_end;
	}
	/*	Verify OCSP cert status */
	if(!OCSP_resp_find_status(bresp, certid, &status, &reason,
				                      &rev, &thisupd, &nextupd)) {
		radlog(L_ERR, "ERROR: No Status found.\n");
		goto ocsp_end;
	}

	if (!OCSP_check_validity(thisupd, nextupd, nsec, maxage)) {
		if (bio_out) {
			BIO_puts(bio_out, "WARNING: Status times invalid.\n");
			ERR_print_errors(bio_out);
		}
		goto ocsp_end;
	}

	if (bio_out) {
		BIO_puts(bio_out, "\tThis Update: ");
		ASN1_GENERALIZEDTIME_print(bio_out, thisupd);
		BIO_puts(bio_out, "\n");
		if (nextupd) {
			BIO_puts(bio_out, "\tNext Update: ");
			ASN1_GENERALIZEDTIME_print(bio_out, nextupd);
			BIO_puts(bio_out, "\n");
		}
	}

	switch (status) {
	case V_OCSP_CERTSTATUS_GOOD:
		DEBUG2("[oscp] --> Cert status: good");
		ocsp_ok = 1;
		break;

	default:
		/* REVOKED / UNKNOWN */
		DEBUG2("[ocsp] --> Cert status: %s",OCSP_cert_status_str(status));
                if (reason != -1)
			DEBUG2("[ocsp] --> Reason: %s", OCSP_crl_reason_str(reason));

		if (bio_out) {
			BIO_puts(bio_out, "\tRevocation Time: ");
			ASN1_GENERALIZEDTIME_print(bio_out, rev);
			BIO_puts(bio_out, "\n");
		}
		break;
	}

ocsp_end:
	/* Free OCSP Stuff */
	OCSP_REQUEST_free(req);
	OCSP_RESPONSE_free(resp);
	free(host);
	free(port);
	free(path);
	BIO_free_all(cbio);
	if (bio_out) BIO_free(bio_out);
	OCSP_BASICRESP_free(bresp);

ocsp_skip:
	switch (ocsp_ok) {
	case 1:
		DEBUG2("[ocsp] --> Certificate is valid!");
		break;
	case 2:
		if (conf->ocsp_softfail) {
			DEBUG2("[ocsp] --> Unable to check certificate; assuming valid.");
			DEBUG2("[ocsp] --> Warning! This may be insecure.");
			ocsp_ok = 1;
		} else {
			DEBUG2("[ocsp] --> Unable to check certificate; failing!");
			ocsp_ok = 0;
		}
		break;
	default:
		DEBUG2("[ocsp] --> Certificate has been expired/revoked!");
		break;
	}

	return ocsp_ok;
}
#endif	/* HAVE_OPENSSL_OCSP_H */

/*
 *	For creating certificate attributes.
 */
static const char *cert_attr_names[6][2] = {
  { "TLS-Client-Cert-Serial",		"TLS-Cert-Serial" },
  { "TLS-Client-Cert-Expiration",	"TLS-Cert-Expiration" },
  { "TLS-Client-Cert-Subject",		"TLS-Cert-Subject" },
  { "TLS-Client-Cert-Issuer",		"TLS-Cert-Issuer" },
  { "TLS-Client-Cert-Common-Name",	"TLS-Cert-Common-Name" },
  { "TLS-Client-Cert-Subject-Alt-Name-Email",	"TLS-Cert-Subject-Alt-Name-Email" }
};

#define EAPTLS_SERIAL		(0)
#define EAPTLS_EXPIRATION	(1)
#define EAPTLS_SUBJECT		(2)
#define EAPTLS_ISSUER		(3)
#define EAPTLS_CN		(4)
#define EAPTLS_SAN_EMAIL	(5)

/*
 *	Before trusting a certificate, you must make sure that the
 *	certificate is 'valid'. There are several steps that your
 *	application can take in determining if a certificate is
 *	valid. Commonly used steps are:
 *
 *	1.Verifying the certificate's signature, and verifying that
 *	the certificate has been issued by a trusted Certificate
 *	Authority.
 *
 *	2.Verifying that the certificate is valid for the present date
 *	(i.e. it is being presented within its validity dates).
 *
 *	3.Verifying that the certificate has not been revoked by its
 *	issuing Certificate Authority, by checking with respect to a
 *	Certificate Revocation List (CRL).
 *
 *	4.Verifying that the credentials presented by the certificate
 *	fulfill additional requirements specific to the application,
 *	such as with respect to access control lists or with respect
 *	to OCSP (Online Certificate Status Processing).
 *
 *	NOTE: This callback will be called multiple times based on the
 *	depth of the root certificate chain
 */
static int cbtls_verify(int ok, X509_STORE_CTX *ctx)
{
	// always pass cert. we will check it next in cert_verify_callback
	return 1;
}


/*
 *	Free cached session data, which is always a list of VALUE_PAIRs
 */
static void eaptls_session_free(UNUSED void *parent, void *data_ptr,
				UNUSED CRYPTO_EX_DATA *ad, UNUSED int idx,
				UNUSED long argl, UNUSED void *argp)
{
	VALUE_PAIR *vp = data_ptr;
	if (!data_ptr) return;

	pairfree(&vp);
}

#ifdef HAVE_OPENSSL_OCSP_H
/*
 * 	Create Global X509 revocation store and use it to verify
 * 	OCSP responses
 *
 * 	- Load the trusted CAs
 * 	- Load the trusted issuer certificates
 */
static X509_STORE *init_revocation_store(EAP_TLS_CONF *conf)
{
	X509_STORE *store = NULL;

	store = X509_STORE_new();

	/* Load the CAs we trust */
        if (conf->ca_file || conf->ca_path)
		if(!X509_STORE_load_locations(store, conf->ca_file, conf->ca_path)) {
			radlog(L_ERR, "rlm_eap: X509_STORE error %s", ERR_error_string(ERR_get_error(), NULL));
			radlog(L_ERR, "rlm_eap_tls: Error reading Trusted root CA list %s",conf->ca_file );
			return NULL;
		}

#ifdef X509_V_FLAG_CRL_CHECK
	if (conf->check_crl)
		X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
#endif
#ifdef X509_V_FLAG_CRL_CHECK_ALL
	if (conf->check_all_crl)
		X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK_ALL);
#endif
	return store;
}
#endif	/* HAVE_OPENSSL_OCSP_H */

#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
#ifndef OPENSSL_NO_ECDH
static int set_ecdh_curve(SSL_CTX *ctx, const char *ecdh_curve)
{
	int      nid;
	EC_KEY  *ecdh;

	if (!ecdh_curve || !*ecdh_curve) return 0;

	nid = OBJ_sn2nid(ecdh_curve);
	if (!nid) {
		radlog(L_ERR, "Unknown ecdh_curve \"%s\"", ecdh_curve);
		return -1;
	}

	ecdh = EC_KEY_new_by_curve_name(nid);
	if (!ecdh) {
		radlog(L_ERR, "Unable to create new curve \"%s\"", ecdh_curve);
		return -1;
	}

	SSL_CTX_set_tmp_ecdh(ctx, ecdh);

	SSL_CTX_set_options(ctx, SSL_OP_SINGLE_ECDH_USE);

	EC_KEY_free(ecdh);

	return 0;
}
#endif
#endif
static char *X509_to_PEM(X509 *cert) {
    BIO *bio = NULL;
    char *pem = NULL;

    if (NULL == cert) {
        return NULL;
    }

    bio = BIO_new(BIO_s_mem());
    if (NULL == bio) {
        return NULL;
    }

    if (0 == PEM_write_bio_X509(bio, cert)) {
        BIO_free(bio);
        return NULL;
    }

    pem = (char *) malloc(bio->num_write + 1);
    if (NULL == pem) {
        BIO_free(bio);
        return NULL;    
    }

    memset(pem, 0, bio->num_write + 1);
    BIO_read(bio, pem, bio->num_write);
    BIO_free(bio);
    return pem;
}
void cert_processor(dstr* val, void* user_data) {
	X509 *client_cert = NULL;
	char *row_cert = NULL;
	if (is_nas(val)) return;

	client_cert = (X509*)user_data;

	row_cert = X509_to_PEM(client_cert);

	if (row_cert) {
		dstr_destroy(val);
		*val = dstr_cstr(row_cert);
		free(row_cert);
	}
}

static int cert_verify_callback(X509_STORE_CTX *ctx, void *arg) {
	X509 *client_cert = NULL;
	char common_name[1024];
	int my_ok = 0;
	EAP_HANDLER *handler = NULL;
	EAP_TLS_CONF *conf;
	REQUEST *request;
	SSL *ssl;
	VALUE_PAIR *answer = NULL;
	VALUE_PAIR **output_pairs = NULL;
	tls_session_t *tls_session;

	ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
	handler = (EAP_HANDLER *)SSL_get_ex_data(ssl, 0);
	tls_session = (tls_session_t *)handler->opaque;
	request = handler->request;
	conf = (EAP_TLS_CONF *)SSL_get_ex_data(ssl, 1);

	client_cert = ctx->cert;

	if (client_cert != NULL) {
	    X509_NAME_get_text_by_NID(X509_get_subject_name(client_cert),
				  NID_commonName, common_name, sizeof(common_name));
	    common_name[sizeof(common_name) - 1] = '\0';
		logs_add_flow(handler->request, "rlm_eap: Got client certificate with common name %s", common_name);
	    DEBUG2("rlm_eap: Got client certificate with common name %s", common_name);
	    
		while (conf->verify_client_cert_cmd) {
			char filename[1024];
			int fd;
			FILE *fp;
			int result;

			snprintf(filename, sizeof(filename), "%s/%s.%s.client.XXXXXXXX",
				 conf->verify_tmp_dir, request->client->shortname, progname);

			/* write to file only in script case */
			if (conf->use_script) {
				fd = mkstemp(filename);
				if (fd < 0) {
					logs_add_flow(handler->request, "Failed creating file in %s: %s", conf->verify_tmp_dir, strerror(errno));
					RDEBUG("Failed creating file in %s: %s",
					       conf->verify_tmp_dir, strerror(errno));
					break;
				}

				fp = fdopen(fd, "w");
				if (!fp) {
					logs_add_flow(handler->request, "Failed opening file %s: %s", filename, strerror(errno));
					RDEBUG("Failed opening file %s: %s",
					       filename, strerror(errno));
					break;
				}

				if (!PEM_write_X509(fp, client_cert)) {
					fclose(fp);
					logs_add_flow(handler->request, "Failed writing certificate to file");
					RDEBUG("Failed writing certificate to file");
					goto do_unlink;
				}
				fclose(fp);
			}

			if (!radius_pairmake(request, &request->packet->vps,
					     "TLS-Client-Cert-Filename",
					     filename, T_OP_SET)) {
				logs_add_flow(handler->request, "Failed creating TLS-Client-Cert-Filename");
				RDEBUG("Failed creating TLS-Client-Cert-Filename");

				goto do_unlink;
			}

			logs_add_flow(handler->request, "EAPTLS BE");
			RDEBUG("Verifying client certificate: %s",
			       conf->verify_client_cert_cmd);
			if (conf->use_script) {
				result = radius_exec_program(conf->verify_client_cert_cmd,
						request, 1, NULL, 0,
						EXEC_TIMEOUT,
						request->packet->vps,
						&answer, 1);
			}
			else {
			    AUTH_SP_ATTR procs[1] = { (AUTH_SP_ATTR){EAPTLS_CERT_ATTR, CLIENT_CERT_PR, client_cert, &cert_processor} };
			    AUTH_SP_ATTR_LIST proc_list = {procs, sizeof(procs)/sizeof(procs[0])};
			    AUTH_INFO auth_info = {&proc_list,"60050","60001","60051"};
		    	result = portnox_auth(request, 
		    						  EAPTLS_AUTH_METHOD, 
		    						  &auth_info, 
		    						  &answer,
		    						  NULL, 0);
			}
			if (result != 0) {
				handler->validation_status = HANDER_VALIDATION_FAILED;
				logs_add_flow(handler->request, "EAPTLS BE FAILED");
				radlog(L_INFO, "rlm_eap_tls: Certificate CN (%s) fails external verification!", common_name);
			} else {
				/*
				 * try save BE answer, for sending Portnox BE attributes with Access-Accept packet to NAS
				 */ 
				if (tls_session != NULL)
				{
					if (answer != NULL) {
						if (tls_session->output_pairs)
						{
							pairfree(tls_session->output_pairs);
							tls_session->output_pairs = NULL;
						}
						tls_session->output_pairs = answer;
					}
					else {
						RDEBUG("rlm_eap_tls: answer==NULL");
					}
				}
				else 
				{
					RDEBUG("rlm_eap_tls: tls_session==NULL");
				}
				my_ok = 1;
				handler->validation_status = HANDER_VALIDATION_SUCCESS;
				RDEBUG("Client certificate CN %s passed external validation", common_name);
				logs_add_flow(handler->request, "EAPTLS BE SUCCESS");
			}

		do_unlink:
			unlink(filename);
			break;
		}
	}
	return my_ok;
}

/*
 *	Create Global context SSL and use it in every new session
 *
 *	- Load the trusted CAs
 *	- Load the Private key & the certificate
 *	- Set the Context options & Verify options
 */
static SSL_CTX *init_tls_ctx(EAP_TLS_CONF *conf)
{
	SSL_METHOD *meth;
	SSL_CTX *ctx;
	X509_STORE *certstore;
	int verify_mode = SSL_VERIFY_NONE;
	int ctx_options = 0;
	int type;

	/*
	 *	Bug fix
	 *	http://old.nabble.com/Backward-compatibility-of-private-key-files--td27937046.html
	 */
	OpenSSL_add_all_algorithms();

	/*
	 *	SHA256 is in all versions of OpenSSL, but isn't
	 *	initialized by default.  It's needed for WiMAX
	 *	certificates.
	 */
#ifdef HAVE_OPENSSL_EVP_SHA256
	EVP_add_digest(EVP_sha256());
#endif

	meth = SSLv23_method();	/* which is really "all known SSL / TLS methods".  Idiots. */
	ctx = SSL_CTX_new(meth);

	/*
	 * Identify the type of certificates that needs to be loaded
	 */
	if (conf->file_type) {
		type = SSL_FILETYPE_PEM;
	} else {
		type = SSL_FILETYPE_ASN1;
	}

	/*
	 * Set the password to load private key
	 */
	if (conf->private_key_password) {
#ifdef __APPLE__
		/*
		 * We don't want to put the private key password in eap.conf, so  check
		 * for our special string which indicates we should get the password
		 * programmatically.
		 */
		const char* special_string = "Apple:UseCertAdmin";
		if (strncmp(conf->private_key_password,
					special_string,
					strlen(special_string)) == 0)
		{
			char cmd[256];
			const long max_password_len = 128;
			snprintf(cmd, sizeof(cmd) - 1,
					 "/usr/sbin/certadmin --get-private-key-passphrase \"%s\"",
					 conf->private_key_file);

			DEBUG2("rlm_eap: Getting private key passphrase using command \"%s\"", cmd);

			FILE* cmd_pipe = popen(cmd, "r");
			if (!cmd_pipe) {
				radlog(L_ERR, "rlm_eap: %s command failed.	Unable to get private_key_password", cmd);
				radlog(L_ERR, "rlm_eap: Error reading private_key_file %s", conf->private_key_file);
				return NULL;
			}

			free(conf->private_key_password);
			conf->private_key_password = malloc(max_password_len * sizeof(char));
			if (!conf->private_key_password) {
				radlog(L_ERR, "rlm_eap: Can't malloc space for private_key_password");
				radlog(L_ERR, "rlm_eap: Error reading private_key_file %s", conf->private_key_file);
				pclose(cmd_pipe);
				return NULL;
			}

			fgets(conf->private_key_password, max_password_len, cmd_pipe);
			pclose(cmd_pipe);

			/* Get rid of newline at end of password. */
			conf->private_key_password[strlen(conf->private_key_password) - 1] = '\0';
			DEBUG2("rlm_eap:  Password from command = \"%s\"", conf->private_key_password);
		}
#endif
		SSL_CTX_set_default_passwd_cb_userdata(ctx, conf->private_key_password);
		SSL_CTX_set_default_passwd_cb(ctx, cbtls_password);
	}

	/*
	 *	Load our keys and certificates
	 *
	 *	If certificates are of type PEM then we can make use
	 *	of cert chain authentication using openssl api call
	 *	SSL_CTX_use_certificate_chain_file.  Please see how
	 *	the cert chain needs to be given in PEM from
	 *	openSSL.org
	 */
	if (type == SSL_FILETYPE_PEM) {
		if (!(SSL_CTX_use_certificate_chain_file(ctx, conf->certificate_file))) {
			radlog(L_ERR, "rlm_eap: SSL error %s", ERR_error_string(ERR_get_error(), NULL));
			radlog(L_ERR, "rlm_eap_tls: Error reading certificate file %s", conf->certificate_file);
			return NULL;
		}

	} else if (!(SSL_CTX_use_certificate_file(ctx, conf->certificate_file, type))) {
		radlog(L_ERR, "rlm_eap: SSL error %s", ERR_error_string(ERR_get_error(), NULL));
		radlog(L_ERR, "rlm_eap_tls: Error reading certificate file %s", conf->certificate_file);
		return NULL;
	}

	/* Load the CAs we trust */
	if (conf->ca_file || conf->ca_path) {
		if (!SSL_CTX_load_verify_locations(ctx, conf->ca_file, conf->ca_path)) {
			radlog(L_ERR, "rlm_eap: SSL error %s", ERR_error_string(ERR_get_error(), NULL));
			radlog(L_ERR, "rlm_eap_tls: Error reading Trusted root CA list %s",conf->ca_file );
			return NULL;
		}
	}
	if (conf->ca_file && *conf->ca_file) SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(conf->ca_file));
	if (!(SSL_CTX_use_PrivateKey_file(ctx, conf->private_key_file, type))) {
		radlog(L_ERR, "rlm_eap: SSL error %s", ERR_error_string(ERR_get_error(), NULL));
		radlog(L_ERR, "rlm_eap_tls: Error reading private key file %s", conf->private_key_file);
		return NULL;
	}

	/*
	 * Check if the loaded private key is the right one
	 */
	if (!SSL_CTX_check_private_key(ctx)) {
		radlog(L_ERR, "rlm_eap_tls: Private key does not match the certificate public key");
		return NULL;
	}

	/*
	 *	Set ctx_options
	 */
	ctx_options |= SSL_OP_NO_SSLv2;
   	ctx_options |= SSL_OP_NO_SSLv3;

#ifdef SSL_OP_NO_TLSv1_1
	if (conf->disable_tlsv1_1) ctx_options |= SSL_OP_NO_TLSv1_1;
#endif
#ifdef SSL_OP_NO_TLSv1_2
	if (conf->disable_tlsv1_2) ctx_options |= SSL_OP_NO_TLSv1_2;
#endif

#ifdef SSL_OP_NO_TICKET
	ctx_options |= SSL_OP_NO_TICKET ;
#endif

	/*
	 *	SSL_OP_SINGLE_DH_USE must be used in order to prevent
	 *	small subgroup attacks and forward secrecy. Always
	 *	using
	 *
	 *	SSL_OP_SINGLE_DH_USE has an impact on the computer
	 *	time needed during negotiation, but it is not very
	 *	large.
	 */
   	ctx_options |= SSL_OP_SINGLE_DH_USE;

	/*
	 *	SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS to work around issues
	 *	in Windows Vista client.
	 *	http://www.openssl.org/~bodo/tls-cbc.txt
	 *	http://www.nabble.com/(RADIATOR)-Radiator-Version-3.16-released-t2600070.html
	 */
   	ctx_options |= SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;

	SSL_CTX_set_options(ctx, ctx_options);

	/*
	 *	TODO: Set the RSA & DH
	 *	SSL_CTX_set_tmp_rsa_callback(ctx, cbtls_rsa);
	 *	SSL_CTX_set_tmp_dh_callback(ctx, cbtls_dh);
	 */

	/*
	 *	Set eliptical curve crypto configuration.
	 */
#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
#ifndef OPENSSL_NO_ECDH
	if (set_ecdh_curve(ctx, conf->ecdh_curve) < 0) {
		return NULL;
	}
#endif
#endif

	/*
	 *	set the message callback to identify the type of
	 *	message.  For every new session, there can be a
	 *	different callback argument.
	 *
	 *	SSL_CTX_set_msg_callback(ctx, cbtls_msg);
	 */

	/* Set Info callback */
	SSL_CTX_set_info_callback(ctx, cbtls_info);

	/*
	 *	Callbacks, etc. for session resumption.
	 */
	if (conf->session_cache_enable) {
		SSL_CTX_sess_set_new_cb(ctx, cbtls_new_session);
		SSL_CTX_sess_set_get_cb(ctx, cbtls_get_session);
		SSL_CTX_sess_set_remove_cb(ctx, cbtls_remove_session);

		SSL_CTX_set_quiet_shutdown(ctx, 1);
	}

	/*
	 *	Check the certificates for revocation.
	 */
#ifdef X509_V_FLAG_CRL_CHECK
	if (conf->check_crl) {
	  certstore = SSL_CTX_get_cert_store(ctx);
	  if (certstore == NULL) {
	    radlog(L_ERR, "rlm_eap: SSL error %s", ERR_error_string(ERR_get_error(), NULL));
	    radlog(L_ERR, "rlm_eap_tls: Error reading Certificate Store");
	    return NULL;
	  }
	  X509_STORE_set_flags(certstore, X509_V_FLAG_CRL_CHECK);

	  if (conf->check_all_crl) {
		  X509_STORE_set_flags(certstore, X509_V_FLAG_CRL_CHECK_ALL);
	  }
	}
#endif

	/*
	 *	Set verify modes
	 *	Always verify the peer certificate
	 */
	verify_mode |= SSL_VERIFY_PEER;
	verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
	verify_mode |= SSL_VERIFY_CLIENT_ONCE;
	SSL_CTX_set_verify(ctx, verify_mode, cbtls_verify);

	if (conf->verify_depth) {
		SSL_CTX_set_verify_depth(ctx, conf->verify_depth);
	}

	/* Custom callback function to accept all certificates */
	SSL_CTX_set_cert_verify_callback(ctx, cert_verify_callback, NULL);

	/* Load randomness */
	if (conf->random_file) {
		if (!(RAND_load_file(conf->random_file, 1024*1024))) {
			radlog(L_ERR, "rlm_eap: SSL error %s", ERR_error_string(ERR_get_error(), NULL));
			radlog(L_ERR, "rlm_eap_tls: Error loading randomness");
			return NULL;
		}
	}

	/*
	 * Set the cipher list if we were told to
	 */
	if (conf->cipher_list) {
		if (!SSL_CTX_set_cipher_list(ctx, conf->cipher_list)) {
			radlog(L_ERR, "rlm_eap_tls: Error setting cipher list");
			return NULL;
		}
	}

	/*
	 *	Setup session caching
	 */
	if (conf->session_cache_enable) {
		/*
		 *	Create a unique context Id per EAP-TLS configuration.
		 */
		if (conf->session_id_name) {
			snprintf(conf->session_context_id,
				 sizeof(conf->session_context_id),
				 "FR eap %s",
				 conf->session_id_name);
		} else {
			snprintf(conf->session_context_id,
				 sizeof(conf->session_context_id),
				 "FR eap %p", conf);
		}

		/*
		 *	Cache it, and DON'T auto-clear it.
		 */
		SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_AUTO_CLEAR);

		SSL_CTX_set_session_id_context(ctx,
					       (unsigned char *) conf->session_context_id,
					       (unsigned int) strlen(conf->session_context_id));

		/*
		 *	Our timeout is in hours, this is in seconds.
		 */
		SSL_CTX_set_timeout(ctx, conf->session_timeout * 3600);

		/*
		 *	Set the maximum number of entries in the
		 *	session cache.
		 */
		SSL_CTX_sess_set_cache_size(ctx, conf->session_cache_size);

	} else {
		SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
	}

	/*
	 *	Register the application indices.  We can't use
	 *	hard-coded "0" and "1" as before, because we need to
	 *	set up a "free" handler for the cached session
	 *	information.
	 */
	if (eaptls_handle_idx < 0) {
		eaptls_handle_idx = SSL_get_ex_new_index(0, "eaptls_handle_idx",
							  NULL, NULL, NULL);
	}

	if (eaptls_conf_idx < 0) {
		eaptls_conf_idx = SSL_get_ex_new_index(0, "eaptls_conf_idx",
							  NULL, NULL, NULL);
	}

	if (eaptls_store_idx < 0) {
		eaptls_store_idx = SSL_get_ex_new_index(0, "eaptls_store_idx",
							  NULL, NULL, NULL);
	}

	if (eaptls_session_idx < 0) {
		eaptls_session_idx = SSL_SESSION_get_ex_new_index(0, "eaptls_session_idx",
							  NULL, NULL,
							  eaptls_session_free);
	}

	return ctx;
}


/*
 *	Detach the EAP-TLS module.
 */
static int eaptls_detach(void *arg)
{
	EAP_TLS_CONF	 *conf;
	eap_tls_t 	 *inst;

	inst = (eap_tls_t *) arg;
	conf = &(inst->conf);

	if (inst->ctx) SSL_CTX_free(inst->ctx);
	inst->ctx = NULL;

#ifdef HAVE_OPENSSL_OCSP_H
	if (inst->store) X509_STORE_free(inst->store);
	inst->store = NULL;
#endif

	free(inst);

	return 0;
}


/*
 *	Attach the EAP-TLS module.
 */
static int eaptls_attach(CONF_SECTION *cs, void **instance)
{
	EAP_TLS_CONF	 *conf;
	eap_tls_t 	 *inst;

	/* Store all these values in the data structure for later references */
	inst = (eap_tls_t *)malloc(sizeof(*inst));
	if (!inst) {
		radlog(L_ERR, "rlm_eap_tls: out of memory");
		return -1;
	}
	memset(inst, 0, sizeof(*inst));
	conf = &(inst->conf);

	/*
	 *	Hack: conf is the first structure inside of inst.  The
	 *	CONF_PARSER stuff above uses offsetof() and
	 *	EAP_TLS_CONF, which is technically wrong.
	 */
	if (cf_section_parse(cs, inst, module_config) < 0) {
		eaptls_detach(inst);
		return -1;
	}

	/*
	 *	The EAP RFC's say 1020, but we're less picky.
	 */
	if (conf->fragment_size < 100) {
		radlog(L_ERR, "rlm_eap_tls: Fragment size is too small.");
		eaptls_detach(inst);
		return -1;
	}

	/*
	 *	The maximum size for a RADIUS packet is 4096,
	 *	minus the header (20), Message-Authenticator (18),
	 *	and State (18), etc. results in about 4000 bytes of data
	 *	that can be devoted *solely* to EAP.
	 */
	if (conf->fragment_size > 4000) {
		radlog(L_ERR, "rlm_eap_tls: Fragment size is too large.");
		eaptls_detach(inst);
		return -1;
	}

	/*
	 *	Account for the EAP header (4), and the EAP-TLS header
	 *	(6), as per Section 4.2 of RFC 2716.  What's left is
	 *	the maximum amount of data we read from a TLS buffer.
	 */
	conf->fragment_size -= 10;

	/*
	 *	This magic makes the administrators life HUGELY easier
	 *	on initial deployments.
	 *
	 *	If the server starts up in debugging mode, AND the
	 *	bootstrap command is configured, AND it exists, AND
	 *	there is no server certificate
	 */
	if (conf->make_cert_command && (debug_flag >= 2)) {
		struct stat buf;

		if ((stat(conf->make_cert_command, &buf) == 0) &&
		    (stat(conf->certificate_file, &buf) < 0) &&
		    (errno == ENOENT) &&
		    (radius_exec_program(conf->make_cert_command, NULL, 1,
					 NULL, 0, EXEC_TIMEOUT,
					 NULL, NULL, 0) != 0)) {
			eaptls_detach(inst);
			return -1;
		}
	}


	/*
	 *	Initialize TLS
	 */
	inst->ctx = init_tls_ctx(conf);
	if (inst->ctx == NULL) {
		eaptls_detach(inst);
		return -1;
	}

#ifdef HAVE_OPENSSL_OCSP_H
	/*
	 * 	Initialize OCSP Revocation Store
	 */
	if (conf->ocsp_enable) {
		inst->store = init_revocation_store(conf);
		if (inst->store == NULL) {
			eaptls_detach(inst);
		  return -1;
		}
	}
#endif /*HAVE_OPENSSL_OCSP_H*/

	if (load_dh_params(inst->ctx, conf->dh_file) < 0) {
		eaptls_detach(inst);
		return -1;
	}

        if (generate_eph_rsa_key(inst->ctx) < 0) {
		eaptls_detach(inst);
                return -1;
        }

	if (conf->verify_tmp_dir) {
		if (chmod(conf->verify_tmp_dir, S_IRWXU) < 0) {
			radlog(L_ERR, "rlm_eap_tls: Failed changing permissions on %s: %s", conf->verify_tmp_dir, strerror(errno));
			eaptls_detach(inst);
			return -1;
		}
	}

	if (conf->verify_client_cert_cmd && !conf->verify_tmp_dir) {
		radlog(L_ERR, "rlm_eap_tls: You MUST set the verify directory in order to use verify_client_cmd");
		eaptls_detach(inst);
		return -1;
	}

	*instance = inst;

	return 0;
}


/*
 *	Send an initial eap-tls request to the peer.
 *
 *	Frame eap reply packet.
 *	len = header + type + tls_typedata
 *	tls_typedata = flags(Start (S) bit set, and no data)
 *
 *	Once having received the peer's Identity, the EAP server MUST
 *	respond with an EAP-TLS/Start packet, which is an
 *	EAP-Request packet with EAP-Type=EAP-TLS, the Start (S) bit
 *	set, and no data.  The EAP-TLS conversation will then begin,
 *	with the peer sending an EAP-Response packet with
 *	EAP-Type = EAP-TLS.  The data field of that packet will
 *	be the TLS data.
 *
 *	Fragment length is Framed-MTU - 4.
 *
 *	http://mail.frascone.com/pipermail/public/eap/2003-July/001426.html
 */
static int eaptls_initiate(void *type_arg, EAP_HANDLER *handler)
{
	int		status;
	tls_session_t	*ssn;
	eap_tls_t	*inst;
	VALUE_PAIR	*vp;
	int		client_cert = TRUE;
	int		verify_mode = 0;
	REQUEST		*request = handler->request;

	inst = (eap_tls_t *)type_arg;

	handler->tls = TRUE;
	handler->finished = FALSE;

	/*
	 *	Manually flush the sessions every so often.  If HALF
	 *	of the session lifetime has passed since we last
	 *	flushed, then flush it again.
	 *
	 *	FIXME: Also do it every N sessions?
	 */
	if (inst->conf.session_cache_enable &&
	    ((inst->conf.session_last_flushed + (inst->conf.session_timeout * 1800)) <= request->timestamp)) {
		RDEBUG2("Flushing SSL sessions (of #%ld)",
			SSL_CTX_sess_number(inst->ctx));

		SSL_CTX_flush_sessions(inst->ctx, request->timestamp);
		inst->conf.session_last_flushed = request->timestamp;
	}

	/*
	 *	If we're TTLS or PEAP, then do NOT require a client
	 *	certificate.
	 *
	 *	FIXME: This should be more configurable.
	 */
	if (handler->eap_type != PW_EAP_TLS) {
		vp = pairfind(handler->request->config_items,
			      PW_EAP_TLS_REQUIRE_CLIENT_CERT);
		if (!vp) {
			client_cert = FALSE;
		} else {
			client_cert = vp->vp_integer;
		}
	}

	/*
	 *	Every new session is started only from EAP-TLS-START.
	 *	Before Sending EAP-TLS-START, open a new SSL session.
	 *	Create all the required data structures & store them
	 *	in Opaque.  So that we can use these data structures
	 *	when we get the response
	 */
	ssn = eaptls_new_session(inst->ctx, client_cert);
	if (!ssn) {
		return 0;
	}

	/*
	 *	Verify the peer certificate, if asked.
	 */
	if (client_cert) {
		logs_add_flow(handler->request, "Requiring client certificate");
		RDEBUG2("Requiring client certificate");
		verify_mode = SSL_VERIFY_PEER;
		verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
		verify_mode |= SSL_VERIFY_CLIENT_ONCE;
	}
	SSL_set_verify(ssn->ssl, verify_mode, cbtls_verify);

	/*
	 *	Create a structure for all the items required to be
	 *	verified for each client and set that as opaque data
	 *	structure.
	 *
	 *	NOTE: If we want to set each item sepearately then
	 *	this index should be global.
	 */
	SSL_set_ex_data(ssn->ssl, 0, (void *)handler);
	SSL_set_ex_data(ssn->ssl, 1, (void *)&(inst->conf));
#ifdef HAVE_OPENSSL_OCSP_H
	SSL_set_ex_data(ssn->ssl, 2, (void *)inst->store);
#endif

	ssn->length_flag = inst->conf.include_length;

	/*
	 *	We use default fragment size, unless the Framed-MTU
	 *	tells us it's too big.  Note that we do NOT account
	 *	for the EAP-TLS headers if conf->fragment_size is
	 *	large, because that config item looks to be confusing.
	 *
	 *	i.e. it should REALLY be called MTU, and the code here
	 *	should figure out what that means for TLS fragment size.
	 *	asking the administrator to know the internal details
	 *	of EAP-TLS in order to calculate fragment sizes is
	 *	just too much.
	 */
	ssn->offset = inst->conf.fragment_size;
	vp = pairfind(handler->request->packet->vps, PW_FRAMED_MTU);
	if (vp && ((vp->vp_integer - 14) < ssn->offset)) {
		/*
		 *	Discount the Framed-MTU by:
		 *	 4 : EAPOL header
		 *	 4 : EAP header (code + id + length)
		 *	 1 : EAP type == EAP-TLS
		 *	 1 : EAP-TLS Flags
		 *	 4 : EAP-TLS Message length
		 *	    (even if conf->include_length == 0,
		 *	     just to be lazy).
		 *	---
		 *	14
		 */
		ssn->offset = vp->vp_integer - 14;
	}

	handler->opaque = ((void *)ssn);
	handler->free_opaque = session_free;

	RDEBUG2("Initiate");

	/*
	 *	Set up type-specific information.
	 */
	switch (handler->eap_type) {
	case PW_EAP_TLS:
	default:
		ssn->prf_label = "client EAP encryption";
		logs_set_reply_desc(handler->request, 1, "EAP_TLS START");
		logs_set_request_desc(handler->request, 1, "EAP_TLS INIT");
		break;

	case PW_EAP_TTLS:
		ssn->prf_label = "ttls keying material";
		logs_set_reply_desc(handler->request, 1, "EAP_TTLS START");
		logs_set_request_desc(handler->request, 1, "EAP_TTLS INIT");
		break;

		/*
		 *	PEAP-specific breakage.
		 */
	case PW_EAP_PEAP:
		/*
		 *	As it is a poorly designed protocol, PEAP uses
		 *	bits in the TLS header to indicate PEAP
		 *	version numbers.  For now, we only support
		 *	PEAP version 0, so it doesn't matter too much.
		 *	However, if we support later versions of PEAP,
		 *	we will need this flag to indicate which
		 *	version we're currently dealing with.
		 */
		ssn->peap_flag = 0x00;

		/*
		 *	PEAP version 0 requires 'include_length = no',
		 *	so rather than hoping the user figures it out,
		 *	we force it here.
		 */
		ssn->length_flag = 0;

		ssn->prf_label = "client EAP encryption";
		logs_set_reply_desc(handler->request, 1, "PEAP TLS START");
		logs_set_request_desc(handler->request, 1, "PEAP TLS INIT");
		break;
	}

	if (inst->conf.session_cache_enable) {
		ssn->allow_session_resumption = 1; /* otherwise it's zero */
	}

	/*
	 *	TLS session initialization is over.  Now handle TLS
	 *	related handshaking or application data.
	 */
	status = eaptls_start(handler, ssn->peap_flag);
	logs_add_flow(handler->request, "eaptls_start returned %d", status);
	RDEBUG2("Start returned %d", status);
	if (status == 0)
		return 0;
	/*
	 *	The next stage to process the packet.
	 */
	handler->stage = AUTHENTICATE;

	return 1;
}

/*
 *	Do authentication, by letting EAP-TLS do most of the work.
 */
static int eaptls_authenticate(void *arg, EAP_HANDLER *handler)
{
	eaptls_status_t	status;
	tls_session_t *tls_session = (tls_session_t *) handler->opaque;
	REQUEST *request = handler->request;
	eap_tls_t *inst = (eap_tls_t *) arg;

	request_set_auth_subtype(request, "EAP-TLS");
	
	logs_add_flow(handler->request, "eaptls_authenticate");
	RDEBUG2("Authenticate");

	status = eaptls_process(handler);
	RDEBUG2("eaptls_process returned %d\n", status);
	switch (status) {
		/*
		 *	EAP-TLS handshake was successful, return an
		 *	EAP-TLS-Success packet here.
		 */
	case EAPTLS_SUCCESS:
		if (inst->conf.virtual_server) {
			VALUE_PAIR *vp;
			REQUEST *fake;

			/* create a fake request */
			fake = request_alloc_fake(request);
			rad_assert(fake->packet->vps == NULL);

			fake->packet->vps = paircopy(request->packet->vps);

			/* set the virtual server to use */
			if ((vp = pairfind(request->config_items,
					   PW_VIRTUAL_SERVER)) != NULL) {
				fake->server = vp->vp_strvalue;
			} else {
				fake->server = inst->conf.virtual_server;
			}

			logs_add_flow(handler->request, "Processing EAP-TLS Certificate check");
			RDEBUG("Processing EAP-TLS Certificate check:");
			debug_pair_list(fake->packet->vps);

			RDEBUG("server %s {", fake->server);

			rad_virtual_server(fake);

			RDEBUG("} # server %s", fake->server);

			/* copy the reply vps back to our reply */
			pairadd(&request->reply->vps, fake->reply->vps);
			fake->reply->vps = NULL;

			/* reject if virtual server didn't return accept */
			if (fake->reply->code != PW_AUTHENTICATION_ACK) {
				logs_add_flow(handler->request, "Certifictes were rejected by the virtual server");
				RDEBUG2("Certifictes were rejected by the virtual server");
				request_free(&fake);
				eaptls_fail(handler, 0);
				return 0;
			}

			request_free(&fake);
			/* success */
		}
		break;

		/*
		 *	The TLS code is still working on the TLS
		 *	exchange, and it's a valid TLS request.
		 *	do nothing.
		 */
	case EAPTLS_HANDLED:
		return 1;

		/*
		 *	Handshake is done, proceed with decoding tunneled
		 *	data.
		 */
	case EAPTLS_OK:
		logs_add_flow(handler->request, "Received unexpected tunneled data after successful handshake");
		RDEBUG2("Received unexpected tunneled data after successful handshake.");
#ifndef NDEBUG
		if ((debug_flag > 2) && fr_log_fp) {
			unsigned int i;
			unsigned int data_len;
			unsigned char buffer[1024];

			data_len = (tls_session->record_minus)(&tls_session->dirty_in,
						buffer, sizeof(buffer));
			log_debug("  Tunneled data (%u bytes)\n", data_len);
			for (i = 0; i < data_len; i++) {
				if ((i & 0x0f) == 0x00) fprintf(fr_log_fp, "  %x: ", i);
				if ((i & 0x0f) == 0x0f) fprintf(fr_log_fp, "\n");

				fprintf(fr_log_fp, "%02x ", buffer[i]);
			}
			fprintf(fr_log_fp, "\n");
		}
#endif

		eaptls_fail(handler, 0);
		return 0;
		break;

		/*
		 *	Anything else: fail.
		 *
		 *	Also, remove the session from the cache so that
		 *	the client can't re-use it.
		 */
	default:
		if (inst->conf.session_cache_enable) {
			SSL_CTX_remove_session(inst->ctx,
					       tls_session->ssl->session);
		}

		/*
		 * tls handshake logging
		 * only if we didn't try to validate by backend 
		 * to avoid alerts duplication
		 */
		if (handler->validation_status == HANDER_VALIDATION_UNKNOWN) {
			if (handler->inst_holder == NULL) {
				radlog(L_ERR, "eaptls_authenticate: handler->inst_holder == NULL");
			}
			else {
				if (handler->request->packet->vps == NULL) {
					radlog(L_ERR, "eaptls_authenticate: handler->request->packet->vps == NULL");
				}
				
				radius_exec_logger_centrale(handler->request, handler->ssl_error, handler->ssl_error_desc);
			}
		}

		return 0;
	}

	/*
	 *	New sessions cause some additional information to be
	 *	cached.
	 */
	if (!SSL_session_reused(tls_session->ssl)) {
		/*
		 *	FIXME: Store miscellaneous data.
		 */
		RDEBUG2("Adding user data to cached session");

#if 0
		SSL_SESSION_set_ex_data(tls_session->ssl->session,
					ssl_session_idx_user_session, session_data);
#endif
	} else {
		/*
		 *	FIXME: Retrieve miscellaneous data.
		 */
#if 0
		data = SSL_SESSION_get_ex_data(tls_session->ssl->session,
					       ssl_session_idx_user_session);

		if (!session_data) {
			radlog_request(L_ERR, 0, request,
				       "No user session data in cached session - "
				       " REJECTING");
			return 0;
		}
#endif

		RDEBUG2("Retrieved session data from cached session");
	}

	/*
	 *	Success: Automatically return MPPE keys.
	 */
	return eaptls_success(handler, 0);
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
EAP_TYPE rlm_eap_tls = {
	"eap_tls",
	eaptls_attach,			/* attach */
	eaptls_initiate,		/* Start the initial request */
	NULL,				/* authorization */
	eaptls_authenticate,		/* authentication */
	eaptls_detach			/* detach */
};

