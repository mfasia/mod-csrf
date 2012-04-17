/* -*-mode: c; indent-tabs-mode: nil; c-basic-offset: 2; -*-
 */

/**
 * mod_csrf - Cross-site request forgery protection module for
 *            the Apache web server
 *
 * Copyright (C) 2012 Christoph Steigmeier, Pascal Buchbinder
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

/************************************************************************
 * Version
 ***********************************************************************/
static const char g_revision[] = "0.0";

/************************************************************************
 * Includes
 ***********************************************************************/
/* openssl */
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

/* apache */
#include <httpd.h>
#include <http_main.h>
#include <http_request.h>
#include <http_connection.h>
#include <http_protocol.h>
#include <http_log.h>
#include <util_filter.h>
#include <ap_regex.h>

#include <mod_ssl.h>
#include <ssl_private.h>
#include <mod_core.h>

/* apr */
#include <apr_hooks.h>
#include <apr_strings.h>
#include <apr_date.h>
#include <apr_base64.h>

/************************************************************************
 * defines
 ***********************************************************************/
#define CSRF_LOG_PFX(id)  "mod_csrf("#id"): "
#define CSRF_LOGD_PFX  "mod_csrf(): "

#define CSRF_IGNORE_PATTERN ".*(jpg)|(jpeg)|(gif)|(png)|(js)|(css)$"
#define CSRF_IGNORE_CACHE "mod_csrf::ignore"

#define CSRF_QUERYID "csrfpId"
#define CSRF_WIN 8
// FIXME
#define CSRF_ENABLE_WINDOW 1
#define CSRF_CHUNKED_ONLY 1
/* div */
#define CSRF_RAND_SIZE 10

// env variable to read id from
#define CSRF_ATTRIBUTE "CSRF_ATTRIBUTE"

/************************************************************************
 * structures
 ***********************************************************************/
/*
 * server configuration
 */
#define CSRF_FUNC_FLAGS_KEY        0x10

typedef struct {
  ap_regex_t *ignore_pattern; /** path pattern which disables request check */
  int enabled;                /** enabled by default (-1) or by user (1) */
  const char *id;
  int flags;
  unsigned char *sec;
  int sec_len;
  unsigned char key[EVP_MAX_KEY_LENGTH];
} csrf_srv_config_t;

typedef struct {
  int enabled;                /** enabled by default (-1) or by user (1) */
} csrf_dir_config_t;

typedef enum  {
  CSRF_RES_NEW = 0,
  CSRF_RES_SEARCH_HEAD,
  CSRF_RES_SEARCH_BODY,
  CSRF_RES_SEARCH_END
} csrf_conn_state_e;

typedef struct {
  csrf_conn_state_e state;
  char *search;
  char *body_window;
  char *script; // meta loading the script
  char *method; // javascript code calling the inject method
  apr_pool_t *pool;
} csrf_req_ctx;

/************************************************************************
 * globals
 ***********************************************************************/
module AP_MODULE_DECLARE_DATA csrf_module;

/* mod_parp, forward and optional function */
APR_DECLARE_OPTIONAL_FN(apr_table_t *, parp_hp_table, (request_rec *));
static APR_OPTIONAL_FN_TYPE(parp_hp_table) *csrf_parp_hp_table_fn = NULL;

/************************************************************************
 * private
 ***********************************************************************/

/*
 * Similar to standard strstr() but case insensitive and lenght limitation
 * (char which is not 0 terminated).
 *
 * @param s1 String to search in
 * @param s2 Pattern to ind
 * @param len Length of s1
 * @return pointer to the beginning of the substring s2 within s1, or NULL
 *         if the substring is not found
 */
static const char *csrf_strncasestr(const char *s1, const char *s2, int len) {
  const char *e1 = &s1[len-1];
  char *p1, *p2;
  if (*s2 == '\0') {
    /* an empty s2 */
    return((char *)s1);
  }
  while(1) {
    for ( ; (*s1 != '\0') && (s1 <= e1) && (apr_tolower(*s1) != apr_tolower(*s2)); s1++);
    if (*s1 == '\0' || s1 > e1) {
      return(NULL);
    }
    /* found first character of s2, see if the rest matches */
    p1 = (char *)s1;
    p2 = (char *)s2;
    for (++p1, ++p2; (apr_tolower(*p1) == apr_tolower(*p2)) && (p1 <= e1); ++p1, ++p2) {
      if((p1 > e1) && (*p2 != '\0')) {
        // reached the end without match
        return NULL;
      }
      if (*p2 == '\0') {
        /* both strings ended together */
        return((char *)s1);
      }
    }
    if (*p2 == '\0') {
      /* second string ended, a match */
      break;
    }
    /* didn't find a match here, try starting at next character in s1 */
    s1++;
  }
  return((char *)s1);
}

/**
 * Checks if csrf has been enabled.
 *
 * @param r
 * @return 1 if it has been enabled for this request
 */
static int csrf_enabled(request_rec *r) {
  csrf_srv_config_t *sconf = ap_get_module_config(r->server->module_config, &csrf_module);
  csrf_dir_config_t *dconf = ap_get_module_config(r->per_dir_config, &csrf_module);
  if(dconf->enabled == 0) {
    /* disbaled for this location (ignore server config) */
    return 0;
  }
  if(sconf->enabled == 0 && dconf->enabled == -1 ) {
    /* disabled for this server (no location config) */
    return 0;
  }
  return 1;
}

/**
 * We ignore (don't require an id) some types of requests
 * - static content like images
 *
 * @param r
 * @return 1 if we don't check this request, 0 if we do
 */
static int csrf_ignore_req(request_rec *r) {
  csrf_srv_config_t *sconf = ap_get_module_config(r->server->module_config, &csrf_module);
  if(apr_table_get(r->notes, CSRF_IGNORE_CACHE)) {
    // cache: check regex only once
    return 1;
  }
  // TODO: ignore by env variable
  if(r->parsed_uri.path) {
    const char *path = strrchr(r->parsed_uri.path, '/'); // faster than match against a long string
    if(path == NULL) {
      path = r->parsed_uri.path;
    }
    if(ap_regexec(sconf->ignore_pattern, path, 0, NULL, 0) == 0) {
      apr_table_set(r->notes, CSRF_IGNORE_CACHE, "i");
      ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r,
                    CSRF_LOGD_PFX"ignores request '%s'", r->parsed_uri.path);
      return 1;
    }
  }
  return 0;
}

/**
 * Returns a table containing the query name/value pairs.
 *
 * @param r
 * @return Table of NULL if no parameter are available
 */
static apr_table_t *csrf_get_query(request_rec *r) {
  apr_table_t *qt = NULL;
  const char *args = r->args;
  if(args == NULL) {
    return NULL;
  }
  qt = apr_table_make(r->pool, 10);
  while(args[0]) {
    char *value = ap_getword(r->pool, &args, '&');
    char *name = ap_getword_nc(r->pool, &value, '=');
    if(name) {
      apr_table_addn(qt, name, value);   
    }
  }
  return qt;
}

/*
 * Crypto routines (from mod_auth_oid.c)
 */
static char *csrf_dec64(request_rec *r, const char *str) {
  csrf_srv_config_t *sconf = ap_get_module_config(r->server->module_config, &csrf_module);
  EVP_CIPHER_CTX cipher_ctx;
  int len = 0;
  int buf_len = 0;
  unsigned char *buf;
  char *dec = (char *)apr_palloc(r->pool, 1 + apr_base64_decode_len(str));
  int dec_len = apr_base64_decode(dec, str);
  buf = apr_pcalloc(r->pool, dec_len);

  EVP_CIPHER_CTX_init(&cipher_ctx);
  EVP_DecryptInit(&cipher_ctx, EVP_des_ede3_cbc(), sconf->key, NULL);
  if(!EVP_DecryptUpdate(&cipher_ctx, (unsigned char *)&buf[buf_len], &len,
                        (const unsigned char *)dec, dec_len)) {
    goto failed;
  }
  buf_len+=len;
  if(!EVP_DecryptFinal(&cipher_ctx, (unsigned char *)&buf[buf_len], &len)) {
    goto failed;
  }
  buf_len+=len;
  EVP_CIPHER_CTX_cleanup(&cipher_ctx);
  
  if(buf_len < CSRF_RAND_SIZE) {
    goto failed;
  }
  if(buf[CSRF_RAND_SIZE-1] != 'A') {
    goto failed;
  }
  buf = &buf[CSRF_RAND_SIZE];
  buf_len = buf_len - CSRF_RAND_SIZE;

  return apr_pstrndup(r->pool, (char *)buf, buf_len);
     
 failed:
  EVP_CIPHER_CTX_cleanup(&cipher_ctx);
  ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, 0, r,
                CSRF_LOG_PFX(010)"Failed to decrypt data.");
  return "";
}

static char *csrf_enc64(request_rec *r, const char *str) {
  csrf_srv_config_t *sconf = ap_get_module_config(r->server->module_config, &csrf_module);
  char *e;
  EVP_CIPHER_CTX cipher_ctx;
  int buf_len = 0;
  int len = 0;
  unsigned char *rand = apr_pcalloc(r->pool, CSRF_RAND_SIZE);
  unsigned char *buf = apr_pcalloc(r->pool,
                                   CSRF_RAND_SIZE +
                                   strlen(str) +
                                   EVP_CIPHER_block_size(EVP_des_ede3_cbc()));
  RAND_bytes(rand, CSRF_RAND_SIZE);
  rand[CSRF_RAND_SIZE-1] = 'A';
  EVP_CIPHER_CTX_init(&cipher_ctx);
  EVP_EncryptInit(&cipher_ctx, EVP_des_ede3_cbc(), sconf->key, NULL);
  if(!EVP_EncryptUpdate(&cipher_ctx, &buf[buf_len], &len,
                        rand, CSRF_RAND_SIZE)) {
    goto failed;
  }
  buf_len+=len;
  if(!EVP_EncryptUpdate(&cipher_ctx, &buf[buf_len], &len,
                        (const unsigned char *)str, strlen(str))) {
    goto failed;
  }
  buf_len+=len;
  if(!EVP_EncryptFinal(&cipher_ctx, &buf[buf_len], &len)) {
    goto failed;
  }
  buf_len+=len;
  EVP_CIPHER_CTX_cleanup(&cipher_ctx);

  e = (char *)apr_pcalloc(r->pool, 1 + apr_base64_encode_len(buf_len));
  len = apr_base64_encode(e, (const char *)buf, buf_len);
  e[len] = '\0';
  return e;

failed:
  EVP_CIPHER_CTX_cleanup(&cipher_ctx);
  ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, 0, r,
                CSRF_LOG_PFX(011)"Failed to encrypt data.");
  return "";
}

/**
 * Generate an id which contains defined data from the
 * request header if available and a timestamp.
 * Then encrypt the id with a predefined or random
 * secret.
 */
static char *csrf_create_id(request_rec *r) {
  const char *csrf_att = apr_table_get(r->subprocess_env, CSRF_ATTRIBUTE);
  char *id = apr_pstrcat(r->pool,
                   apr_psprintf(r->pool, "%"APR_TIME_T_FMT"", r->request_time),
                   "#",
                   csrf_att,
                   NULL);
  return csrf_enc64(r, id);
}

static int csrf_validate_id(request_rec *r, const char *id) {
  // FIXME: implement verification
  return 1;
}

/**
 * Verifies that a valid csrf request id could be found
 *
 * @param r
 * @param tl Table containg the request parameters
 * @param msg Error message if validation fails
 * @return 1 on success (0 if request id is not available or invalid)
 */
static int csrf_validate_req_id(request_rec *r, apr_table_t *tl, char **msg) {
  csrf_srv_config_t *sconf = ap_get_module_config(r->server->module_config, &csrf_module);
  const char *csrfid = apr_table_get(tl, sconf->id);
  if(csrfid != NULL) {
    return csrf_validate_id(r, csrfid);
  }
  *msg = apr_psprintf(r->pool, "no '%s' parameter in request", sconf->id);
  return 0;
}

static const char *csrf_get_contenttype(request_rec *r) {
  const char* type = NULL;
  type = apr_table_get(r->headers_out, "Content-Type");
  if(type == NULL) {
    type = apr_table_get(r->err_headers_out, "Content-Type"); // maybe an error page
  }
  if(type == NULL) {
    type = r->content_type;
  }
  return type;
}

/**
 * Injects a new bucket containing a reference to the java script.
 *
 * @param r
 * @param bb
 * @param b Bucket to split and insert date new bucket at the postion of the marker
 * @param rctx Request context containing the state of the parser
 * @param buf String representation of the bucket
 * @param sz Position to split the bucket and insert the new content
 * @return Bucket to continue searching (at the marker)
 */
static apr_bucket *csrf_inject_head(request_rec *r, apr_bucket_brigade *bb, apr_bucket *b,
                                    csrf_req_ctx *rctx,
                                    const char *buf, apr_size_t sz) {
  apr_bucket *e;
  apr_bucket_split(b, sz);
  b = APR_BUCKET_NEXT(b);
  e = apr_bucket_pool_create(rctx->script, strlen(rctx->script), r->pool, bb->bucket_alloc);

  APR_BUCKET_INSERT_BEFORE(b, e);
  rctx->state = CSRF_RES_SEARCH_BODY;
  rctx->search = apr_pstrdup(r->pool, "</body>");
  return b;
}

/**
 * Injects a new bucket containing a java script method call incl. the id.
 *
 * @param r
 * @param bb
 * @param b Bucket to split and insert date new bucket at the postion of the marker
 * @param rctx Request context containing the state of the parser
 * @param buf String representation of the bucket
 * @param sz Position to split the bucket and insert the new content
 * @return Bucket to continue searching (at the marker)
 */
static apr_bucket *csrf_inject_body(request_rec *r, apr_bucket_brigade *bb, apr_bucket *b,
                                    csrf_req_ctx *rctx,
                                    const char *buf, apr_size_t sz) {
  apr_bucket *e;
  apr_bucket_split(b, sz);
  b = APR_BUCKET_NEXT(b);
  e = apr_bucket_pool_create(rctx->method, strlen(rctx->method), r->pool, bb->bucket_alloc);

  APR_BUCKET_INSERT_BEFORE(b, e);
  rctx->state = CSRF_RES_SEARCH_END;
  rctx->search = NULL;
  return b;
}

/**
 * Get or create (and init) the pre request context used by the response parser.
 *
 * @param r
 * @return
 */
static csrf_req_ctx *csrf_get_rctx(request_rec *r) {
  csrf_req_ctx *rctx = ap_get_module_config(r->request_config, &csrf_module);
  if(rctx == NULL) {
    csrf_srv_config_t *sconf = ap_get_module_config(r->server->module_config, &csrf_module);
    rctx = apr_pcalloc(r->pool, sizeof(csrf_req_ctx));
    rctx->state = CSRF_RES_NEW;
    rctx->search = NULL;
    rctx->body_window = apr_pcalloc(r->pool, 2*CSRF_WIN+1);
    rctx->body_window[0] = '\0';
    rctx->method = apr_psprintf(r->pool, "<script type=\"text/javascript\">\n"
                                "<!--\ncsrfInsert(\"%s\", \"%s\");\n"
                                "//-->\n"
                                "</script>\n",
                                sconf->id,
                                csrf_create_id(r));
    // TODO: directive to configure alternative script path /csrf.js?000
    rctx->script = apr_psprintf(r->pool, "<script language=\"JavaScript\""
                               " src=\"%s\" type=\"text/javascript\">"
                                "</script>\n",
                                "/csrf.js?000");
    rctx->pool = NULL;
    ap_set_module_config(r->request_config, &csrf_module, rctx);
  }
  return rctx;
}

/************************************************************************
 * handlers
 ***********************************************************************/

/**
 * Out filter to inject our java script to every html page
 */
static apr_status_t csrf_out_filter_body(ap_filter_t *f, apr_bucket_brigade *bb) {
  request_rec *r = f->r;
  csrf_req_ctx *rctx = csrf_get_rctx(r);

  /*
   * states:
   * - new (determine if it's html and force chunked response)
   * - search </head> to insert link to our js
   * - search </body> to insert script method/id
   * - end (all done)
   */
  if(rctx->state == CSRF_RES_NEW) {
    const char *type = csrf_get_contenttype(r);
    if(type == NULL || strncasecmp(type, "text/html", 9) != 0) {
      // we don't want to parse this response (no html)
      rctx->state = CSRF_RES_SEARCH_END;
      rctx->search = NULL;
      ap_remove_output_filter(f);
    } else {
      // start searching head/body to inject our script
      if(CSRF_CHUNKED_ONLY) {
        // send as chunked response
        apr_table_unset(r->headers_out, "Content-Length");
        apr_table_unset(r->err_headers_out, "Content-Length");
        r->chunked = 1;
      } else {
        // adjust the content-length header
        // TODO: append dummy bytes if we can't inject the data
        int errh = 0;
        const char* cl =  apr_table_get(r->headers_out, "Content-Length");
        if(!cl) {
          errh = 1;
          cl =  apr_table_get(r->err_headers_out, "Content-Length");
        }
        if(cl) {
          // adjust non-chunked response
          char *length;
          apr_off_t s;
          char *errp = NULL;
          if(apr_strtoff(&s, cl, &errp, 10) == APR_SUCCESS) {
            s = s + strlen(rctx->script) + strlen(rctx->method);
            length = apr_psprintf(r->pool, "%"APR_OFF_T_FMT, s);
            if(!errh) {
              apr_table_set(r->headers_out, "Content-Length", length);
            } else {
              apr_table_set(r->err_headers_out, "Content-Length", length);
            }
          } else {
            // fallback to chunked
            r->chunked = 1;
            if(!errh) {
              apr_table_unset(r->headers_out, "Content-Length");
            } else {
              apr_table_unset(r->err_headers_out, "Content-Length");
            }
          }
        }
      }
      apr_table_add(r->headers_out, "Cache-Control", "no-cache, no-store");
      apr_table_unset(r->headers_out, "Etag");
      rctx->state = CSRF_RES_SEARCH_HEAD;
      rctx->search = apr_pstrdup(r->pool, "</head>");
    }
  }

  // start searching within this brigade...
  if(rctx->search) {
    apr_bucket *b;
    int loop = 0;
    /* pool to allocate buckets from (used to insert buffer from previous loop)
       this pool survices this filter call in we destroy it when we are called
       the next time because we expect that the bucket has been send to the network */
    apr_pool_t *pool;
    apr_pool_create(&pool, r->pool);
    for(b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b)) {
      if(APR_BUCKET_IS_EOS(b)) {
        /* If we ever see an EOS, make sure to FLUSH. */
        apr_bucket *flush = apr_bucket_flush_create(f->c->bucket_alloc);
        APR_BUCKET_INSERT_BEFORE(b, flush);
      }
      if(!(APR_BUCKET_IS_METADATA(b))) {
        const char *buf = NULL;
        apr_size_t  nbytes = 0;

        if(apr_bucket_read(b, &buf, &nbytes, APR_BLOCK_READ) == APR_SUCCESS) {
          if(nbytes > 0) {
            const char *marker = NULL;

            /*
             * 1. overlap with existing buffer
             */
            if(CSRF_ENABLE_WINDOW && rctx->body_window[0]) {
              int blen = nbytes > CSRF_WIN ? CSRF_WIN : nbytes-1;
              int wlen = strlen(rctx->body_window); // lenght of the previous buffer
              apr_bucket *last;

              // add some bytes of the new bucket to the previous
              strncpy(&rctx->body_window[wlen], buf, blen);
              rctx->body_window[wlen+blen+1] = '\0';

              // add the previous data to the brigade (always - does not matter if we find a match)
              // note: we need the temp. per loop pool to allocate the bucket from
              last = apr_bucket_pool_create(apr_pstrndup(pool, rctx->body_window, wlen), wlen,
                                            pool, bb->bucket_alloc);
              if(loop == 0) {
                // first bucket in the brigade (insert before does not work, see apr_ring.h)
                APR_BRIGADE_INSERT_HEAD(bb, last);
              } else {
                APR_BUCKET_INSERT_BEFORE(b, last);
              }

              // search within the window
              marker = ap_strcasestr(rctx->body_window, rctx->search);
              if(marker) {
                // found pattern
                apr_size_t sz = marker - rctx->body_window;
                if(sz < wlen) {
                  // within the previously stored data
                  // example: [..</he][ad>...]
                  //             ^
                  if(rctx->state == CSRF_RES_SEARCH_HEAD) {
                    csrf_inject_head(r, bb, last, rctx, rctx->body_window, sz);
                  } else if(rctx->state == CSRF_RES_SEARCH_BODY) {
                    csrf_inject_body(r, bb, last, rctx, rctx->body_window, sz);
                  }
                } else {
                  // in window but not within the previously stored data ("2. new buffer" will detect it)
                }
              }
              rctx->body_window[0] = '\0';
            }

            /*
             * 2. new buffer
             */
          restart:
            if(rctx->state != CSRF_RES_SEARCH_END) {
              marker = csrf_strncasestr(buf, rctx->search, nbytes);
              if(marker) {
                // found pattern
                apr_size_t sz = marker - buf;
                if(rctx->state == CSRF_RES_SEARCH_HEAD) {
                  b = csrf_inject_head(r, bb, b, rctx, buf, sz);
                  // TODO: re-calcluate e buffer pointer and size instead of re-reading
                  if(apr_bucket_read(b, &buf, &nbytes, APR_BLOCK_READ) == APR_SUCCESS) {
                    goto restart;
                  } else {
                    // TODO: error handling?
                    break;
                  }
                } else if(rctx->state == CSRF_RES_SEARCH_BODY) {
                  b = csrf_inject_body(r, bb, b, rctx, buf, sz);
                  break;
                }
              }
            }

            /*
             * 3. end parsing if we are done
             */
            if(rctx->state == CSRF_RES_SEARCH_END) {
              break;
            }

            /*
             * 4. store the end (for next loop)
             */
            if(CSRF_ENABLE_WINDOW && rctx->state != CSRF_RES_SEARCH_END) {
              apr_bucket *rb;
              int blen = nbytes > CSRF_WIN ? CSRF_WIN : nbytes-1;
              strncpy(rctx->body_window, &buf[nbytes - blen], blen);
              rctx->body_window[blen] = '\0';
              apr_bucket_split(b, nbytes - blen);
              rb = APR_BUCKET_NEXT(b);
              APR_BUCKET_REMOVE(rb);
            }
          }
        }
      }
      loop++;
    }
    if(rctx->pool) {
      // this data is no longer needed
      apr_pool_destroy(rctx->pool);
    }
    rctx->pool = pool; // store pool (until the buckets are sent)
  }
  return ap_pass_brigade(f->next, bb);
}

/**
 * Request verification.
 *
 * @param r
 * @return
 */
static int csrf_fixup(request_rec * r) {
  if(ap_is_initial_req(r) && csrf_enabled(r)) {
    ap_add_output_filter("csrf_out_filter_body", NULL, r, r->connection);
    if(!csrf_ignore_req(r)) {
      apr_table_t *tl = NULL;
      char *msg = NULL;
      if(csrf_parp_hp_table_fn) {
        tl = csrf_parp_hp_table_fn(r);
      }
      if(tl == NULL) {
        // parp was not active/loaded, we read the request query ourself
        tl = csrf_get_query(r);
      }
      if(tl == NULL) {
        /* no request query/body 
         * => nothing to do here since we don't validate "simple" 
         *    requests without any parameters */
        return DECLINED;
      }
      if(!csrf_validate_req_id(r, tl, &msg)) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                      CSRF_LOG_PFX(000)"request denied, %s", msg ? msg : "");
        return HTTP_FORBIDDEN;
      }
    }
  }
  return DECLINED;
}

/**
 * Prepares the request.
 * - Enable parameter parser if required (based on content type).
 *
 * @param r
 * @return
 */
static int csrf_header_parser(request_rec * r) {
  if(ap_is_initial_req(r)) {
    /* enables parameter parser */
    const char *ct = apr_table_get(r->headers_in, "Content-Type");
    if(ct && csrf_enabled(r) && !csrf_ignore_req(r)) {
      if(ap_strcasestr(ct, "application/x-www-form-urlencoded") ||
         ap_strcasestr(ct, "multipart/form-data") ||
         ap_strcasestr(ct, "multipart/mixed") ||
         ap_strcasestr(ct, "application/json")) {
        apr_table_set(r->subprocess_env, "parp", "mod_csrf");
      }
    }
  }
  return DECLINED;
}

/** finalize configuration */
static int csrf_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                            apr_pool_t *ptemp, server_rec *bs) {
  ap_add_version_component(pconf, apr_psprintf(pconf, "mod_csrf/%s", g_revision));
  if(ap_find_linked_module("mod_parp.c") == NULL) {
    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, bs, 
                 CSRF_LOG_PFX(000)"mod_parp not available");
    csrf_parp_hp_table_fn = NULL;
  } else {
    csrf_parp_hp_table_fn = APR_RETRIEVE_OPTIONAL_FN(parp_hp_table);
  }
  return DECLINED;
}

/************************************************************************
 * directiv handlers 
 ***********************************************************************/
static void *csrf_dir_config_create(apr_pool_t *p, char *d) {
  csrf_dir_config_t *dconf = apr_pcalloc(p, sizeof(csrf_dir_config_t));
  dconf->enabled = -1;
  return dconf;
}

static void *csrf_dir_config_merge(apr_pool_t *p, void *basev, void *addv) {
  csrf_dir_config_t *b = (csrf_dir_config_t *)basev;
  csrf_dir_config_t *o = (csrf_dir_config_t *)addv;
  csrf_dir_config_t *m = apr_pcalloc(p, sizeof(csrf_dir_config_t));
  if(o->enabled != -1) {
    m->enabled = o->enabled;
  } else {
    m->enabled = b->enabled;
  }
  return m;
}

static void *csrf_srv_config_create(apr_pool_t *p, server_rec *s) {
  csrf_srv_config_t *sconf = apr_pcalloc(p, sizeof(csrf_srv_config_t));
  sconf->ignore_pattern = ap_pregcomp(p, CSRF_IGNORE_PATTERN, AP_REG_ICASE);
  sconf->id = apr_pstrdup(p, CSRF_QUERYID);
  sconf->enabled = -1;
  return sconf;
}

static void *csrf_srv_config_merge(apr_pool_t *p, void *basev, void *addv) {
  csrf_srv_config_t *b = (csrf_srv_config_t *)basev;
  csrf_srv_config_t *o = (csrf_srv_config_t *)addv;
  csrf_srv_config_t *m = apr_pcalloc(p, sizeof(csrf_srv_config_t));
  if(o->enabled != -1) {
    m->enabled = o->enabled;
  } else {
    m->enabled = b->enabled;
  }
  m->ignore_pattern = b->ignore_pattern;
  m->id = b->id;
  if(o->flags & CSRF_FUNC_FLAGS_KEY) {
    m->sec_len = o->sec_len;
    m->sec = o->sec;
    memcpy(m->key, o->key, sizeof(o->key));
    m->flags |= CSRF_FUNC_FLAGS_KEY;
  } else {
    m->sec_len = b->sec_len;
    m->sec = b->sec;
    memcpy(m->key, b->key, sizeof(b->key));
  }
  return m;
}

const char *csrf_enable_cmd(cmd_parms *cmd, void *dcfg, int flag) {
  if(cmd->path) {
    csrf_srv_config_t *conf = dcfg;
    conf->enabled = flag;
  } else {
    csrf_srv_config_t *conf = ap_get_module_config(cmd->server->module_config, &csrf_module);
    conf->enabled = flag;
  }
  return NULL;
}

/* CSRF_Passphrase */
const char *csrf_pwd_cmd(cmd_parms *cmd, void *dcfg, const char *pwd) {
  csrf_srv_config_t *sconf = ap_get_module_config(cmd->server->module_config, &csrf_module);
  sconf->sec = (unsigned char *)apr_pstrcat(cmd->pool, pwd, "W9sO.4h7-6PU", NULL);
  sconf->sec_len = strlen((char *)sconf->sec);
  EVP_BytesToKey(EVP_des_ede3_cbc(), EVP_sha1(), NULL, sconf->sec,
                 sconf->sec_len, 1, sconf->key, NULL);
  sconf->flags |= CSRF_FUNC_FLAGS_KEY;
  return NULL;
}

static const command_rec csrf_config_cmds[] = {
  // TODO: add directive do override ignore pattern sconf->ignore_pattern
  // TODO: specify action (log, deny, off) insted of on/off only
  // TODO: directive to override CSRF_QUERYID
  AP_INIT_FLAG("CSRF_Enable", csrf_enable_cmd, NULL,
               RSRC_CONF|ACCESS_CONF,
               "CSRF_Enable 'on'|'off', enables the module. Default is 'on'."),
  AP_INIT_TAKE1("CSRF_Passphrase", csrf_pwd_cmd, NULL,
                RSRC_CONF,
                "CSRF_Passphrase <string>, used for 'csrfpId' encryption."
                " Default is a non-persistent random passphrase."),
  { NULL }
};

/************************************************************************
 * apache register 
 ***********************************************************************/
static void csrf_register_hooks(apr_pool_t * p) {
  static const char *pre[] = { "mod_setenvif.c", "mod_setenvifplus.c", NULL };
  static const char *parp[] = { "mod_parp.c", NULL };
  ap_hook_header_parser(csrf_header_parser, NULL, parp, APR_HOOK_FIRST);
  ap_hook_fixups(csrf_fixup, pre, NULL, APR_HOOK_MIDDLE);
  ap_hook_post_config(csrf_post_config, pre, NULL, APR_HOOK_MIDDLE);
  ap_register_output_filter("csrf_out_filter_body", csrf_out_filter_body, NULL, AP_FTYPE_RESOURCE);
}

/************************************************************************
 * apache module definition 
 ***********************************************************************/
module AP_MODULE_DECLARE_DATA csrf_module ={ 
  STANDARD20_MODULE_STUFF,
  csrf_dir_config_create,                  /**< dir config */
  csrf_dir_config_merge,                   /**< dir merger */
  csrf_srv_config_create,                  /**< server config */
  csrf_srv_config_merge,                   /**< server merger */
  csrf_config_cmds,                        /**< command table */
  csrf_register_hooks,                     /**< hook registery */
};
