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

/************************************************************************
 * structures
 ***********************************************************************/
/*
 * server configuration
 */
typedef struct {
  ap_regex_t *ignore_pattern; /** path pattern which disables request check */
  int enabled;                /** enabled by default (-1) or by user (1) */
  const char *id;
} csrf_srv_config_t;

typedef struct {
  int enabled;                /** enabled by default (-1) or by user (1) */
} csrf_dir_config_t;

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
  if(r->parsed_uri.path &&
     ap_regexec(sconf->ignore_pattern, r->parsed_uri.path, 0, NULL, 0) == 0) {
    apr_table_set(r->notes, CSRF_IGNORE_CACHE, "i");
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r,
                  CSRF_LOGD_PFX"ignores request '%s'", r->parsed_uri.path);
    return 1;
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
    // FIXME: implement verification
    return 1;
  }
  *msg = apr_psprintf(r->pool, "no '%s' parameter in request", sconf->id);
  return 0;
}

/************************************************************************
 * handlers
 ***********************************************************************/

/**
 * Request verification.
 *
 * @param r
 * @return
 */
static int csrf_fixup(request_rec * r) {
  if(ap_is_initial_req(r)) {
    if(csrf_enabled(r) && !csrf_ignore_req(r)) {
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
        // TODO log
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

static const command_rec csrf_config_cmds[] = {
  // TODO add directive do override ignore pattern sconf->ignore_pattern
  // TODO specify action (log, deny, off) insted of on/off only
  AP_INIT_FLAG("CSRF_Enable", csrf_enable_cmd, NULL,
               RSRC_CONF|ACCESS_CONF,
               "CSRF_Enable 'on'|'off', enables the module. Default is 'on'."),
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
