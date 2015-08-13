/* -*-mode: c; indent-tabs-mode: nil; c-basic-offset: 2; -*-
 */

/**
 * mod_fp - Module to gather "data about the browser" (fingerprint)
 *
 * See also http://sourceforge.net/projects/mod-csrf/
 *
 * Copyright (C) 2015 Pascal Buchbinder
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

/* apr */
#include "apr.h"
#include "apr_strings.h"
#include "apr_strmatch.h"
#include "apr_lib.h"
#include "apr_base64.h"

/* apache */
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_filter.h"

/************************************************************************
 * defines
 ***********************************************************************/
#define CLID_LOG_PFX(id)  "mod_fp("#id"): "
#define FP_HDRORDER       "FP_HeaderOrder"

// Apache 2.4 compat
#if (AP_SERVER_MINORVERSION_NUMBER == 4)
#define SF_CONN_REMOTEIP(r) r->connection->client_ip
#else
#define SF_CONN_REMOTEIP(r) r->connection->remote_ip
#endif

/************************************************************************
 * structures
 ***********************************************************************/
typedef struct {
  apr_table_t *headers;
} fp_srv_config_t;

/*
typedef struct {
} fp_dir_config_t;
*/

/************************************************************************
 * globals
 ***********************************************************************/
module AP_MODULE_DECLARE_DATA fp_module;

/************************************************************************
 * private
 ***********************************************************************/

/************************************************************************
 * handlers
 ***********************************************************************/

static int fp_post_read_request(request_rec *r) {
  if(ap_is_initial_req(r)) {
    fp_srv_config_t *conf = ap_get_module_config(r->server->module_config, 
                                             &fp_module);
    if(conf->headers) {
      int i;
      char *id = "";
      apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(r->headers_in)->elts;
      for(i = 0; i < apr_table_elts(r->headers_in)->nelts; i++) {
        const char *hdrId = apr_table_get(conf->headers, entry[i].key);
        if(hdrId != NULL) {
          id = apr_pstrcat(r->pool, id, hdrId, NULL);
        }
      }
      apr_table_set(r->subprocess_env, FP_HDRORDER, id);
    }
  }
  return DECLINED;
}

/*
static int fp_post_config(apr_pool_t *pconf, apr_pool_t *plog, 
                            apr_pool_t *ptemp, server_rec *bs) {
  server_rec *s = bs;
  fp_srv_config_t *conf = ap_get_module_config(bs->module_config, 
                                             &fp_module);
  ap_add_version_component(pconf, apr_psprintf(pconf, "mod_fp/%s", 
                                               g_revision));
  while(s) {
    conf = ap_get_module_config(s->module_config, &fp_module);
    s = s->next;
  }
  return DECLINED;
}
*/

/************************************************************************
 * directiv handlers 
 ***********************************************************************/
/*
static void *fp_dir_config_create(apr_pool_t *p, char *d) {
  fp_dir_config_t *dconf = apr_pcalloc(p, sizeof(fp_dir_config_t));
  return dconf;
}

static void *fp_dir_config_merge(apr_pool_t *p, void *basev, void *addv) {
  fp_dir_config_t *b = (fp_dir_config_t *)basev;
  fp_dir_config_t *o = (fp_dir_config_t *)addv;
  fp_dir_config_t *m = apr_pcalloc(p, sizeof(fp_dir_config_t));
  return m;
}
*/

static void *fp_srv_config_create(apr_pool_t *p, server_rec *s) {
  fp_srv_config_t *sconf = apr_pcalloc(p, sizeof(fp_srv_config_t));
  sconf->headers = NULL;
  return sconf;
}

static void *fp_srv_config_merge(apr_pool_t *p, void *basev, void *addv) {
  fp_srv_config_t *sconf = apr_pcalloc(p, sizeof(fp_srv_config_t));
  fp_srv_config_t *base = basev;
  fp_srv_config_t *add = addv;
  if(add->headers) {
    sconf->headers = add->headers;
  } else {
    sconf->headers = base->headers;
  }
  return sconf;
}

const char *fp_headers_cmd(cmd_parms *cmd, void *dcfg, const char *header) {
  fp_srv_config_t *conf = ap_get_module_config(cmd->server->module_config, &fp_module);
  if(conf->headers == NULL) {
    conf->headers = apr_table_make(cmd->pool, 10);
  }
  apr_table_add(conf->headers, header, apr_psprintf(cmd->pool, "%d;", apr_table_elts(conf->headers)->nelts));
  return NULL;
}

static const command_rec fp_config_cmds[] = {
  AP_INIT_ITERATE("FP_HeaderOrder", fp_headers_cmd, NULL,
                  RSRC_CONF,
                  ""),
  { NULL }
};

/************************************************************************
 * apache register 
 ***********************************************************************/
static void fp_register_hooks(apr_pool_t * p) {
  static const char *pre[] = { "mod_ssl.c", NULL };
  static const char *post[] = { "mod_clientid.c", "mod_setenvifplus.c", "mod_parp.c", NULL };
  ap_hook_post_read_request(fp_post_read_request, pre, post, APR_HOOK_MIDDLE);
  //ap_hook_post_config(fp_post_config, pre, NULL, APR_HOOK_MIDDLE);
}

/************************************************************************
 * apache module definition 
 ***********************************************************************/
module AP_MODULE_DECLARE_DATA fp_module ={ 
  STANDARD20_MODULE_STUFF,
  //fp_dir_config_create,                    /**< dir config */
  //fp_dir_config_merge,                     /**< dir merger */
  NULL,
  NULL,
  fp_srv_config_create,                    /**< server config */
  fp_srv_config_merge,                     /**< server merger */
  fp_config_cmds,                          /**< command table */
  fp_register_hooks,                       /**< hook registery */
};
