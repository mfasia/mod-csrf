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

/************************************************************************
 * structures
 ***********************************************************************/

/************************************************************************
 * globals
 ***********************************************************************/
module AP_MODULE_DECLARE_DATA csrf_module;

/************************************************************************
 * private
 ***********************************************************************/

/************************************************************************
 * handlers
 ***********************************************************************/

/** finalize configuration */
static int csrf_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                            apr_pool_t *ptemp, server_rec *bs) {
  return DECLINED;
}

/************************************************************************
 * directiv handlers 
 ***********************************************************************/

/************************************************************************
 * apache register 
 ***********************************************************************/
static void csrf_register_hooks(apr_pool_t * p) {
  static const char *pre[] = { NULL };
  ap_hook_post_config(csrf_post_config, pre, NULL, APR_HOOK_MIDDLE);
}

/************************************************************************
 * apache module definition 
 ***********************************************************************/
module AP_MODULE_DECLARE_DATA csrf_module ={ 
  STANDARD20_MODULE_STUFF,
  NULL,                                    /**< dir config creater */
  NULL,                                    /**< dir merger */
  NULL,                                    /**< server config */
  NULL,                                    /**< server merger */
  NULL,                                    /**< command table */
  csrf_register_hooks,                     /**< hook registery */
};

