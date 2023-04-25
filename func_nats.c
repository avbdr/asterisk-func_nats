/*
 * func_nats.c
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */


/*! \file
 *
 *  Functions for interaction with NATS
 *
 */

/*** MODULEINFO
	<support_level>extended</support_level>
	<depend></depend>
 ***/


#include <asterisk.h>
#include <asterisk/module.h>
#include <asterisk/logger.h>


#ifndef AST_MODULE
#define AST_MODULE "func_nats"
#endif





static int load_module(void)
{
    ast_log(LOG_NOTICE, "Hello World!n");
    return AST_MODULE_LOAD_SUCCESS;
  
}

static int unload_module(void)
{
    ast_log(LOG_NOTICE, "Goodbye World!n");
    return 0;
}


AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_DEFAULT, "NATS related dialplan functions",
                .load = load_module,
                .unload = unload_module
);




/*!
 * \brief Handles the load of the config of the module
 */
/* static int load_config(void) */
/* { */
/*     struct ast_config *config; */
/*     const char *conf_str; */
/*     struct ast_flags config_flags = { 0 }; */

/*     config = ast_config_load(NATS_CONF, config_flags); */

/*     if (config == CONFIG_STATUS_FILEMISSING || config == CONFIG_STATUS_FILEINVALID) { */
/*         ast_log(AST_LOG_ERROR, "Unable to load config %s\n", NATS_CONF); */
/*         return -1; */
/*     } */

/*     ast_mutex_lock(&nats_lock); */

/*     if (!(conf_str = ast_variable_retrieve(config, "general", "hostname"))) { */
/*         ast_log(AST_LOG_NOTICE, */
/*                 "No nats hostname, using localhost as default.\n"); */
/*         conf_str =  "127.0.0.1"; */
/*     } */

/*     ast_copy_string(hostname, conf_str, sizeof(hostname)); */

/*     if (!(conf_str = ast_variable_retrieve(config, "general", "port"))) { */
/*         ast_log(AST_LOG_NOTICE, */
/*                 "No nats port found, using 6379 as default.\n"); */
/*         conf_str = "6379"; */
/*     } */

/*     port = (unsigned int)atoi(conf_str); */

/*     if (!(conf_str = ast_variable_retrieve(config, "general", "database"))) { */
/*         ast_log(AST_LOG_NOTICE, */
/*                 "NATS: No database found, using '0' as default.\n"); */
/*         conf_str =  "0"; */
/*     } */

/*     ast_copy_string(dbname, conf_str, sizeof(dbname)); */

/*     if (!(conf_str = ast_variable_retrieve(config, "general", "password"))) { */
/*         ast_log(AST_LOG_NOTICE, */
/*                 "No nats password found, disabling authentication.\n"); */
/*         conf_str =  ""; */
/*     } */

/*     ast_copy_string(password, conf_str, sizeof(password)); */

/*     if (!(conf_str = ast_variable_retrieve(config, "general", "timeout"))) { */
/*         ast_log(AST_LOG_NOTICE, */
/*                 "No nats timeout found, using 5 seconds as default.\n"); */
/*         conf_str = "5"; */
/*     } */

/*     timeout.tv_sec = atoi(conf_str); */

/*     if (!(conf_str = ast_variable_retrieve(config, "general", "bgsave"))) { */
/*         ast_log(AST_LOG_NOTICE, */
/*                 "No bgsave setting found, using default of false.\n"); */
/*         conf_str =  "false"; */
/*     } */

/*     ast_copy_string(bgsave, conf_str, sizeof(bgsave)); */

/*     ast_config_destroy(config); */

/*     ast_verb(2, "NATS config loaded.\n"); */

/*     /\* Done reloading. Release lock so others can now use driver. *\/ */
/*     ast_mutex_unlock(&nats_lock); */

/*     return 1; */
/* } */

