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
#include <asterisk/pbx.h>
#include <asterisk/logger.h>
#include <asterisk/app.h>


#include <nats/nats.h>


/*** DOCUMENTATION
    <function name="NATS_PUBLISH" language="en_US">
		<synopsis>
			Publish payload to subject
		</synopsis>
		<syntax>
			<parameter name="subject" required="true">
				<para>NATS subject</para>
			</parameter>
			<parameter name="payload" required="true">
				<para>payload in key1=value1,key2=value2 format</para>
			</parameter>
		</syntax>
		<description>
			<para>
			NATS_PUBLISH(subject,"key1=val1,key2=val2...")
			</para>
		</description>
    </function>
 ***/



#ifndef AST_MODULE
#define AST_MODULE "func_nats"
#endif

#define NATS_CONF "func_nats.conf"
#define STR_CONF_SZ 256




AST_MUTEX_DEFINE_STATIC(nats_lock);

static char nats_url[STR_CONF_SZ] = "";

static int nats_connect(void * data);
static void nats_disconnect(void * data);

AST_THREADSTORAGE_CUSTOM(nats_instance, nats_connect, nats_disconnect)



static int nats_connect(void * data)
{
    natsConnection     ** conn = data;
    natsStatus         s;

    s = natsConnection_ConnectTo(conn, nats_url);
    if (s != NATS_OK)
    {
        ast_log(LOG_NOTICE, "Could not create NATS connection");
        return -1;
    }
    
    return 0;
}

static void nats_disconnect(void * data)
{
    natsConnection     ** conn = data;

    natsConnection_Destroy(*conn);
    
    ast_free(data);
}



     
static int acf_nats_publish_exec(struct ast_channel *chan, const char *cmd, char *parse, char *return_buffer, size_t len)
{
     AST_DECLARE_APP_ARGS(args,
			 AST_APP_ARG(arg1);
			 AST_APP_ARG(arg2););

    
    if (ast_strlen_zero(parse)) {
        ast_log(LOG_WARNING, "NATS_PUBLISH requires two arguments, NATS_PUBLISH(subject,key1=val1,key2=val2...)\n");
        return -1;
    }
   
    AST_STANDARD_APP_ARGS(args, parse);

    if (args.argc != 2) {
        ast_log(LOG_WARNING, "NATS_PUBLISH requires two arguments, NATS_PUBLISH(subject,key1=val1,key2=val2...)\n");
        return -1;
    }
    
    natsConnection      **conn;
    natsStatus         s;
    
    if (!(conn = ast_threadstorage_get(&nats_instance, sizeof(*conn)))) {
        ast_log(LOG_ERROR, "Error retrieving the nats connection from the thread\n");
        return -1;
    }
    
    s = natsConnection_PublishString(*conn, args.arg1, args.arg2);

    if (s != NATS_OK)
    {
        nats_PrintLastErrorStack(stderr);
        ast_log(LOG_NOTICE, "Error publishing to nats server");
        return 0;
    }

    return 0;
}


static struct ast_custom_function acf_nats_publish = {
        .name = "NATS_PUBLISH",
        .read = acf_nats_publish_exec,
};





static int load_config(void)
{
    struct ast_config *config;
    const char *conf_str;
    struct ast_flags config_flags = { 0 };

    config = ast_config_load(NATS_CONF, config_flags);

    if (config == CONFIG_STATUS_FILEMISSING || config == CONFIG_STATUS_FILEINVALID) {
        ast_log(AST_LOG_ERROR, "Unable to load config %s\n", NATS_CONF);
        return -1;
    }

    ast_mutex_lock(&nats_lock);

    if (!(conf_str = ast_variable_retrieve(config, "general", "nats_url"))) {
        ast_log(AST_LOG_NOTICE,
                "No nats_url configured, using nats://127.0.0.1:4222 as default.\n");
        conf_str =  "nats://127.0.0.1:4222";
    }

    ast_copy_string(nats_url, conf_str, sizeof(nats_url));

     
    ast_config_destroy(config);
    ast_verb(2, "NATS config loaded.\n");
    ast_mutex_unlock(&nats_lock);

    return 1;
}



static int load_module(void)
{
    if(load_config() == -1){
        return AST_MODULE_LOAD_DECLINE;
    }

    int res = 0;
    res |= ast_custom_function_register(&acf_nats_publish);

    return AST_MODULE_LOAD_SUCCESS;
  
}

static int unload_module(void)
{
    int res = 0;
    res |= ast_custom_function_unregister(&acf_nats_publish);
    
    return 0;
}

static int reload(void)
{
    ast_log(AST_LOG_NOTICE, "Reloading ...\n");
    if(load_config() == -1){
        return AST_MODULE_LOAD_DECLINE;
    }

    return 0;
}


AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_DEFAULT, "NATS related dialplan functions",
                .load = load_module,
                .unload = unload_module,
                .reload = reload,
);


