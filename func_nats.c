/*
 * func_nats.c
 *
 * Base code is based on Sergio Medina Toledo <lumasepa at gmail>
 * https://github.com/tic-ull/func_redis
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Functions for interaction with NATS database
 *
 * \author Sergio Medina Toledo <lumasepa at gmail>
 * \author Alan Graham <ag at zerohalo>
 *
 * \ingroup functions
 */

/*** MODULEINFO
	<support_level>extended</support_level>
	<depend>hinats</depend>
 ***/


#include <asterisk.h>

#ifdef ASTERISK_REGISTER_FILE
ASTERISK_REGISTER_FILE()
#else
ASTERISK_FILE_VERSION("func_nats.c", "$Revision: 1 $")
#endif

#include <asterisk/module.h>
#include <asterisk/channel.h>
#include <asterisk/pbx.h>
#include <asterisk/utils.h>
#include <asterisk/app.h>
#include <asterisk/cli.h>
#include <asterisk/config.h>

#ifndef AST_MODULE
#define AST_MODULE "func_nats"
#endif

#include <errno.h>

#if HINATS_MAJOR == 0 && HINATS_MINOR == 11
typedef char *sds;
struct sdshdr {
    int len;
    int free;
    char buf[];
};
void sdsfree(sds s) {
    if (s == NULL) return;
    free((char*)s - sizeof(struct sdshdr));
}
#endif

/*** DOCUMENTATION
	<function name="NATS" language="en_US">
		<synopsis>
			Read from or write to a NATS database.
		</synopsis>
		<syntax>
			<parameter name="key" required="true" />
		</syntax>
		<description>
			<para>This function will read from or write a value to the NATS database.  On a
			read, this function returns the corresponding value from the database, or blank
			if it does not exist.  Reading a database value will also set the variable
			NATS_RESULT.  If you wish to find out if an entry exists, use the NATS_EXISTS
			function.</para>
		</description>
		<see-also>
			<ref type="function">NATS_DELETE</ref>
			<ref type="function">NATS_EXISTS</ref>
		</see-also>
	</function>
	<function name="NATS_EXISTS" language="en_US">
		<synopsis>
			Check to see if a key exists in the NATS database.
		</synopsis>
		<syntax>
			<parameter name="key" required="true" />
		</syntax>
		<description>
			<para>This function will check to see if a key exists in the NATS
			database. If it exists, the function will return <literal>1</literal>. If not,
			it will return <literal>0</literal>.  Checking for existence of a database key will
			also set the variable NATS_RESULT to the key's value if it exists.</para>
		</description>
		<see-also>
			<ref type="function">NATS</ref>
		</see-also>
	</function>
	<function name="NATS_DELETE" language="en_US">
		<synopsis>
			Return a value from the database and delete it.
		</synopsis>
		<syntax>
			<parameter name="key" required="true" />
		</syntax>
		<description>
			<para>This function will retrieve a value from the NATS database
			and then remove that key from the database.</para>
		</description>
	</function>
    <function name="NATS_COMMAND" language="en_US">
		<synopsis>
			Send a command to nats, all nats commands are valid
		</synopsis>
		<syntax>
			<parameter name="channel" required="true" />
		</syntax>
		<description>
			<para>Send a command to nats, all nats commands are valid
			the result is saved in NATS_RESULT, Example:
			NATS_COMMAND("SET key value")
			</para>
		</description>
		<see-also>
			<ref type="function">NATS</ref>
			<ref type="function">NATS_DELETE</ref>
			<ref type="function">NATS_EXISTS</ref>
		</see-also>
	</function>
 ***/

#define NATS_CONF "func_nats.conf"
#define STR_CONF_SZ 256

// max size of long long [−9223372036854775807,+9223372036854775807]
#define LONG_LONG_LEN_IN_STR 20

#define __LOG_BUFFER_SZ 1024


#define natsLoggedCommand(nats, ...) natsCommand(nats, __VA_ARGS__); \
snprintf (__log_buffer, __LOG_BUFFER_SZ, __VA_ARGS__); \
ast_debug(1, "%s\n", __log_buffer);


#define get_safe_nats_context_for_func_as(name) natsContext * name = NULL;\
if (!(nats_context = ast_threadstorage_get(&nats_instance, sizeof(natsContext))))\
{\
ast_log(LOG_ERROR, "Error retrieving the nats context from thread\n");\
return -1;\
}\


#define get_safe_nats_context_for_cli_as(name) natsContext * name = NULL;\
if (!(nats_context = ast_threadstorage_get(&nats_instance, sizeof(natsContext))))\
{\
ast_log(LOG_ERROR, "Error retrieving the nats context from thread\n");\
return CLI_FAILURE;\
}\


#define replyHaveError(reply) (reply != NULL && reply->type == NATS_REPLY_ERROR)

AST_MUTEX_DEFINE_STATIC(nats_lock);

static char hostname[STR_CONF_SZ] = "";
static char dbname[STR_CONF_SZ] = "";
static char password[STR_CONF_SZ] = "";
static char bgsave[STR_CONF_SZ] = "";
static unsigned int port = 6379;
static struct timeval timeout;
static char __log_buffer[__LOG_BUFFER_SZ] = "";

static int nats_connect(void * data);
static void nats_disconnect(void * data);

AST_THREADSTORAGE_CUSTOM(nats_instance, nats_connect, nats_disconnect)

/*!
 * \brief Handles the connection to nats, the auth and the selection of the database
 */
static int nats_connect(void * data)
{
    natsContext * nats_context = NULL;
    nats_context = natsConnectWithTimeout(hostname, port, timeout);
    if (nats_context == NULL) {
        ast_log(AST_LOG_ERROR,
                "Couldn't establish connection. Reason: UNKNOWN\n");
        return -1;
    }

    if(nats_context->err != 0){
        ast_log(AST_LOG_ERROR,
                "Couldn't establish connection. Reason: %s\n", nats_context->errstr);
        return -1;
    }

    natsReply * reply = NULL;
    if (strnlen(password, STR_CONF_SZ) != 0) {
        ast_log(AST_LOG_DEBUG, "NATS : Authenticating...\n");
        reply = natsCommand(nats_context,"AUTH %s", password);
        if (replyHaveError(reply)) {
            ast_log(LOG_ERROR, "Unable to authenticate. Reason: %s\n", reply->str);
            return -1;
        }
        ast_log(AST_LOG_DEBUG, "NATS : Authenticated.\n");
        freeReplyObject(reply);
    }

    if (strnlen(dbname, STR_CONF_SZ) != 0) {
        ast_log(AST_LOG_DEBUG, "Selecting DB %s\n", dbname);
        reply = natsLoggedCommand(nats_context,"SELECT %s", dbname);
        if (replyHaveError(reply)) {
            ast_log(AST_LOG_ERROR, "Unable to select DB %s. Reason: %s\n", dbname, reply->str);
            return -1;
        }
        ast_log(AST_LOG_DEBUG, "Database %s selected.\n", dbname);
        freeReplyObject(reply);
    }

    memcpy(data, nats_context, sizeof(natsContext));
    free(nats_context);
    return 0;
}

static void nats_disconnect(void *data){
    natsContext * nats_context = data;

    if (nats_context == NULL)
        return;

    if (nats_context->fd > 0)
        close(nats_context->fd);
    if (nats_context->obuf != NULL)
        sdsfree(nats_context->obuf);
    if (nats_context->reader != NULL){
        if (nats_context->reader->reply != NULL && nats_context->reader->fn && nats_context->reader->fn->freeObject)
            nats_context->reader->fn->freeObject(nats_context->reader->reply);
        if (nats_context->reader->buf != NULL)
            sdsfree(nats_context->reader->buf);
        free(nats_context->reader);
    } // = natsReaderFree(nats_context->reader);


#if HINATS_MAJOR == 0 && HINATS_MINOR > 12
    if (nats_context->tcp.host)
        free(nats_context->tcp.host);
    if (nats_context->tcp.source_addr)
        free(nats_context->tcp.source_addr);
    if (nats_context->timeout)
        free(nats_context->timeout);
#endif

#if HINATS_MAJOR == 0 && HINATS_MINOR == 13 && HINATS_PATCH == 0
    if (nats_context->unix.path){
        free(nats_context->unix.path);
    }
#endif

#if HINATS_MAJOR == 0 && HINATS_MINOR == 13 && HINATS_PATCH > 0
    if (nats_context->unix_sock.path){
        free(nats_context->unix_sock.path);
    }
#endif

    free(nats_context);
    return;
}

/*!
 * \brief Method for get an string from a nats reply, it is a helper method
 */
static char * get_reply_value_as_str(natsReply *reply){
    char * value = NULL;
    if (reply != NULL){
        switch (reply->type){
            case NATS_REPLY_NIL:
                value = (char*)malloc(4);
                snprintf(value, 4, "%s", "nil");
                break;
            case NATS_REPLY_INTEGER:
                value = (char*)malloc(LONG_LONG_LEN_IN_STR);
                snprintf(value, LONG_LONG_LEN_IN_STR, "%lld", reply->integer);
                break;
            case NATS_REPLY_STRING:
            case NATS_REPLY_STATUS:
            case NATS_REPLY_ERROR:
                value = (char*)malloc((size_t)reply->len + 1);
                snprintf(value, (size_t)(reply->len) + 1, "%s", reply->str);
                break;
            case NATS_REPLY_ARRAY:
                for(size_t i = 0; i < reply->elements; ++i){
                    char * old_value = NULL;
                    natsReply * element = reply->element[i];

                    char * element_value = get_reply_value_as_str(element);
                    size_t element_sz = (size_t)element->len;

                    if (i == 0){
                        size_t value_sz = element_sz + 1 ; // 1 = "\0"
                        value = (char*)malloc(value_sz);
                        snprintf(value, value_sz, "%s", element_value);
                    }else{
                        old_value = value;
                        size_t old_value_sz = strlen(old_value);
                        size_t value_new_sz = old_value_sz + element_sz + 2; // 2  = comma + "\0"
                        value = (char*)malloc(value_new_sz);
                        snprintf(value, value_new_sz, "%s,%s", old_value, element_value);
                        free(old_value);
                    }
                }
                break;
            default:
                break;
        }
    } else {
        ast_log(AST_LOG_ERROR, "NATS: reply is NULL \n");
        value = NULL;
    }
    return value;
}

/*!
 * \brief Handles the load of the config of the module
 */
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

    if (!(conf_str = ast_variable_retrieve(config, "general", "hostname"))) {
        ast_log(AST_LOG_NOTICE,
                "No nats hostname, using localhost as default.\n");
        conf_str =  "127.0.0.1";
    }

    ast_copy_string(hostname, conf_str, sizeof(hostname));

    if (!(conf_str = ast_variable_retrieve(config, "general", "port"))) {
        ast_log(AST_LOG_NOTICE,
                "No nats port found, using 6379 as default.\n");
        conf_str = "6379";
    }

    port = (unsigned int)atoi(conf_str);

    if (!(conf_str = ast_variable_retrieve(config, "general", "database"))) {
        ast_log(AST_LOG_NOTICE,
                "NATS: No database found, using '0' as default.\n");
        conf_str =  "0";
    }

    ast_copy_string(dbname, conf_str, sizeof(dbname));

    if (!(conf_str = ast_variable_retrieve(config, "general", "password"))) {
        ast_log(AST_LOG_NOTICE,
                "No nats password found, disabling authentication.\n");
        conf_str =  "";
    }

    ast_copy_string(password, conf_str, sizeof(password));

    if (!(conf_str = ast_variable_retrieve(config, "general", "timeout"))) {
        ast_log(AST_LOG_NOTICE,
                "No nats timeout found, using 5 seconds as default.\n");
        conf_str = "5";
    }

    timeout.tv_sec = atoi(conf_str);

    if (!(conf_str = ast_variable_retrieve(config, "general", "bgsave"))) {
        ast_log(AST_LOG_NOTICE,
                "No bgsave setting found, using default of false.\n");
        conf_str =  "false";
    }

    ast_copy_string(bgsave, conf_str, sizeof(bgsave));

    ast_config_destroy(config);

    ast_verb(2, "NATS config loaded.\n");

    /* Done reloading. Release lock so others can now use driver. */
    ast_mutex_unlock(&nats_lock);

    return 1;
}

static int function_nats_command(struct ast_channel *chan, const char *cmd,
                                 char *parse, char *return_buffer, size_t rtn_buff_len)
{
    AST_DECLARE_APP_ARGS(args, AST_APP_ARG(command););

    return_buffer[0] = '\0';

    if (ast_strlen_zero(parse)) {
        ast_log(LOG_WARNING, "NATS_COMMAND requires one argument, NATS_COMMAND(<command>)\n");
        return -1;
    }

    AST_STANDARD_APP_ARGS(args, parse);

    if (args.argc != 1) {
        ast_log(AST_LOG_WARNING, "NATS_COMMAND requires one argument, NATS_COMMAND(<command>)\n");
        return -1;
    }

    natsReply * reply = NULL;
    get_safe_nats_context_for_func_as(nats_context);

    reply = natsLoggedCommand(nats_context, args.command);

    if (replyHaveError(reply)) {
        ast_log(AST_LOG_ERROR, "%s\n", reply->str);
        pbx_builtin_setvar_helper(chan, "NATS_ERROR", reply->str);
        freeReplyObject(reply);
        return -1;
    } else {
        char* reply_str = get_reply_value_as_str(reply);
        if (reply_str){
            strncpy(return_buffer, reply_str, rtn_buff_len);
            free(reply_str);
        }else{
            pbx_builtin_setvar_helper(chan, "NATS_ERROR", "Error in reply as str");
        }
    }
    pbx_builtin_setvar_helper(chan, "NATS_RESULT", return_buffer);

    return 0;
}

static struct ast_custom_function nats_command_function = {
        .name = "NATS_COMMAND",
        .read = function_nats_command,
        .read_max = 2,
};


static int function_nats_read(struct ast_channel *chan, const char *cmd,
                               char *parse, char *return_buffer, size_t rtn_buff_len)
{
    AST_DECLARE_APP_ARGS(args,
                         AST_APP_ARG(key);
    );

    return_buffer[0] = '\0';

    if (ast_strlen_zero(parse)) {
        ast_log(AST_LOG_WARNING, "NATS requires one argument NATS(<key>)\n");
        return -1;
    }

    AST_STANDARD_APP_ARGS(args, parse);

    natsReply * reply = NULL;
    if (args.argc != 1) {
        ast_log(AST_LOG_WARNING, "NATS requires one argument NATS(<key>)\n");
        return -1;
    }

    get_safe_nats_context_for_func_as(nats_context);

    reply = natsLoggedCommand(nats_context,"GET %s", args.key);
    if (replyHaveError(reply)) {
        ast_log(AST_LOG_ERROR, "%s\n", reply->str);
        pbx_builtin_setvar_helper(chan, "NATS_ERROR", reply->str);
        freeReplyObject(reply);
        return -1;
    } else {
        char * value = get_reply_value_as_str(reply);
        if(value) {
            snprintf(return_buffer, rtn_buff_len, "%s", value);
            pbx_builtin_setvar_helper(chan, "NATS_RESULT", value);
            free(value);
        }
        freeReplyObject(reply);
    }
    return 0;
}

static int function_nats_write(struct ast_channel *chan, const char *cmd, char *parse,
                                const char *value)
{
    AST_DECLARE_APP_ARGS(args,
                         AST_APP_ARG(key);
    );

    if (ast_strlen_zero(parse)) {
        ast_log(AST_LOG_WARNING, "NATS requires an argument, NATS(<key>)=<value>\n");
        return -1;
    }

    AST_STANDARD_APP_ARGS(args, parse);

    if (args.argc != 1) {
        ast_log(AST_LOG_WARNING, "NATS requires one argument NATS(<key>)=<value>\n");
        return -1;
    }

    natsReply * reply = NULL;
    get_safe_nats_context_for_func_as(nats_context);
    reply = natsLoggedCommand(nats_context,"SET %s %s", args.key, value);

    if (replyHaveError(reply)) {
        ast_log(AST_LOG_WARNING, "NATS: Error writing value to database. Reason: %s\n", reply->str);
        pbx_builtin_setvar_helper(chan, "NATS_ERROR", reply->str);
        freeReplyObject(reply);
        return -1;
    }

    freeReplyObject(reply);

    return 0;
}

static struct ast_custom_function nats_function = {
        .name = "NATS",
        .read = function_nats_read,
        .write = function_nats_write,
};

static int function_nats_exists(struct ast_channel *chan, const char *cmd,
                                 char *parse, char *return_buffer, size_t rtn_buff_len)
{
    AST_DECLARE_APP_ARGS(args,
                         AST_APP_ARG(key);
    );

    return_buffer[0] = '\0';

    if (ast_strlen_zero(parse)) {
        ast_log(AST_LOG_WARNING, "NATS_EXISTS requires one argument, NATS(<key>)\n");
        return -1;
    }

    AST_STANDARD_APP_ARGS(args, parse);

    if (args.argc != 1) {
        ast_log(AST_LOG_WARNING, "NATS_EXISTS requires one argument, NATS(<key>)\n");
        return -1;
    }

    natsReply * reply = NULL;
    get_safe_nats_context_for_func_as(nats_context);
    reply = natsLoggedCommand(nats_context,"EXISTS %s", args.key);

    if(reply == NULL){
        ast_log(AST_LOG_ERROR, "NATS reply is NULL\n");
        pbx_builtin_setvar_helper(chan, "NATS_ERROR", "Reply is NULL");
        return -1;
    }

    if (replyHaveError(reply)) {
        ast_log(LOG_ERROR, "%s\n", reply->str);
        pbx_builtin_setvar_helper(chan, "NATS_ERROR", reply->str);
        freeReplyObject(reply);
        return -1;
    } else  if (reply->integer == 1){
		strncpy(return_buffer, "1", rtn_buff_len);
	} else if (reply->integer == 0){
        strncpy(return_buffer, "0", rtn_buff_len);
    } else {
        ast_log(AST_LOG_WARNING, "NATS EXIST failed\n");
        strncpy(return_buffer, "0", rtn_buff_len);
    }
    pbx_builtin_setvar_helper(chan, "NATS_RESULT", return_buffer);

    return 0;
}

static struct ast_custom_function nats_exists_function = {
        .name = "NATS_EXISTS",
        .read = function_nats_exists,
        .read_max = 2,
};

static int function_nats_delete(struct ast_channel *chan, const char *cmd,
                                 char *parse, char *return_buffer, size_t rtn_buff_len)
{
    AST_DECLARE_APP_ARGS(args,
                         AST_APP_ARG(key);
    );

    return_buffer[0] = '\0';

    if (ast_strlen_zero(parse)) {
        ast_log(AST_LOG_WARNING, "NATS_DELETE requires one argument NATS_DELETE(<key>)\n");
        return -1;
    }

    AST_STANDARD_APP_ARGS(args, parse);

    natsReply * reply = NULL;

    if (args.argc != 1) {
        ast_log(AST_LOG_WARNING, "NATS_DELETE requires one argument, NATS_DELETE(<key>)\n");
        return -1;
    }
    get_safe_nats_context_for_func_as(nats_context);
    reply = natsLoggedCommand(nats_context,"DEL %s", args.key);

    if(reply == NULL) {
        ast_log(AST_LOG_ERROR, "NATS reply is NULL\n");
        pbx_builtin_setvar_helper(chan, "NATS_ERROR", "Reply is NULL");
        return -1;
    }
    if (replyHaveError(reply)) {
        ast_log(AST_LOG_ERROR, "%s\n", reply->str);
        pbx_builtin_setvar_helper(chan, "NATS_ERROR", reply->str);
        freeReplyObject(reply);
        return -1;
    } else if (reply->integer == 0){
       ast_log(AST_LOG_WARNING, "NATS_DELETE: Key %s not found in database.\n", args.key);
    }

    freeReplyObject(reply);

    return 0;
}

/*!
 * \brief Wrapper to execute NATS_DELETE from a write operation. Allows execution
 * even if live_dangerously is disabled.
 */
static int function_nats_delete_write(struct ast_channel *chan, const char *cmd, char *parse,
                                       const char *value)
{
    /* Throwaway to hold the result from the read */
    char return_buffer[128];
    return function_nats_delete(chan, cmd, parse, return_buffer, sizeof(return_buffer));
}

static struct ast_custom_function nats_delete_function = {
        .name = "NATS_DELETE",
        .read = function_nats_delete,
        .write = function_nats_delete_write,
};

static char *handle_cli_nats_set(struct ast_cli_entry *e, int cmd, struct ast_cli_args *args)
{
    switch (cmd) {
        case CLI_INIT:
            e->command = "nats set";
            e->usage =
                    "Usage: nats set <key> <value>\n"
                            "       Creates an entry in the NATS database for a given key and value.\n";
            return NULL;
        case CLI_GENERATE:
            return NULL;
        default:break;
    }

    if (args->argc != 4){
        return CLI_SHOWUSAGE;
    }


    natsReply * reply = NULL;
    get_safe_nats_context_for_cli_as(nats_context)

    reply = natsLoggedCommand(nats_context,"SET %s %s", args->argv[2], args->argv[3]);
    if (reply == NULL){
        ast_cli(args->fd, "NATS error, reply is NULL\n");
    } else if (replyHaveError(reply)) {
        ast_cli(args->fd, "%s\n", reply->str);
        ast_cli(args->fd, "NATS database error.\n");
    } else {
        ast_cli(args->fd, "NATS database entry created.\n");
    }
    freeReplyObject(reply);
    return CLI_SUCCESS;
}

static char *handle_cli_nats_del(struct ast_cli_entry *e, int cmd, struct ast_cli_args *args)
{
    switch (cmd) {
        case CLI_INIT:
            e->command = "nats del";
            e->usage =
                    "Usage: nats del <key>\n"
                            "       Deletes an entry in the NATS database for a given key.\n";
            return NULL;
        case CLI_GENERATE:
            return NULL;
        default:break;
    }

    if (args->argc != 3){
        return CLI_SHOWUSAGE;
    }

    natsReply * reply = NULL;
    get_safe_nats_context_for_cli_as(nats_context);
    reply = natsLoggedCommand(nats_context,"DEL %s", args->argv[2]);
    if (reply == NULL){
        ast_cli(args->fd, "NATS error, reply is NULL\n");
    } else if (replyHaveError(reply)) {
        ast_cli(args->fd, "%s\n", reply->str);
        ast_cli(args->fd, "NATS database entry does not exist.\n");
    } else {
        ast_cli(args->fd, "NATS database entry removed.\n");
    }

    freeReplyObject(reply);
    return CLI_SUCCESS;
}

static char *handle_cli_nats_show(struct ast_cli_entry *e, int cmd, struct ast_cli_args *args)
{
    switch (cmd) {
        case CLI_INIT:
            e->command = "nats show";
            e->usage =
                    "Usage: nats show\n"
                            "   OR: nats show [pattern]\n"
                            "       Shows NATS database contents, optionally restricted\n"
                            "       to a pattern.\n"
                            "\n"
                            "		[pattern] pattern to match keys\n"
                            "		Examples :\n"
                            "			- h?llo matches hello, hallo and hxllo\n"
                            "			- h*llo matches hllo and heeeello\n"
                            "			- h[ae]llo matches hello and hallo, but not hillo\n";
            return NULL;
        case CLI_GENERATE:
            return NULL;
        default:break;
    }

    natsReply * reply = NULL;
    get_safe_nats_context_for_cli_as(nats_context);
	if (args->argc == 3) {
		/* key */
		reply = natsLoggedCommand(nats_context,"KEYS %s", args->argv[2]);
	} else if (args->argc == 2) {
		/* show all */
		reply = natsLoggedCommand(nats_context,"KEYS *");
	} else {
		return CLI_SHOWUSAGE;
	}

	unsigned int i = 0;
	natsReply * get_reply;

    if (reply == NULL){
        ast_cli(args->fd, "NATS error, reply is NULL\n");
    } else if (replyHaveError(reply)) {
        ast_cli(args->fd, "%s\n", reply->str);
    } else {

        for (i = 0; i < reply->elements; i++) {
            get_reply = natsLoggedCommand(nats_context, "GET %s", reply->element[i]->str);
            if (get_reply != NULL) {
                if (replyHaveError(reply)) {
                    ast_cli(args->fd, "%s\n", reply->str);
                } else {
                    char *value = get_reply_value_as_str(get_reply);
                    if (value) {
                        ast_cli(args->fd, "%-50s: %-25s\n", reply->element[i]->str, value);
                        free(value);
                    }
                }
            }
            freeReplyObject(get_reply);
        }

        ast_cli(args->fd, "%d results found.\n", (int) reply->elements);
    }
    freeReplyObject(reply);

    return CLI_SUCCESS;
}

static struct ast_cli_entry cli_func_nats[] = {
        AST_CLI_DEFINE(handle_cli_nats_show, "Get all NATS values or by pattern in key"),
        AST_CLI_DEFINE(handle_cli_nats_del, "Delete a key - value in NATS"),
        AST_CLI_DEFINE(handle_cli_nats_set, "Creates a new key - value in NATS"),
};

static int unload_module(void)
{
    int res = 0;

    if (ast_true(bgsave)) {
        natsReply * reply = NULL;
        natsContext * nats_context = NULL;
        if (!(nats_context = ast_threadstorage_get(&nats_instance, sizeof(natsContext))))
        {
            ast_log(AST_LOG_ERROR, "Error retrieving the nats context from thread\n");
            return -1;
        }
        ast_log(AST_LOG_NOTICE, "Sending BGSAVE before closing connection.\n");
        reply = natsLoggedCommand(nats_context, "BGSAVE");
        ast_log(AST_LOG_NOTICE, "Closing connection.\n");
        freeReplyObject(reply);
    }

    ast_cli_unregister_multiple(cli_func_nats, ARRAY_LEN(cli_func_nats));
    res |= ast_custom_function_unregister(&nats_function);
    res |= ast_custom_function_unregister(&nats_exists_function);
    res |= ast_custom_function_unregister(&nats_delete_function);
    res |= ast_custom_function_unregister(&nats_command_function);

    return res;
}

static int load_module(void)
{
    if(load_config() == -1){
        return AST_MODULE_LOAD_DECLINE;
    }
    int res = 0;

    ast_cli_register_multiple(cli_func_nats, ARRAY_LEN(cli_func_nats));

    res |= ast_custom_function_register(&nats_function);
    res |= ast_custom_function_register(&nats_exists_function);
    res |= ast_custom_function_register(&nats_delete_function);
    res |= ast_custom_function_register(&nats_command_function);

    return res;
}

static int reload(void)
{
    ast_log(AST_LOG_NOTICE, "Reloading.\n");
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
