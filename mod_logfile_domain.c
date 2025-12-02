/*
 * FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 *
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 *
 * The Initial Developer of the Original Code is
 * Anthony Minessale II <anthm@freeswitch.org>
 * Portions created by the Initial Developer are Copyright (C)
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Your Name <your@email.com>
 *
 *
 * mod_logfile_domain.c -- Domain-based Filesystem Logging
 *
 */

#include <switch.h>
#include <ctype.h>
#include <string.h>

SWITCH_MODULE_LOAD_FUNCTION(mod_logfile_domain_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_logfile_domain_shutdown);
SWITCH_MODULE_DEFINITION(mod_logfile_domain, mod_logfile_domain_load, mod_logfile_domain_shutdown, NULL);

#define WARM_FUZZY_OFFSET 256
#define MAX_ROT 4096
#define UUID_CACHE_SIZE 1000

static switch_memory_pool_t *module_pool = NULL;
static switch_hash_t *domain_profile_hash = NULL;
static switch_hash_t *uuid_domain_cache = NULL;

static struct {
        int rotate;
        switch_mutex_t *mutex;
        switch_mutex_t *cache_mutex;
        switch_event_node_t *node;
        switch_event_node_t *channel_create_node;
        switch_event_node_t *channel_answer_node;
        switch_event_node_t *channel_destroy_node;
        uint32_t default_log_level;
        switch_size_t default_roll_size;
        switch_size_t default_max_rot;
        switch_bool_t log_uuid;
} globals;

struct domain_logfile_profile {
        char *domain_name;
        switch_size_t log_size;
        switch_size_t roll_size;
        switch_size_t max_rot;
        char *logfile;
        switch_file_t *log_afd;
        uint32_t all_level;
        uint32_t suffix;
        switch_bool_t log_uuid;
};

typedef struct domain_logfile_profile domain_logfile_profile_t;

/* Forward declarations */
static switch_status_t mod_logfile_domain_openlogfile(domain_logfile_profile_t *profile, switch_bool_t check);
static switch_status_t mod_logfile_domain_rotate(domain_logfile_profile_t *profile);
static switch_status_t mod_logfile_domain_raw_write(domain_logfile_profile_t *profile, char *log_data);
static char* find_matching_cached_domain(const char *extracted_domain);
static char* clean_domain_string(const char *domain);

/* UUID to Domain cache functions */
static void cache_uuid_domain(const char *uuid_str, const char *domain)
{
        if (zstr(uuid_str) || zstr(domain)) {
                return;
        }

        switch_mutex_lock(globals.cache_mutex);
        switch_core_hash_insert(uuid_domain_cache, uuid_str, strdup(domain));
        switch_mutex_unlock(globals.cache_mutex);
}

static char* get_cached_domain(const char *uuid_str)
{
        char *domain = NULL;
        char *result = NULL;

        if (zstr(uuid_str)) {
                return NULL;
        }

        switch_mutex_lock(globals.cache_mutex);
        domain = (char *)switch_core_hash_find(uuid_domain_cache, uuid_str);
        if (domain) {
                result = strdup(domain);
        }
        switch_mutex_unlock(globals.cache_mutex);

        return result;
}

static void remove_cached_domain(const char *uuid_str)
{
        char *domain = NULL;

        if (zstr(uuid_str)) {
                return;
        }

        switch_mutex_lock(globals.cache_mutex);
        domain = (char *)switch_core_hash_find(uuid_domain_cache, uuid_str);
        if (domain) {
                switch_core_hash_delete(uuid_domain_cache, uuid_str);
                free(domain);
        }
        switch_mutex_unlock(globals.cache_mutex);
}

static char* get_domain_from_uuid(const char *uuid_str)
{
        switch_core_session_t *session = NULL;
        switch_channel_t *channel = NULL;
        const char *domain = NULL;
        char *result = NULL;

        if (zstr(uuid_str)) {
                return NULL;
        }

        /* First check cache */
        result = get_cached_domain(uuid_str);
        if (result) {
                return result;
        }

        /* Try to get from active session */
        session = switch_core_session_locate(uuid_str);
        if (session) {
                channel = switch_core_session_get_channel(session);
                if (channel) {
                        /* Try multiple channel variables to get domain */
                        domain = switch_channel_get_variable(channel, "domain_name");
                        if (zstr(domain)) {
                                domain = switch_channel_get_variable(channel, "sip_req_host");
                        }
                        if (zstr(domain)) {
                                domain = switch_channel_get_variable(channel, "sip_to_host");
                        }
                        if (zstr(domain)) {
                                domain = switch_channel_get_variable(channel, "sip_from_host");
                        }

                        if (!zstr(domain)) {
                                result = strdup(domain);
                                /* Cache it for future use */
                                cache_uuid_domain(uuid_str, domain);
                                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, 
                                                                 "mod_logfile_domain: Domain '%s' found and cached for UUID: %s\n", result, uuid_str);
                        }
                }
                switch_core_session_rwunlock(session);
        }

        return result;
}

/* Improved domain cleaning function */
static char* clean_domain_string(const char *domain)
{
        char *cleaned = NULL;
        char *p = NULL;
        int len;

        if (zstr(domain)) {
                return NULL;
        }

        cleaned = strdup(domain);
        
        /* Convert to lowercase */
        p = cleaned;
        while (*p) {
                *p = (char) tolower((int) *p);
                p++;
        }

        /* Remove trailing/leading whitespace and invalid characters */
        /* Find first valid character */
        p = cleaned;
        while (*p && (isspace(*p) || !isascii(*p))) {
                p++;
        }
        
        if (*p == '\0') {
                free(cleaned);
                return NULL;
        }

        /* If we skipped characters, move string to beginning */
        if (p != cleaned) {
                memmove(cleaned, p, strlen(p) + 1);
        }

        /* Truncate at first invalid character (only allow alphanumeric, dot, dash, underscore) */
        p = cleaned;
        while (*p) {
                if (!isascii(*p) || (!isalnum(*p) && *p != '.' && *p != '-' && *p != '_')) {
                        *p = '\0';
                        break;
                }
                p++;
        }

        /* Remove trailing dots, dashes, underscores */
        len = strlen(cleaned);
        while (len > 0 && (cleaned[len-1] == '.' || cleaned[len-1] == '-' || cleaned[len-1] == '_')) {
                cleaned[len-1] = '\0';
                len--;
        }

        if (zstr(cleaned)) {
                free(cleaned);
                return NULL;
        }

        return cleaned;
}

/* Check extracted domain against currently active domain profiles for EXACT match */
static char* find_matching_cached_domain(const char *extracted_domain)
{
        switch_hash_index_t *hi;
        const void *var;
        void *val;
        domain_logfile_profile_t *profile;
        char *found_domain = NULL;
        char *cleaned_extracted = NULL;
        char *cleaned_profile = NULL;

        if (zstr(extracted_domain)) {
                return NULL;
        }

        /* Clean the extracted domain */
        cleaned_extracted = clean_domain_string(extracted_domain);
        if (!cleaned_extracted) {
                return NULL;
        }

        switch_mutex_lock(globals.mutex);

        /* Look for EXACT match in cached profiles */
        for (hi = switch_core_hash_first(domain_profile_hash); hi; hi = switch_core_hash_next(&hi)) {
                switch_core_hash_this(hi, &var, NULL, &val);
                profile = (domain_logfile_profile_t *)val;

                if (profile && profile->domain_name) {
                        /* Clean the cached domain name for comparison */
                        cleaned_profile = clean_domain_string(profile->domain_name);
                        
                        if (cleaned_profile) {
                                /* EXACT match comparison (case-insensitive due to cleaning) */
                                if (strcmp(cleaned_profile, cleaned_extracted) == 0) {
                                        /* Found exact match - use the original cached domain name */
                                        found_domain = strdup(profile->domain_name);
                                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, 
                                                        "mod_logfile_domain: Extracted domain '%s' exactly matched cached domain '%s'\n", 
                                                        extracted_domain, profile->domain_name);
                                        free(cleaned_profile);
                                        break;
                                }
                                free(cleaned_profile);
                        }
                }
        }

        switch_mutex_unlock(globals.mutex);
        free(cleaned_extracted);

        return found_domain;
}

/* Extract domain from log data - with improved cleaning */
static char* extract_domain_from_logdata(const char *log_data)
{
        char *temp = NULL;
        char *context_pos = NULL;
        char *at_pos = NULL;
        char *end = NULL;
        char *cleaned = NULL;

        if (zstr(log_data)) {
                return NULL;
        }

        /* Look for "in context" pattern: "Processing ... in context 192.168.1.157" */
        context_pos = strstr(log_data, "in context ");
        if (context_pos) {
                context_pos += 11; /* Skip "in context " */
                temp = strdup(context_pos);
                
                /* Find end of domain */
                end = strchr(temp, '\n');
                if (end) *end = '\0';
                end = strchr(temp, ' ');
                if (end) *end = '\0';
                end = strchr(temp, ')');
                if (end) *end = '\0';
                end = strchr(temp, ']');
                if (end) *end = '\0';
                
                /* Clean the extracted domain */
                cleaned = clean_domain_string(temp);
                free(temp);
                
                if (cleaned && strlen(cleaned) > 0) {
                        return cleaned;
                }
                if (cleaned) free(cleaned);
        }

        /* Look for @domain pattern: "sofia/internal/1234@192.168.1.157" */
        temp = strdup(log_data);
        at_pos = strchr(temp, '@');
        if (at_pos) {
                at_pos++; /* Skip @ */
                
                /* Find end of domain */
                end = strchr(at_pos, ' ');
                if (end) *end = '\0';
                end = strchr(at_pos, '\n');
                if (end) *end = '\0';
                end = strchr(at_pos, ']');
                if (end) *end = '\0';
                end = strchr(at_pos, ')');
                if (end) *end = '\0';
                end = strchr(at_pos, ',');
                if (end) *end = '\0';

                /* Clean the extracted domain */
                cleaned = clean_domain_string(at_pos);
                free(temp);
                
                if (cleaned && strlen(cleaned) > 3) {
                        return cleaned;
                }
                if (cleaned) free(cleaned);
        } else {
                free(temp);
        }

        return NULL;
}

static domain_logfile_profile_t* get_domain_profile(const char *domain)
{
        domain_logfile_profile_t *profile = NULL;
        char logfile_path[512];

        if (zstr(domain)) {
                return NULL;
        }

        switch_mutex_lock(globals.mutex);

        /* Check if profile already exists */
        profile = (domain_logfile_profile_t *)switch_core_hash_find(domain_profile_hash, domain);

        if (!profile) {
                /* Create new domain profile */
                profile = switch_core_alloc(module_pool, sizeof(*profile));
                memset(profile, 0, sizeof(*profile));

                profile->domain_name = switch_core_strdup(module_pool, domain);

                /* Use global default settings */
                profile->all_level = globals.default_log_level;
                profile->roll_size = globals.default_roll_size;
                profile->max_rot = globals.default_max_rot;
                profile->log_uuid = globals.log_uuid;
                profile->suffix = 1;

                /* Create domain-specific log file path: /path/to/log/domain.log */
                switch_snprintf(logfile_path, sizeof(logfile_path), 
                                                "%s%s%s.log", 
                                                SWITCH_GLOBAL_dirs.log_dir, 
                                                SWITCH_PATH_SEPARATOR, 
                                                domain);
                profile->logfile = switch_core_strdup(module_pool, logfile_path);

                /* Open log file */
                if (mod_logfile_domain_openlogfile(profile, SWITCH_TRUE) == SWITCH_STATUS_SUCCESS) {
                        switch_core_hash_insert(domain_profile_hash, domain, (void *)profile);
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, 
                                                         "mod_logfile_domain: Created domain-specific log: %s for domain: %s\n", 
                                                         profile->logfile, domain);
                } else {
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, 
                                                         "mod_logfile_domain: Failed to create log file: %s\n", profile->logfile);
                        profile = NULL;
                }
        }

        switch_mutex_unlock(globals.mutex);
        return profile;
}

static switch_status_t mod_logfile_domain_openlogfile(domain_logfile_profile_t *profile, switch_bool_t check)
{
        unsigned int flags = 0;
        switch_file_t *afd;
        switch_status_t stat;

        flags |= SWITCH_FOPEN_CREATE;
        flags |= SWITCH_FOPEN_READ;
        flags |= SWITCH_FOPEN_WRITE;
        flags |= SWITCH_FOPEN_APPEND;

        stat = switch_file_open(&afd, profile->logfile, flags, SWITCH_FPROT_OS_DEFAULT, module_pool);
        if (stat != SWITCH_STATUS_SUCCESS) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, 
                                                 "mod_logfile_domain: logfile %s open error, status=%d\n", profile->logfile, stat);
                return SWITCH_STATUS_FALSE;
        }

        profile->log_afd = afd;
        profile->log_size = switch_file_get_size(profile->log_afd);

        if (check && profile->roll_size && profile->log_size >= profile->roll_size) {
                mod_logfile_domain_rotate(profile);
        }

        return SWITCH_STATUS_SUCCESS;
}

static switch_status_t mod_logfile_domain_rotate(domain_logfile_profile_t *profile)
{
        unsigned int i = 0;
        char *filename = NULL;
        switch_status_t stat = 0;
        int64_t offset = 0;
        switch_memory_pool_t *pool = NULL;
        switch_time_exp_t tm;
        char date[80] = "";
        switch_size_t retsize;
        switch_status_t status = SWITCH_STATUS_SUCCESS;

        switch_mutex_lock(globals.mutex);

        switch_time_exp_lt(&tm, switch_micro_time_now());
        switch_strftime_nocheck(date, &retsize, sizeof(date), "%Y-%m-%d-%H-%M-%S", &tm);

        profile->log_size = 0;
        stat = switch_file_seek(profile->log_afd, SWITCH_SEEK_SET, &offset);

        if (stat != SWITCH_STATUS_SUCCESS) {
                status = SWITCH_STATUS_FALSE;
                goto end;
        }

        switch_core_new_memory_pool(&pool);
        filename = switch_core_alloc(pool, strlen(profile->logfile) + WARM_FUZZY_OFFSET);

        if (profile->max_rot) {
                char *from_filename = NULL;
                char *to_filename = NULL;

                from_filename = switch_core_alloc(pool, strlen(profile->logfile) + WARM_FUZZY_OFFSET);
                to_filename = switch_core_alloc(pool, strlen(profile->logfile) + WARM_FUZZY_OFFSET);

                for (i=profile->suffix; i>1; i--) {
                        sprintf((char *) to_filename, "%s.%i", profile->logfile, i);
                        sprintf((char *) from_filename, "%s.%i", profile->logfile, i-1);

                        if (switch_file_exists(to_filename, pool) == SWITCH_STATUS_SUCCESS) {
                                if ((status = switch_file_remove(to_filename, pool)) != SWITCH_STATUS_SUCCESS) {
                                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "mod_logfile_domain: Error removing log %s\n",to_filename);
                                        goto end;
                                }
                        }

                        if ((status = switch_file_rename(from_filename, to_filename, pool)) != SWITCH_STATUS_SUCCESS) {
                                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "mod_logfile_domain: Error renaming log from %s to %s [%s]\n",
                                                                 from_filename, to_filename, strerror(errno));
                                if (errno != ENOENT) {
                                        goto end;
                                }
                        }
                }

                sprintf((char *) to_filename, "%s.%i", profile->logfile, i);

                if (switch_file_exists(to_filename, pool) == SWITCH_STATUS_SUCCESS) {
                        if ((status = switch_file_remove(to_filename, pool)) != SWITCH_STATUS_SUCCESS) {
                                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "mod_logfile_domain: Error removing log %s [%s]\n", to_filename, strerror(errno));
                                goto end;
                        }
                }

                switch_file_close(profile->log_afd);
                if ((status = switch_file_rename(profile->logfile, to_filename, pool)) != SWITCH_STATUS_SUCCESS) {
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "mod_logfile_domain: Error renaming log from %s to %s [%s]\n", profile->logfile, to_filename, strerror(errno));
                        goto end;
                }

                if ((status = mod_logfile_domain_openlogfile(profile, SWITCH_FALSE)) != SWITCH_STATUS_SUCCESS) {
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "mod_logfile_domain: Error reopening log %s\n", profile->logfile);
                }
                if (profile->suffix < profile->max_rot) {
                        profile->suffix++;
                }

                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "mod_logfile_domain: New log started: %s\n", profile->logfile);
                goto end;
        }

        for (i = 1; i < MAX_ROT; i++) {
                sprintf((char *) filename, "%s.%s.%i", profile->logfile, date, i);
                if (switch_file_exists(filename, pool) == SWITCH_STATUS_SUCCESS) {
                        continue;
                }

                switch_file_close(profile->log_afd);
                switch_file_rename(profile->logfile, filename, pool);
                if ((status = mod_logfile_domain_openlogfile(profile, SWITCH_FALSE)) != SWITCH_STATUS_SUCCESS) {
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "mod_logfile_domain: Error Rotating Log!\n");
                        goto end;
                }
                break;
        }

        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "mod_logfile_domain: New log started.\n");

 end:
        if (pool) {
                switch_core_destroy_memory_pool(&pool);
        }
        switch_mutex_unlock(globals.mutex);
        return status;
}

static switch_status_t mod_logfile_domain_raw_write(domain_logfile_profile_t *profile, char *log_data)
{
        switch_size_t len;
        switch_status_t status = SWITCH_STATUS_SUCCESS;

        if (!profile || !profile->log_afd) {
                return SWITCH_STATUS_FALSE;
        }

        len = strlen(log_data);
        if (len <= 0) {
                return SWITCH_STATUS_FALSE;
        }

        switch_mutex_lock(globals.mutex);

        if (switch_file_write(profile->log_afd, log_data, &len) != SWITCH_STATUS_SUCCESS) {
                switch_file_close(profile->log_afd);
                if ((status = mod_logfile_domain_openlogfile(profile, SWITCH_TRUE)) == SWITCH_STATUS_SUCCESS) {
                        len = strlen(log_data);
                        switch_file_write(profile->log_afd, log_data, &len);
                }
        }

        switch_mutex_unlock(globals.mutex);

        if (status == SWITCH_STATUS_SUCCESS) {
                profile->log_size += len;

                if (profile->roll_size && profile->log_size >= profile->roll_size) {
                        mod_logfile_domain_rotate(profile);
                }
        }

        return status;
}

static switch_status_t mod_logfile_domain_logger(const switch_log_node_t *node, switch_log_level_t level)
{
        char *domain = NULL;
        char *extracted_domain = NULL;
        char *matched_domain = NULL;
        domain_logfile_profile_t *domain_profile = NULL;
        size_t ok = 0;

        /* Try to get domain from UUID first */
        if (!zstr(node->userdata)) {
                domain = get_domain_from_uuid(node->userdata);
        }

        /* Second try: Extract domain from log data if UUID lookup failed */
        if (!domain && !zstr(node->data)) {
                extracted_domain = extract_domain_from_logdata(node->data);

                if (extracted_domain) {
                        /* Try to find exact match in cached domains */
                        matched_domain = find_matching_cached_domain(extracted_domain);

                        if (matched_domain) {
                                /* Use the cached domain (exact match found) */
                                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, 
                                                "mod_logfile_domain: Extracted domain '%s' matched cached domain '%s'\n", 
                                                extracted_domain, matched_domain);
                                free(extracted_domain);
                                domain = matched_domain;
                        } else {
                                /* No exact match - use the cleaned extracted domain */
                                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, 
                                                "mod_logfile_domain: Using new extracted domain '%s'\n", 
                                                extracted_domain);
                                domain = extracted_domain;
                        }
                }
        }

        /* If we found a domain, write to domain-specific log */
        if (domain) {
                domain_profile = get_domain_profile(domain);
                if (domain_profile) {
                        ok = switch_log_check_mask(domain_profile->all_level, level);
                        if (ok) {
                                if (domain_profile->log_uuid && !zstr(node->userdata)) {
                                        char buf[2048];
                                        char *dup = strdup(node->data);
                                        char *lines[100];
                                        int argc, i;

                                        argc = switch_split(dup, '\n', lines);
                                        for (i = 0; i < argc; i++) {
                                                switch_snprintf(buf, sizeof(buf), "%s %s\n", node->userdata, lines[i]);
                                                mod_logfile_domain_raw_write(domain_profile, buf);
                                        }
                                        free(dup);
                                } else {
                                        mod_logfile_domain_raw_write(domain_profile, node->data);
                                }
                        }
                }
                free(domain);
        }

        return SWITCH_STATUS_SUCCESS;
}

/* Event handler for channel events to manage cache */
static void channel_event_handler(switch_event_t *event)
{
        const char *uuid = switch_event_get_header(event, "Unique-ID");
        const char *domain = NULL;

        if (zstr(uuid)) {
                return;
        }

        switch (event->event_id) {
                case SWITCH_EVENT_CHANNEL_CREATE:
                case SWITCH_EVENT_CHANNEL_ANSWER:
                        /* Try to get and cache domain early */
                        domain = switch_event_get_header(event, "variable_domain_name");
                        if (zstr(domain)) {
                                domain = switch_event_get_header(event, "variable_sip_req_host");
                        }
                        if (zstr(domain)) {
                                domain = switch_event_get_header(event, "variable_sip_to_host");
                        }
                        if (zstr(domain)) {
                                domain = switch_event_get_header(event, "variable_sip_from_host");
                        }
                        if (!zstr(domain)) {
                                cache_uuid_domain(uuid, domain);
                        }
                        break;

                case SWITCH_EVENT_CHANNEL_DESTROY:
                        /* Clean up cache when channel is destroyed */
                        remove_cached_domain(uuid);
                        break;

                default:
                        break;
        }
}

static void event_handler(switch_event_t *event)
{
        const char *sig = switch_event_get_header(event, "Trapped-Signal");
        switch_hash_index_t *hi;
        void *val;
        const void *var;
        domain_logfile_profile_t *profile;

        if (sig && !strcmp(sig, "HUP")) {
                if (globals.rotate) {
                        for (hi = switch_core_hash_first(domain_profile_hash); hi; hi = switch_core_hash_next(&hi)) {
                                switch_core_hash_this(hi, &var, NULL, &val);
                                profile = val;
                                if (profile && profile->log_afd) {
                                        mod_logfile_domain_rotate(profile);
                                }
                        }
                } else {
                        switch_mutex_lock(globals.mutex);
                        for (hi = switch_core_hash_first(domain_profile_hash); hi; hi = switch_core_hash_next(&hi)) {
                                switch_core_hash_this(hi, &var, NULL, &val);
                                profile = val;
                                if (profile && profile->log_afd) {
                                        switch_file_close(profile->log_afd);
                                        if (mod_logfile_domain_openlogfile(profile, SWITCH_TRUE) != SWITCH_STATUS_SUCCESS) {
                                                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "mod_logfile_domain: Error Re-opening Log!\n");
                                        }
                                }
                        }
                        switch_mutex_unlock(globals.mutex);
                }
        }
}

SWITCH_MODULE_LOAD_FUNCTION(mod_logfile_domain_load)
{
        char *cf = "logfile_domain.conf";
        switch_xml_t cfg, xml, settings, param;

        module_pool = pool;

        memset(&globals, 0, sizeof(globals));
        switch_mutex_init(&globals.mutex, SWITCH_MUTEX_NESTED, module_pool);
        switch_mutex_init(&globals.cache_mutex, SWITCH_MUTEX_NESTED, module_pool);

        /* Set default values */
        globals.default_log_level = SWITCH_LOG_DEBUG | SWITCH_LOG_INFO | SWITCH_LOG_NOTICE | SWITCH_LOG_WARNING | SWITCH_LOG_ERROR | SWITCH_LOG_CRIT | SWITCH_LOG_ALERT;
        globals.default_roll_size = 104857600; /* 100MB */
        globals.default_max_rot = 32;
        globals.log_uuid = SWITCH_TRUE;
        globals.rotate = SWITCH_TRUE;

        if (domain_profile_hash) {
                switch_core_hash_destroy(&domain_profile_hash);
        }
        switch_core_hash_init(&domain_profile_hash);

        if (uuid_domain_cache) {
                switch_core_hash_destroy(&uuid_domain_cache);
        }
        switch_core_hash_init(&uuid_domain_cache);

        if (switch_event_bind_removable(modname, SWITCH_EVENT_TRAP, SWITCH_EVENT_SUBCLASS_ANY, event_handler, NULL, &globals.node) != SWITCH_STATUS_SUCCESS) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mod_logfile_domain: Couldn't bind to TRAP event!\n");
                return SWITCH_STATUS_GENERR;
        }

        *module_interface = switch_loadable_module_create_module_interface(pool, modname);

        /* Load configuration */
        if (!(xml = switch_xml_open_cfg(cf, &cfg, NULL))) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "mod_logfile_domain: Open of %s failed, using defaults\n", cf);
        } else {
                if ((settings = switch_xml_child(cfg, "settings"))) {
                        for (param = switch_xml_child(settings, "param"); param; param = param->next) {
                                char *var = (char *) switch_xml_attr_soft(param, "name");
                                char *val = (char *) switch_xml_attr_soft(param, "value");

                                if (!strcmp(var, "rotate-on-hup")) {
                                        globals.rotate = switch_true(val);
                                } else if (!strcmp(var, "default-log-level")) {
                                        globals.default_log_level = switch_log_str2mask(val);
                                } else if (!strcmp(var, "default-rollover")) {
                                        globals.default_roll_size = switch_atoui(val);
                                } else if (!strcmp(var, "default-maximum-rotate")) {
                                        globals.default_max_rot = switch_atoui(val);
                                        if (globals.default_max_rot == 0) {
                                                globals.default_max_rot = MAX_ROT;
                                        }
                                } else if (!strcmp(var, "uuid")) {
                                        globals.log_uuid = switch_true(val);
                                }
                        }
                }
                switch_xml_free(xml);
        }

        /* Bind to channel events for caching domain info */
        if (switch_event_bind_removable(modname, SWITCH_EVENT_CHANNEL_CREATE, SWITCH_EVENT_SUBCLASS_ANY, 
                                                                         channel_event_handler, NULL, &globals.channel_create_node) != SWITCH_STATUS_SUCCESS) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "mod_logfile_domain: Couldn't bind to CHANNEL_CREATE event\n");
        }
        if (switch_event_bind_removable(modname, SWITCH_EVENT_CHANNEL_ANSWER, SWITCH_EVENT_SUBCLASS_ANY, 
                                                                         channel_event_handler, NULL, &globals.channel_answer_node) != SWITCH_STATUS_SUCCESS) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "mod_logfile_domain: Couldn't bind to CHANNEL_ANSWER event\n");
        }
        if (switch_event_bind_removable(modname, SWITCH_EVENT_CHANNEL_DESTROY, SWITCH_EVENT_SUBCLASS_ANY, 
                                                                         channel_event_handler, NULL, &globals.channel_destroy_node) != SWITCH_STATUS_SUCCESS) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "mod_logfile_domain: Couldn't bind to CHANNEL_DESTROY event\n");
        }

        /* Bind our logger */
        switch_log_bind_logger(mod_logfile_domain_logger, SWITCH_LOG_DEBUG, SWITCH_FALSE);

        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, 
                                         "mod_logfile_domain loaded successfully. Domain-based logging enabled.\n");

        return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_logfile_domain_shutdown)
{
        switch_hash_index_t *hi;

        switch_log_unbind_logger(mod_logfile_domain_logger);
        switch_event_unbind(&globals.node);
        switch_event_unbind(&globals.channel_create_node);
        switch_event_unbind(&globals.channel_answer_node);
        switch_event_unbind(&globals.channel_destroy_node);

        /* Close all open log files */
        if (domain_profile_hash) {
                for (hi = switch_core_hash_first(domain_profile_hash); hi; hi = switch_core_hash_next(&hi)) {
                        void *val;
                        const void *key;
                        domain_logfile_profile_t *profile;

                        switch_core_hash_this(hi, &key, NULL, &val);
                        profile = (domain_logfile_profile_t *)val;

                        if (profile && profile->log_afd) {
                                switch_file_close(profile->log_afd);
                                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, 
                                                                 "mod_logfile_domain: Closing %s\n", 
                                                                 profile->logfile ? profile->logfile : "unknown");
                        }
                }
                switch_core_hash_destroy(&domain_profile_hash);
        }

        /* Clean up UUID cache */
        if (uuid_domain_cache) {
                for (hi = switch_core_hash_first(uuid_domain_cache); hi; hi = switch_core_hash_next(&hi)) {
                        void *val;
                        const void *key;
                        char *domain;

                        switch_core_hash_this(hi, &key, NULL, &val);
                        domain = (char *)val;

                        if (domain) {
                                free(domain);
                        }
                }
                switch_core_hash_destroy(&uuid_domain_cache);
        }

        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "mod_logfile_domain shutdown complete\n");

        return SWITCH_STATUS_SUCCESS;
}

/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4 noet:
 */