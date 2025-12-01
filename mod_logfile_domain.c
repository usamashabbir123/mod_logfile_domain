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
 * Anthony LaMantia <anthony@petabit.net>
 * Michael Jerris <mike@jerris.com>
 *
 *
 * mod_logfile.c -- Filesystem Logging with Domain-based Support
 *
 */

#include <switch.h>

SWITCH_MODULE_LOAD_FUNCTION(mod_logfile_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_logfile_shutdown);
SWITCH_MODULE_DEFINITION(mod_logfile, mod_logfile_load, mod_logfile_shutdown, NULL);

#define DEFAULT_LIMIT    0xA00000       /* About 10 MB */
#define WARM_FUZZY_OFFSET 256
#define MAX_ROT 4096                    /* why not */
#define UUID_CACHE_SIZE 1000

static switch_memory_pool_t *module_pool = NULL;
static switch_hash_t *profile_hash = NULL;
static switch_hash_t *domain_profile_hash = NULL;
static switch_hash_t *uuid_domain_cache = NULL;

static struct {
	int rotate;
	switch_mutex_t *mutex;
	switch_mutex_t *cache_mutex;
	switch_event_node_t *node;
	switch_bool_t domain_based_logging;
} globals;

struct logfile_profile {
	char *name;
	switch_size_t log_size;
	switch_size_t roll_size;
	switch_size_t max_rot;
	char *logfile;
	switch_file_t *log_afd;
	switch_hash_t *log_hash;
	uint32_t all_level;
	uint32_t suffix;
	switch_bool_t log_uuid;
	switch_bool_t is_domain_profile;
	char *domain_name;
};

typedef struct logfile_profile logfile_profile_t;

/* Forward declarations */
static switch_status_t load_profile(switch_xml_t xml);
static switch_status_t mod_logfile_openlogfile(logfile_profile_t *profile, switch_bool_t check);
static switch_status_t mod_logfile_rotate(logfile_profile_t *profile);
static switch_status_t mod_logfile_raw_write(logfile_profile_t *profile, char *log_data);

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
				                "Domain '%s' found and cached for UUID: %s\n", result, uuid_str);
			}
		}
		switch_core_session_rwunlock(session);
	}

	return result;
}

/* Extract domain from log data when UUID is not available */
static char* extract_domain_from_logdata(const char *log_data)
{
	char *result = NULL;
	char *temp = NULL;
	char *context_pos = NULL;
	char *at_pos = NULL;
	char *end = NULL;
	
	if (zstr(log_data)) {
		return NULL;
	}

	/* Look for "in context" pattern: "Processing ... in context 192.168.1.157" */
	context_pos = strstr(log_data, "in context ");
	if (context_pos) {
		context_pos += 11; /* Skip "in context " */
		temp = strdup(context_pos);
		end = strchr(temp, '\n');
		if (end) *end = '\0';
		end = strchr(temp, ' ');
		if (end) *end = '\0';
		if (!zstr(temp)) {
			result = temp;
			return result;
		}
		free(temp);
	}

	/* Look for @domain pattern: "sofia/internal/1234@192.168.1.157" */
	temp = strdup(log_data);
	at_pos = strchr(temp, '@');
	if (at_pos) {
		at_pos++; /* Skip @ */
		end = strchr(at_pos, ' ');
		if (end) *end = '\0';
		end = strchr(at_pos, '\n');
		if (end) *end = '\0';
		end = strchr(at_pos, ']');
		if (end) *end = '\0';
		if (!zstr(at_pos) && strlen(at_pos) > 3) {
			result = strdup(at_pos);
			free(temp);
			return result;
		}
	}
	free(temp);

	return NULL;
}

static logfile_profile_t* get_domain_profile(const char *domain)
{
	logfile_profile_t *profile = NULL;
	logfile_profile_t *template_profile = NULL;
	char profile_name[256];
	char logfile_path[512];

	if (zstr(domain)) {
		return NULL;
	}

	switch_mutex_lock(globals.mutex);

	/* Check if profile already exists */
	profile = (logfile_profile_t *)switch_core_hash_find(domain_profile_hash, domain);
	
	if (!profile) {
		/* Get the default profile as template */
		template_profile = (logfile_profile_t *)switch_core_hash_find(profile_hash, "default");
		if (!template_profile) {
			switch_mutex_unlock(globals.mutex);
			return NULL;
		}

		/* Create new domain profile */
		profile = switch_core_alloc(module_pool, sizeof(*profile));
		memset(profile, 0, sizeof(*profile));
		switch_core_hash_init(&(profile->log_hash));

		switch_snprintf(profile_name, sizeof(profile_name), "domain_%s", domain);
		profile->name = switch_core_strdup(module_pool, profile_name);
		profile->domain_name = switch_core_strdup(module_pool, domain);
		profile->is_domain_profile = SWITCH_TRUE;

		/* Copy settings from template */
		profile->all_level = template_profile->all_level;
		profile->roll_size = template_profile->roll_size;
		profile->max_rot = template_profile->max_rot;
		profile->log_uuid = template_profile->log_uuid;
		profile->suffix = 1;

		/* Create domain-specific log file path: /path/to/log/domain.log */
		switch_snprintf(logfile_path, sizeof(logfile_path), 
		               "%s%s%s.log", 
		               SWITCH_GLOBAL_dirs.log_dir, 
		               SWITCH_PATH_SEPARATOR, 
		               domain);
		profile->logfile = switch_core_strdup(module_pool, logfile_path);

		/* Open log file */
		if (mod_logfile_openlogfile(profile, SWITCH_TRUE) == SWITCH_STATUS_SUCCESS) {
			switch_core_hash_insert(domain_profile_hash, domain, (void *)profile);
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, 
			                "Created domain-specific log: %s for domain: %s\n", 
			                profile->logfile, domain);
		} else {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, 
			                "Failed to create log file: %s\n", profile->logfile);
			switch_core_hash_destroy(&profile->log_hash);
			profile = NULL;
		}
	}

	switch_mutex_unlock(globals.mutex);
	return profile;
}

static void add_mapping(logfile_profile_t *profile, char *var, char *val)
{
	if (!strcasecmp(var, "all")) {
		profile->all_level |= (uint32_t) switch_log_str2mask(val);
		return;
	}

	switch_core_hash_insert(profile->log_hash, var, (void *) (intptr_t) switch_log_str2mask(val));
}

static switch_status_t mod_logfile_openlogfile(logfile_profile_t *profile, switch_bool_t check)
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
		                "logfile %s open error, status=%d\n", profile->logfile, stat);
		return SWITCH_STATUS_FALSE;
	}

	profile->log_afd = afd;
	profile->log_size = switch_file_get_size(profile->log_afd);

	if (check && profile->roll_size && profile->log_size >= profile->roll_size) {
		mod_logfile_rotate(profile);
	}

	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t mod_logfile_rotate(logfile_profile_t *profile)
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
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Error removing log %s\n",to_filename);
					goto end;
				}
			}

			if ((status = switch_file_rename(from_filename, to_filename, pool)) != SWITCH_STATUS_SUCCESS) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Error renaming log from %s to %s [%s]\n",
				                                  from_filename, to_filename, strerror(errno));
				if (errno != ENOENT) {
					goto end;
				}
			}
		}

		sprintf((char *) to_filename, "%s.%i", profile->logfile, i);

		if (switch_file_exists(to_filename, pool) == SWITCH_STATUS_SUCCESS) {
			if ((status = switch_file_remove(to_filename, pool)) != SWITCH_STATUS_SUCCESS) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Error removing log %s [%s]\n", to_filename, strerror(errno));
				goto end;
			}
		}

		switch_file_close(profile->log_afd);
		if ((status = switch_file_rename(profile->logfile, to_filename, pool)) != SWITCH_STATUS_SUCCESS) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Error renaming log from %s to %s [%s]\n", profile->logfile, to_filename, strerror(errno));
			goto end;
		}

		if ((status = mod_logfile_openlogfile(profile, SWITCH_FALSE)) != SWITCH_STATUS_SUCCESS) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Error reopening log %s\n", profile->logfile);
		}
		if (profile->suffix < profile->max_rot) {
			profile->suffix++;
		}

		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "New log started: %s\n", profile->logfile);
		goto end;
	}

	for (i = 1; i < MAX_ROT; i++) {
		sprintf((char *) filename, "%s.%s.%i", profile->logfile, date, i);
		if (switch_file_exists(filename, pool) == SWITCH_STATUS_SUCCESS) {
			continue;
		}

		switch_file_close(profile->log_afd);
		switch_file_rename(profile->logfile, filename, pool);
		if ((status = mod_logfile_openlogfile(profile, SWITCH_FALSE)) != SWITCH_STATUS_SUCCESS) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Error Rotating Log!\n");
			goto end;
		}
		break;
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "New log started.\n");

  end:
	if (pool) {
		switch_core_destroy_memory_pool(&pool);
	}
	switch_mutex_unlock(globals.mutex);
	return status;
}

static switch_status_t mod_logfile_raw_write(logfile_profile_t *profile, char *log_data)
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
		if ((status = mod_logfile_openlogfile(profile, SWITCH_TRUE)) == SWITCH_STATUS_SUCCESS) {
			len = strlen(log_data);
			switch_file_write(profile->log_afd, log_data, &len);
		}
	}

	switch_mutex_unlock(globals.mutex);

	if (status == SWITCH_STATUS_SUCCESS) {
		profile->log_size += len;

		if (profile->roll_size && profile->log_size >= profile->roll_size) {
			mod_logfile_rotate(profile);
		}
	}

	return status;
}

static switch_status_t process_node(const switch_log_node_t *node, switch_log_level_t level)
{
	switch_hash_index_t *hi;
	void *val;
	const void *var;
	logfile_profile_t *profile;
	char *domain = NULL;
	logfile_profile_t *domain_profile = NULL;

	/* Try to get domain if domain-based logging is enabled */
	if (globals.domain_based_logging) {
		/* First try: Get domain from UUID */
		if (!zstr(node->userdata)) {
			domain = get_domain_from_uuid(node->userdata);
		}
		
		/* Second try: Extract domain from log data if UUID lookup failed */
		if (!domain && !zstr(node->data)) {
			domain = extract_domain_from_logdata(node->data);
		}

		/* If we found a domain, write to domain-specific log */
		if (domain) {
			domain_profile = get_domain_profile(domain);
			if (domain_profile) {
				size_t ok = switch_log_check_mask(domain_profile->all_level, level);
				if (ok) {
					if (domain_profile->log_uuid && !zstr(node->userdata)) {
						char buf[2048];
						char *dup = strdup(node->data);
						char *lines[100];
						int argc, i;

						argc = switch_split(dup, '\n', lines);
						for (i = 0; i < argc; i++) {
							switch_snprintf(buf, sizeof(buf), "%s %s\n", node->userdata, lines[i]);
							mod_logfile_raw_write(domain_profile, buf);
						}
						free(dup);
					} else {
						mod_logfile_raw_write(domain_profile, node->data);
					}
				}
			}
			free(domain);
		}
	}

	/* Write to regular profiles (e.g., freeswitch.log for all logs) */
	for (hi = switch_core_hash_first(profile_hash); hi; hi = switch_core_hash_next(&hi)) {
		size_t mask = 0;
		size_t ok = 0;

		switch_core_hash_this(hi, &var, NULL, &val);
		profile = val;

		/* Skip if this is a domain profile or no log file */
		if (!profile || !profile->log_afd) {
			continue;
		}

		ok = switch_log_check_mask(profile->all_level, level);

		if (!ok) {
			mask = (size_t) switch_core_hash_find(profile->log_hash, node->file);
			ok = switch_log_check_mask(mask, level);
		}

		if (!ok) {
			mask = (size_t) switch_core_hash_find(profile->log_hash, node->func);
			ok = switch_log_check_mask(mask, level);
		}

		if (!ok) {
			char tmp[256] = "";
			switch_snprintf(tmp, sizeof(tmp), "%s:%s", node->file, node->func);
			mask = (size_t) switch_core_hash_find(profile->log_hash, tmp);
			ok = switch_log_check_mask(mask, level);
		}

		if (ok) {
			if (profile->log_uuid && !zstr(node->userdata)) {
				char buf[2048];
				char *dup = strdup(node->data);
				char *lines[100];
				int argc, i;

				argc = switch_split(dup, '\n', lines);
				for (i = 0; i < argc; i++) {
					switch_snprintf(buf, sizeof(buf), "%s %s\n", node->userdata, lines[i]);
					mod_logfile_raw_write(profile, buf);
				}
				free(dup);
			} else {
				mod_logfile_raw_write(profile, node->data);
			}
		}
	}

	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t mod_logfile_logger(const switch_log_node_t *node, switch_log_level_t level)
{
	return process_node(node, level);
}

static void cleanup_profile(void *ptr)
{
	logfile_profile_t *profile = (logfile_profile_t *) ptr;

	if (profile->log_hash) {
		switch_core_hash_destroy(&profile->log_hash);
	}
	if (profile->log_afd) {
		switch_file_close(profile->log_afd);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Closing %s\n", 
		                profile->logfile ? profile->logfile : "unknown");
	}
	switch_safe_free(profile->logfile);
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

static switch_status_t load_profile(switch_xml_t xml)
{
	switch_xml_t param, settings;
	char *name = (char *) switch_xml_attr_soft(xml, "name");
	logfile_profile_t *new_profile;

	new_profile = switch_core_alloc(module_pool, sizeof(*new_profile));
	memset(new_profile, 0, sizeof(*new_profile));
	switch_core_hash_init(&(new_profile->log_hash));
	new_profile->name = switch_core_strdup(module_pool, switch_str_nil(name));

	new_profile->suffix = 1;
	new_profile->log_uuid = SWITCH_TRUE;
	new_profile->is_domain_profile = SWITCH_FALSE;

	if ((settings = switch_xml_child(xml, "settings"))) {
		for (param = switch_xml_child(settings, "param"); param; param = param->next) {
			char *var = (char *) switch_xml_attr_soft(param, "name");
			char *val = (char *) switch_xml_attr_soft(param, "value");
			if (!strcmp(var, "logfile")) {
				new_profile->logfile = strdup(val);
			} else if (!strcmp(var, "rollover")) {
				new_profile->roll_size = switch_atoui(val);
			} else if (!strcmp(var, "maximum-rotate")) {
				new_profile->max_rot = switch_atoui(val);
				if (new_profile->max_rot == 0) {
					new_profile->max_rot = MAX_ROT;
				}
			} else if (!strcmp(var, "uuid")) {
				new_profile->log_uuid = switch_true(val);
			}
		}
	}

	if ((settings = switch_xml_child(xml, "mappings"))) {
		for (param = switch_xml_child(settings, "map"); param; param = param->next) {
			char *var = (char *) switch_xml_attr_soft(param, "name");
			char *val = (char *) switch_xml_attr_soft(param, "value");
			add_mapping(new_profile, var, val);
		}
	}

	if (zstr(new_profile->logfile)) {
		char logfile[512];
		switch_snprintf(logfile, sizeof(logfile), "%s%s%s", 
		               SWITCH_GLOBAL_dirs.log_dir, SWITCH_PATH_SEPARATOR, "freeswitch.log");
		new_profile->logfile = strdup(logfile);
	}

	if (mod_logfile_openlogfile(new_profile, SWITCH_TRUE) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, 
		                "Failed to open logfile: %s\n", new_profile->logfile);
		return SWITCH_STATUS_GENERR;
	}

	switch_core_hash_insert_destructor(profile_hash, new_profile->name, 
	                                   (void *) new_profile, cleanup_profile);
	
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, 
	                "Loaded profile '%s' with logfile: %s\n", 
	                new_profile->name, new_profile->logfile);
	
	return SWITCH_STATUS_SUCCESS;
}

static void event_handler(switch_event_t *event)
{
	const char *sig = switch_event_get_header(event, "Trapped-Signal");
	switch_hash_index_t *hi;
	void *val;
	const void *var;
	logfile_profile_t *profile;

	if (sig && !strcmp(sig, "HUP")) {
		if (globals.rotate) {
			for (hi = switch_core_hash_first(profile_hash); hi; hi = switch_core_hash_next(&hi)) {
				switch_core_hash_this(hi, &var, NULL, &val);
				profile = val;
				if (profile && profile->log_afd) {
					mod_logfile_rotate(profile);
				}
			}
			for (hi = switch_core_hash_first(domain_profile_hash); hi; hi = switch_core_hash_next(&hi)) {
				switch_core_hash_this(hi, &var, NULL, &val);
				profile = val;
				if (profile && profile->log_afd) {
					mod_logfile_rotate(profile);
				}
			}
		} else {
			switch_mutex_lock(globals.mutex);
			for (hi = switch_core_hash_first(profile_hash); hi; hi = switch_core_hash_next(&hi)) {
				switch_core_hash_this(hi, &var, NULL, &val);
				profile = val;
				if (profile && profile->log_afd) {
					switch_file_close(profile->log_afd);
					if (mod_logfile_openlogfile(profile, SWITCH_TRUE) != SWITCH_STATUS_SUCCESS) {
						switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Error Re-opening Log!\n");
					}
				}
			}
			switch_mutex_unlock(globals.mutex);
		}
	}
}

SWITCH_MODULE_LOAD_FUNCTION(mod_logfile_load)
{
	char *cf = "logfile.conf";
	switch_xml_t cfg, xml, settings, param, profiles, xprofile;
	switch_event_node_t *channel_event_node = NULL;

	module_pool = pool;

	memset(&globals, 0, sizeof(globals));
	switch_mutex_init(&globals.mutex, SWITCH_MUTEX_NESTED, module_pool);
	switch_mutex_init(&globals.cache_mutex, SWITCH_MUTEX_NESTED, module_pool);
	globals.domain_based_logging = SWITCH_FALSE;

	if (profile_hash) {
		switch_core_hash_destroy(&profile_hash);
	}
	switch_core_hash_init(&profile_hash);

	if (domain_profile_hash) {
		switch_core_hash_destroy(&domain_profile_hash);
	}
	switch_core_hash_init(&domain_profile_hash);

	if (uuid_domain_cache) {
		switch_core_hash_destroy(&uuid_domain_cache);
	}
	switch_core_hash_init(&uuid_domain_cache);

	if (switch_event_bind_removable(modname, SWITCH_EVENT_TRAP, SWITCH_EVENT_SUBCLASS_ANY, event_handler, NULL, &globals.node) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't bind!\n");
		return SWITCH_STATUS_GENERR;
	}

	*module_interface = switch_loadable_module_create_module_interface(pool, modname);

	if (!(xml = switch_xml_open_cfg(cf, &cfg, NULL))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Open of %s failed\n", cf);
	} else {
		if ((settings = switch_xml_child(cfg, "settings"))) {
			for (param = switch_xml_child(settings, "param"); param; param = param->next) {
				char *var = (char *) switch_xml_attr_soft(param, "name");
				char *val = (char *) switch_xml_attr_soft(param, "value");
				if (!strcmp(var, "rotate-on-hup")) {
					globals.rotate = switch_true(val);
				} else if (!strcmp(var, "domain-based-logging")) {
					globals.domain_based_logging = switch_true(val);
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, 
					                "Domain-based logging: %s\n", 
					                globals.domain_based_logging ? "ENABLED" : "DISABLED");
				}
			}
		}

		if ((profiles = switch_xml_child(cfg, "profiles"))) {
			for (xprofile = switch_xml_child(profiles, "profile"); xprofile; xprofile = xprofile->next) {
				if (load_profile(xprofile) != SWITCH_STATUS_SUCCESS) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "error loading profile.\n");
				}
			}
		}

		switch_xml_free(xml);
	}

	/* Bind to channel events for caching domain info */
	if (globals.domain_based_logging) {
		if (switch_event_bind_removable(modname, SWITCH_EVENT_CHANNEL_CREATE, SWITCH_EVENT_SUBCLASS_ANY, 
		                                 channel_event_handler, NULL, &channel_event_node) != SWITCH_STATUS_SUCCESS) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Couldn't bind to CHANNEL_CREATE event\n");
		}
		if (switch_event_bind_removable(modname, SWITCH_EVENT_CHANNEL_ANSWER, SWITCH_EVENT_SUBCLASS_ANY, 
		                                 channel_event_handler, NULL, &channel_event_node) != SWITCH_STATUS_SUCCESS) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Couldn't bind to CHANNEL_ANSWER event\n");
		}
		if (switch_event_bind_removable(modname, SWITCH_EVENT_CHANNEL_DESTROY, SWITCH_EVENT_SUBCLASS_ANY, 
		                                 channel_event_handler, NULL, &channel_event_node) != SWITCH_STATUS_SUCCESS) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Couldn't bind to CHANNEL_DESTROY event\n");
		}
	}

	switch_log_bind_logger(mod_logfile_logger, SWITCH_LOG_DEBUG, SWITCH_FALSE);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, 
	                "mod_logfile loaded successfully. Domain-based logging: %s\n",
	                globals.domain_based_logging ? "ENABLED" : "DISABLED");

	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_logfile_shutdown)
{
	switch_log_unbind_logger(mod_logfile_logger);
	switch_event_unbind(&globals.node);
	switch_core_hash_destroy(&profile_hash);
	switch_core_hash_destroy(&domain_profile_hash);
	switch_core_hash_destroy(&uuid_domain_cache);
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