# HTTP POST file analysis, scoped before attaching an analyzer.
# No http_entity_data handler is registered by this package.

module PHP2SHELL;

type PHP_LongjumpFileInfo: record {
	http: HTTP::Info &optional;
	tail: string &default="";
	prefix: string &default="";
	serialized: bool &default=F;
	rejected: bool &default=F;
	stopped: bool &default=F;

	# A value separator or raw NUL ends name counting until the next field.
	form_name_done: bool &default=F;
	form_name_bytes: count &default=0;
};

redef record fa_file += {
	php_longjump: PHP_LongjumpFileInfo &optional;
};

global handle_post_body: event(f: fa_file, data: string);

function get_longjump_file_info(f: fa_file): PHP_LongjumpFileInfo
	{
	if ( ! f?$php_longjump )
		f$php_longjump = PHP_LongjumpFileInfo();

	return f$php_longjump;
	}

function stop_post_body(f: fa_file)
	{
	# Remove only this package's callback, once per entity.
	local php_longjump_fi = get_longjump_file_info(f);
	if ( php_longjump_fi$stopped )
		return;

	php_longjump_fi$stopped = T;

	Files::remove_analyzer(f, Files::ANALYZER_DATA_EVENT,
	                       [$stream_event=handle_post_body]);
	}

event handle_post_body(f: fa_file, data: string)
	{
	local php_longjump_fi = get_longjump_file_info(f);
	if ( ! php_longjump_fi?$http || php_longjump_fi$stopped )
		return;

	local info = php_longjump_fi$http;
	local php_longjump = get_longjump_info(info);

	# Stop in first-finding mode, or when the shared budget is spent.
	if ( (detect_only_once && |php_longjump$indicators| > 0) ||
	     php_longjump$body_bytes >= http_body_analysis_byte_depth )
		{
		stop_post_body(f);
		return;
		}

	# Trim only the chunk that crosses the remaining transaction budget.
	local remaining = http_body_analysis_byte_depth -
	                  php_longjump$body_bytes;
	local chunk: string;

	if ( |data| > remaining )
		chunk = sub_bytes(data, 1, remaining);
	else
		chunk = data;

	php_longjump$body_bytes += |chunk|;

	# Detach now, but still deliver the final permitted chunk below.
	if ( php_longjump$body_bytes >= http_body_analysis_byte_depth )
		stop_post_body(f);

	if ( |chunk| == 0 )
		return;

	for ( cid in f$conns )
		event post_body_data(f$conns[cid], info, f, chunk);
	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool)
	{
	# Only attach to HTTP request entities when body inspection is enabled.
	if ( ! inspect_post_bodies || ! is_orig || f$source != "HTTP" )
		return;

	if ( ! c?$http )
		return; #@ NOT-TESTED

	local info = c$http;

	# Require an in-scope POST before accessing its detection state.
	if ( ! c?$http || ! eligible_http(info) || info$method != "POST" )
		return;

	local php_longjump = get_longjump_info(info);

	# First-finding mode skips later entities in the same transaction.
	if ( detect_only_once && |php_longjump$indicators| > 0 )
		return;

	# All entities in the transaction share one inspection budget.
	if ( php_longjump$body_bytes >= http_body_analysis_byte_depth )
		return;

	# Preserve the original transaction for queued file callbacks.
	local php_longjump_fi = get_longjump_file_info(f);
	php_longjump_fi$http = info;

	Files::add_analyzer(f, Files::ANALYZER_DATA_EVENT,
	                    [$stream_event=handle_post_body]);
	}
