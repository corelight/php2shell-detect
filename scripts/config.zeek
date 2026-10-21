module PHP2SHELL;

export {
	redef enum Notice::Type += {
		PHP_Crash_Sequence,
		Multipart_Header_Flood,
		Large_Form_Key,
		Serialized_Integer_Overflow,
		Serialized_Integer_Collisions,
		Serialized_String_Collisions,
		Serialized_Duplicate_Array,
		Serialized_Object_Repetition,
		Potentially_Affected_PHP_Version,
	};

	## Stop after the first finding per HTTP transaction. F reports each
	## distinct indicator while retaining the configured inspection limits.
	## In clusters, a submitted proxy correlation is independent of later
	## worker findings; both can produce a notice even with this option T.
	option detect_only_once = F;

	option max_trans_depth = 3;
	option inspect_cookies = T;
	option inspect_post_bodies = T;

	## Response-header inventory, independent of crash correlation.
	option detect_affected_php_versions = T;

	## Suppress version notices per server IP, across ports and versions.
	option php_version_notice_interval = 1 hr;

	## Branch -> first provisionally fixed patch number. Unlisted branches
	## remain candidates. TODO before release: verify these assumed cutoffs.
	## Assumes next patch after each latest stable release on 2026-10-18.
	const php_fixed_patch_versions = table(
		["8.2"] = 35,
		["8.3"] = 36,
		["8.4"] = 27,
		["8.5"] = 12,
	) &redef;

	option correlation_window = 1 min;
	option max_pending_sessions = 1000;

	const session_cookie_names = set("PHPSESSID") &redef;

	## A strict shared budget for POST entity data, across all MIME parts.
	option http_body_analysis_byte_depth = 8 * 1024 * 1024;

	option body_overlap_bytes = 256;
	option large_form_key_bytes = 64 * 1024;
	option multipart_header_threshold = 128;

	## Maximum raw body bytes included in a notice; 0 omits body samples.
	option notice_body_sample_bytes = 64;
}

## POST request entity data delivered by Files::ANALYZER_DATA_EVENT.
## Chunks are not whole bodies. f identifies a particular MIME entity.
global post_body_data: event(c: connection, info: HTTP::Info,
                             f: fa_file, data: string);

global eligible_http: function(info: HTTP::Info): bool;
global report_indicator:
	function(c: connection, info: HTTP::Info, indicator: string,
	         note: Notice::Type, detail: string);
global remember_session: function(c: connection, info: HTTP::Info,
                                  is_orig: bool, value: string);
global track_suspicious_sessions: function(c: connection, info: HTTP::Info);
global check_crash_sequence: function(c: connection, info: HTTP::Info);
global php_version_is_affected: function(version: string): bool;
global inspect_php_version_header:
	function(c: connection, name: string, value: string);

type PHP_LongjumpInfo: record {
	request_sessions: set[string] &default=set();
	response_sessions: set[string] &default=set();

	# Send each session once per transaction without retaining
	# worker contexts.
	submitted_sessions: set[string] &default=set();

	indicators: set[string] &default=set();
	body_bytes: count &default=0;
	upload_progress: bool &default=F;
	suspicious: bool &default=F;
	form_encoded: bool &default=F;
	multipart_headers: count &default=0;
	version_reported: bool &default=F;
};

redef record HTTP::Info += {
	php_longjump: PHP_LongjumpInfo &optional;
};

function eligible_http(info: HTTP::Info): bool
	{
	return info?$method && (max_trans_depth == 0 ||
	                        info$trans_depth <= max_trans_depth);
	}

function report_indicator(c: connection, info: HTTP::Info, indicator: string,
                          note: Notice::Type, detail: string)
	{
	if ( ! info?$php_longjump )
		return; #@ NOT-TESTED

	local php_longjump = info$php_longjump;

	# Suppress duplicates and, in first-finding mode, later indicators.
	if ( (detect_only_once && |php_longjump$indicators| > 0) ||
	     indicator in php_longjump$indicators )
		return;

	add php_longjump$indicators[indicator];

	# Remember suspicious activity for correlation with later transactions.
	if ( note != PHP_Crash_Sequence )
		{
		php_longjump$suspicious = T;
		track_suspicious_sessions(c, info);
		}

	# Supporting context is supplied by detector that observed the finding.
	NOTICE([$note=note, $conn=c,
	        $msg=fmt("CVE-2026-109618 / CVE-2026-109619 Potential RCE in PHP longjmp() memory handling, indicator observed: %s",
	                 indicator),
	        $sub=fmt("indicator='%s', method=%s, trans_depth=%d, %s",
	                 indicator, info$method, info$trans_depth, detail),
	        $identifier=fmt("%s/%d/%s", c$uid, info$trans_depth, indicator),
	        $suppress_for=0 sec]);
	}
