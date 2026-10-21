module PHP2SHELL;

type Session_Key: record {
	client: addr;
	server: addr;
	server_port: port;
	host: string;
	session_digest: string;
};

type Pending_Trigger: record {
	last_seen: time;
	uid: string;
	trans_depth: count;
};

# Keys contain an in-memory session digest, scoped to client and HTTP
# authority. Neither the digest nor the cookie is written to any log.
global pending_sessions: table[Session_Key] of Pending_Trigger
                          &write_expire=correlation_window;

global submit_session_trigger:
	function(key: Session_Key, trigger: Pending_Trigger);
global submit_session_followup: function(c: connection, info: HTTP::Info,
                                         key: Session_Key, seen: time);

function session_key(c: connection, info: HTTP::Info,
                     session: string): Session_Key
	{
	local id = c$id;
	return Session_Key($client=id$orig_h, $server=id$resp_h,
	                   $server_port=id$resp_p,
	                   $host=info?$host ? to_lower(info$host) : "",
	                   $session_digest=session);
	}

function store_session_trigger(key: Session_Key, trigger: Pending_Trigger)
	{
	# Late messages must not replace a newer trigger for the same session.
	if ( key in pending_sessions )
		{
		if ( trigger$last_seen < pending_sessions[key]$last_seen )
			return;
		}

	else if ( |pending_sessions| >= max_pending_sessions )
		return;

	pending_sessions[key] = trigger;
	}

function matching_session_trigger(trigger: Pending_Trigger, uid: string,
                                  trans_depth: count, seen: time): bool
	{
	# Compare observation times, not the order in which workers
	# deliver events.
	return seen >= trigger$last_seen &&
	       seen - trigger$last_seen <= correlation_window &&
	       (trigger$uid != uid || trigger$trans_depth != trans_depth);
	}

function crash_sequence_detail(trigger: Pending_Trigger, seen: time): string
	{
	local detail = "source=mime_header, header_name=CONTENT-DISPOSITION, ";
	detail += fmt("trigger_uid=%s, trigger_trans_depth=%d, ",
	              trigger$uid, trigger$trans_depth);
	detail += fmt("age_seconds=%.6f, window_seconds=%g",
	              interval_to_double(seen - trigger$last_seen),
	              interval_to_double(correlation_window));
	detail += "; related suspicious HTTP transactions; crash attempt suspected";
	return detail;
	}

function report_crash_sequence(c: connection, info: HTTP::Info,
                               trigger: Pending_Trigger, seen: time)
	{
	report_indicator(c, info, "php-crash-sequence", PHP_Crash_Sequence,
	                 crash_sequence_detail(trigger, seen));
	}

function track_suspicious_sessions(c: connection, info: HTTP::Info)
	{
	if ( ! inspect_cookies || ! info?$php_longjump )
		return;

	local php_longjump = info$php_longjump;
	if ( ! php_longjump$suspicious )
		return;

	# Associate suspicious activity with identifiers seen in
	# either direction.
	local sessions = php_longjump$request_sessions |
	                 php_longjump$response_sessions;

	for ( session in sessions )
		{
		local key = session_key(c, info, session);
		local trigger = Pending_Trigger($last_seen=network_time(),
		                                $uid=c$uid,
		                                $trans_depth=info$trans_depth);
		if ( Cluster::is_enabled() )
			submit_session_trigger(key, trigger);
		else
			store_session_trigger(key, trigger);
		}
	}

function check_crash_sequence(c: connection, info: HTTP::Info)
	{
	if ( ! inspect_cookies || ! info?$php_longjump )
		return;

	local php_longjump = info$php_longjump;
	if ( ! php_longjump$upload_progress )
		return; #@ NOT-TESTED

	for ( session in php_longjump$request_sessions )
		{
		local key = session_key(c, info, session);

		if ( Cluster::is_enabled() )
			{
			submit_session_followup(c, info, key, network_time());
			next;
			}

		if ( key !in pending_sessions )
			next;

		local trigger = pending_sessions[key];
		if ( ! matching_session_trigger(trigger, c$uid,
		                                info$trans_depth,
		                                network_time()) )
			next;

		report_crash_sequence(c, info, trigger, network_time());

		return;
		}
	}

function get_longjump_info(info: HTTP::Info): PHP_LongjumpInfo
	{
	if ( ! info?$php_longjump )
		info$php_longjump = PHP_LongjumpInfo();

	return info$php_longjump;
	}

function remember_session(c: connection, info: HTTP::Info,
                          is_orig: bool, value: string)
	{
	local php_longjump = get_longjump_info(info);

	# Response attributes do not need to be split or inspected.
	if ( ! is_orig )
		{
		local semicolon = strstr(value, ";");
		if ( semicolon > 0 )
			value = sub_bytes(value, 1, semicolon - 1);
		}

	# Keep only configured cookie identifiers, retained as in-memory
	# digests.
	local changed = F;
	local pairs = split_string(value, /;/);

	for ( i, pair in pairs )
		{
		local equals = strstr(pair, "=");
		if ( equals == 0 )
			next;

		local name = strip(sub_bytes(pair, 1, equals - 1));
		if ( name !in session_cookie_names )
			next;

		local token = strip(sub_bytes(pair, equals + 1,
		                              |pair| - equals));
		if ( starts_with(token, "\"") && ends_with(token, "\"") &&
		     |token| >= 2 )
			token = sub_bytes(token, 2, |token| - 2);
		if ( |token| == 0 )
			next;

		local digest = sha256_hash(cat(name, "=", token));

		if ( is_orig )
			{
			changed = changed || digest !in
			                     php_longjump$request_sessions;
			add php_longjump$request_sessions[digest];
			}

		else
			{
			changed = changed || digest !in
			                     php_longjump$response_sessions;
			add php_longjump$response_sessions[digest];
			}
		}

	# A new identifier can arrive after the transaction's first finding.
	if ( changed )
		track_suspicious_sessions(c, info);
	}
