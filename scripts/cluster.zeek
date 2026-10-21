module PHP2SHELL;

# Workers send only the metadata needed to match and describe a follow-up.
type Session_Followup: record {
	seen: time;
	id: conn_id;
	uid: string;
	trans_depth: count;
};

# Retain early follow-ups when messages from different workers arrive reversed.
global pending_followups: table[Session_Key] of Session_Followup
                           &create_expire=correlation_window;

global session_trigger: event(key: Session_Key, trigger: Pending_Trigger);
global session_followup: event(key: Session_Key, followup: Session_Followup);

function submit_session_trigger(key: Session_Key, trigger: Pending_Trigger)
	{
	Cluster::publish_hrw(Cluster::proxy_pool, key,
	                     session_trigger, key, trigger);
	}

function submit_session_followup(c: connection, info: HTTP::Info,
                                 key: Session_Key, seen: time)
	{
	local php_longjump = get_longjump_info(info);

	if ( "php-crash-sequence" in php_longjump$indicators ||
	     (detect_only_once && |php_longjump$indicators| > 0) )
		return;

	# Repeated MIME fields must not publish the same session again.
	if ( key$session_digest in php_longjump$submitted_sessions )
		return;

	add php_longjump$submitted_sessions[key$session_digest];
	local followup = Session_Followup($seen=seen, $id=c$id, $uid=c$uid,
	                                  $trans_depth=info$trans_depth);

	Cluster::publish_hrw(Cluster::proxy_pool, key,
	                     session_followup, key, followup);
	}

function report_proxy_match(trigger: Pending_Trigger,
                            followup: Session_Followup)
	{
	NOTICE([$note=PHP_Crash_Sequence, $id=followup$id, $uid=followup$uid,
	        $msg="CVE-2026-109618 / CVE-2026-109619 Potential RCE in PHP longjmp() memory handling, indicator observed: php-crash-sequence",
	        $sub=fmt("indicator='php-crash-sequence', method=POST, trans_depth=%d, %s",
	                 followup$trans_depth,
	                 crash_sequence_detail(trigger, followup$seen)),
	        $identifier=fmt("%s/%d/php-crash-sequence",
	                        followup$uid, followup$trans_depth),
	        $suppress_for=correlation_window]);
	}

event session_trigger(key: Session_Key, trigger: Pending_Trigger)
	{
	store_session_trigger(key, trigger);

	if ( key !in pending_followups )
		return;

	local followup = pending_followups[key];
	local uid = followup$uid;
	local depth = followup$trans_depth;
	local seen = followup$seen;

	if ( matching_session_trigger(trigger, uid, depth, seen) )
		{
		report_proxy_match(trigger, followup);
		delete pending_followups[key];
		}
	}

event session_followup(key: Session_Key, followup: Session_Followup)
	{
	local uid = followup$uid;
	local depth = followup$trans_depth;

	if ( key in pending_sessions &&
	     matching_session_trigger(pending_sessions[key],
	                              uid, depth, followup$seen) )
		{
		report_proxy_match(pending_sessions[key], followup);
		return;
		}

	# Preserve the first observation.
	if ( key in pending_followups ||
	     |pending_followups| >= max_pending_sessions )
		return;

	pending_followups[key] = followup;
	}
