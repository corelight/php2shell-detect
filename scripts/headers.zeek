module PHP2SHELL;

const form_encoded_RE = /^application\/x-www-form-urlencoded([ \t]*;|[ \t]*$)/;

event http_header(c: connection, is_orig: bool, name: string, value: string)
	{
	if ( ! c?$http )
		return; #@ NOT-TESTED

	local info = c$http;

	# Handle response headers here; the remaining checks are request-only.
	if ( ! is_orig )
		{
		# Version inventory also applies to responses to GET.
		if ( detect_affected_php_versions &&
		     (name == "SERVER" || name == "X-POWERED-BY") )
			inspect_php_version_header(c, name, value);

		if ( ! inspect_cookies || name != "SET-COOKIE" )
			return;

		if ( ! eligible_http(info) || info$method != "POST" )
			return;

		# Only outer response cookies can establish session state.
		if ( info$resp_mime_depth == 1 )
			remember_session(c, info, F, value);

		return;
		}

	if ( ! eligible_http(info) || info$method != "POST" )
		return;

	# Discard unrelated headers before looking up transaction state.
	if ( name != "COOKIE" && name != "CONTENT-TYPE" &&
	     name != "CONTENT-DISPOSITION" && name != "X" )
		return;

	local php_longjump = get_longjump_info(info);

	# Zeek also emits http_header for nested MIME entities. Its depth
	# counters are 1 for the outer HTTP entity, then increase for parts.
	# Outer request headers supply session identifiers and the body type.
	if ( info$orig_mime_depth == 1 )
		{
		if ( inspect_cookies && name == "COOKIE" )
			remember_session(c, info, T, value);

		else if ( inspect_post_bodies && name == "CONTENT-TYPE" )
			php_longjump$form_encoded =
				form_encoded_RE in to_lower(value);
		return;
		}

	# Apply MIME-part checks only while request inspection remains eligible.
	if ( ! inspect_post_bodies ||
	     (detect_only_once && |php_longjump$indicators| > 0) )
		return;

	if ( name == "CONTENT-DISPOSITION" && upload_progress_name in value )
		{
		php_longjump$upload_progress = T;
		check_crash_sequence(c, info);
		}

	else if ( name == "X" && value == "Y" )
		{
		++php_longjump$multipart_headers;

		if ( php_longjump$multipart_headers ==
		     multipart_header_threshold )
			{
			local detail = fmt("source=mime_header, header_name=%s, mime_depth=%d",
			                   name, info$orig_mime_depth);
			detail = cat(detail, fmt(", observed=%d, threshold=%d",
			                       php_longjump$multipart_headers,
			                       multipart_header_threshold));

			report_indicator(c, info, "multipart-header-flood",
			                 Multipart_Header_Flood, detail);
			}
		}
	}
