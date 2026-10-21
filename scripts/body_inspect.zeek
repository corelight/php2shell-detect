module PHP2SHELL;

function body_sample_detail(data: string): string
	{
	if ( notice_body_sample_bytes == 0 )
		return "";

	# Bound the raw bytes before escaping quotes, backslashes,
	# and binary data.
	local sample = sub_bytes(data, 1, notice_body_sample_bytes);
	return fmt(", sample_bytes=%d, sample_truncated=%s, body_sample=\"%s\"",
	           |sample|, |sample| < |data|, to_string_literal(sample));
	}

function inspect_form_name(c: connection, info: HTTP::Info,
                           f: fa_file, data: string, part: string): bool
	{
	local php_longjump_fi = get_longjump_file_info(f);

	if ( part == "&" )
		{
		php_longjump_fi$form_name_done = F;
		php_longjump_fi$form_name_bytes = 0;
		return F;
		}

	if ( php_longjump_fi$form_name_done )
		return F;

	# PHP terminates registered names at a raw NUL. Ignore the rest
	# of this field, but keep looking for subsequent ampersands.
	local name_end = strstr(part, "=");
	local nul = strstr(part, "\x00");
	if ( nul > 0 && (name_end == 0 || nul < name_end) )
		name_end = nul;

	if ( name_end > 0 )
		{
		php_longjump_fi$form_name_bytes += name_end - 1;
		php_longjump_fi$form_name_done = T;
		}
	else
		php_longjump_fi$form_name_bytes += |part|;

	local php_longjump = get_longjump_info(info);

	if ( php_longjump_fi$form_name_bytes < large_form_key_bytes ||
	     "large-form-key" in php_longjump$indicators )
		return F;

	local detail =
		fmt("source=post_body, body_format=form_urlencoded, fuid=%s",
		    f$id);
	detail = fmt("%s, inspected_bytes=%d, field_name_bytes=%d, threshold_bytes=%d%s",
	             detail, php_longjump$body_bytes,
	             php_longjump_fi$form_name_bytes,
	             large_form_key_bytes, body_sample_detail(data));

	report_indicator(c, info, "large-form-key", Large_Form_Key, detail);

	if ( detect_only_once )
		{
		stop_post_body(f);
		return T;
		}

	return F;
	}

function inspect_form_names(c: connection, info: HTTP::Info,
                            f: fa_file, data: string)
	{
	# Keep separator tokens so a field name can span chunks and a long
	# value is never charged as a long name. Counts are wire bytes, before
	# URL decoding; no complete name or value needs to be buffered.
	local parts = split_string_all(data, /&/);

	for ( _, part in parts )
		if ( inspect_form_name(c, info, f, data, part) )
			return;
	}

event post_body_data(c: connection, info: HTTP::Info, f: fa_file, data: string)
	{
	# Form-encoded requests use name counters instead of body pattern
	# matching.
	local php_longjump = get_longjump_info(info);

	if ( php_longjump$form_encoded )
		{
		inspect_form_names(c, info, f, data);
		return;
		}

	local php_longjump_fi = get_longjump_file_info(f);

	# Classify once. Only incomplete eligible prefixes need another chunk.
	if ( ! php_longjump_fi$serialized )
		{
		local f_prefix = php_longjump_fi$prefix;
		local prefix = cat(f_prefix,
		                   sub_bytes(data, 1, 64 - |f_prefix|));

		if ( serialized_array_start in prefix )
			{
			php_longjump_fi$serialized = T;
			php_longjump_fi$tail = f_prefix;
			php_longjump_fi$prefix = "";
			}

		else if ( |prefix| < 64 && serialized_array_partial in prefix )
			{
			php_longjump_fi$prefix = prefix;
			return;
			}
		else
			{
			php_longjump_fi$rejected = T;
			stop_post_body(f);
			return;
			}
		}

	# Include retained boundary bytes when searching the current chunk.
	local window = data;

	if ( |php_longjump_fi$tail| > 0 )
		window = php_longjump_fi$tail + data;

	local nwindow = |window|;

	for ( _, marker in body_markers[window] )
		{
		if ( marker !in body_notice_types ||
		     marker in php_longjump$indicators )
			next;

		local detail = fmt("source=post_body, body_format=php_serialized, fuid=%s",
		                   f$id);
		detail = fmt("%s, inspected_bytes=%d, window_bytes=%d%s; suspicious structure, crash attempt suspected",
		             detail, php_longjump$body_bytes,
		             nwindow, body_sample_detail(window));

		report_indicator(c, info, marker,
		                 body_notice_types[marker], detail);

		if ( detect_only_once )
			{
			stop_post_body(f);
			return;
			}
		}

	# Retain only the overlap needed for the next chunk.
	local start = nwindow > body_overlap_bytes ?
	              nwindow - body_overlap_bytes + 1 : 1;
	php_longjump_fi$tail = sub_bytes(window, start, body_overlap_bytes);
	}
