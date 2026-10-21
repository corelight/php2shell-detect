module PHP2SHELL;

# Stable version triplets and common vendor suffixes; no partial versions.
const php_version_triplet =
	/^(0|[1-9][0-9]?)\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,3})$/;
const php_header_token = /^php\/(0|[1-9][0-9]?)\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,3})([-+][a-z0-9.+~_-]+)?$/;

function php_version_is_affected(version: string): bool
	{
	if ( php_version_triplet !in version )
		return F;

	local parts = split_string(version, /\./);
	local major = to_count(parts[0]);
	local minor = to_count(parts[1]);
	local patch = to_count(parts[2]);

	# TODO before release: verify affected ranges and first fixed releases
	# against official PHP advisories/release notes. Synchronize the lower
	# bound, fixed-patch table, Suricata rules, notice metadata, docs and
	# tests. The HTTP-affected range starts at 5.4.0. Configured cutoffs
	# provisionally assume the next patch releases are fixed; unlisted
	# branches remain candidates.
	if ( major < 5 || (major == 5 && minor < 4) )
		return F;

	local branch = fmt("%d.%d", major, minor);

	return branch !in php_fixed_patch_versions ||
	       patch < php_fixed_patch_versions[branch];
	}

function inspect_php_version_header(c: connection, name: string, value: string)
	{
	if ( ! c?$http || ! eligible_http(c$http) )
		return;

	local info = c$http;
	local php_longjump = get_longjump_info(info);

	# Ignore nested MIME headers and further version headers in
	# this response.
	if ( info$resp_mime_depth != 1 || php_longjump$version_reported )
		return;

	# Bound work even if a peer supplies an unusually large Server header.
	local bounded = sub_bytes(value, 1, 1024);

	# A truncated token must not become a valid version at the byte limit.
	if ( |value| > 1024 )
		bounded = cat(bounded, "!");

	local tokens = split_string(to_lower(bounded), /[ \t,;()]+/);

	for ( _, token in tokens )
		{
		if ( php_header_token !in token )
			next;

		local version = split_string(sub_bytes(token, 5, |token| - 4),
		                             /[-+]/)[0];
		if ( ! php_version_is_affected(version) )
			next;

		php_longjump$version_reported = T;

		# Inventory findings never mark a request suspicious or seed
		# a session. Share suppression across all ports and advertised
		# versions on a server.
		NOTICE([$note=Potentially_Affected_PHP_Version, $conn=c,
		        $msg=fmt("CVE-2026-109618 / CVE-2026-109619 Potential RCE in PHP longjmp() memory handling, PHP advertises a potentially affected version: %s",
		                 version),
		        $sub=fmt("source=response_header, header_name=%s, php_version=%s, trans_depth=%d, first_affected=5.4.0",
		                 name, version, info$trans_depth),
		        $identifier=cat(c$id$resp_h),
		        $suppress_for=php_version_notice_interval]);
		return;
		}
	}
