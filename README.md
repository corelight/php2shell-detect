# php2shell Detection

Zeek detections and Suricata rules for HTTP indicators associated with
"php2shell" CVE-2026-109618 / CVE-2026-109619, potential RCE in PHP longjmp()
memory handling. Findings identify suspicious traffic or potentially affected
software.

- [Corelight blog: PHP2Shell detection before disclosure][blog]
- [PHP advisory](https://www.php.net/archive/2026.php#2026-10-20-1)

## Zeek

Requires Zeek 7.0.0 or later. Install with the Zeek Package Manager:

```sh
zkg install https://github.com/corelight/php2shell-detect
```

Load installed packages with `@load packages` in your Zeek configuration.
For a direct checkout, load `/path/to/php2shell-detect/scripts`.
The package uses standard Zeek HTTP, file-analysis, notice, and cluster APIs.

The package inspects POST field-name lengths, selected serialized-data
structures, and repeated MIME headers. It also correlates related suspicious
transactions using configured session cookies. Response headers provide
separate PHP version inventory. Traffic must be visible to Zeek's HTTP
analyzer; encrypted HTTP requires decryption before inspection.

### Notices

All notice types are under `PHP2SHELL::`:

| Notice | Observation |
|---|---|
| `PHP_Crash_Sequence` | Related suspicious HTTP transactions within one session |
| `Multipart_Header_Flood` | Excessive repetition of recognized MIME headers |
| `Large_Form_Key` | Unusually long URL-encoded form field name |
| `Serialized_Integer_Overflow` | Unusually large serialized integer token |
| `Serialized_Integer_Collisions` | Recognized serialized integer-key pattern |
| `Serialized_String_Collisions` | Recognized serialized string-key pattern |
| `Serialized_Duplicate_Array` | Repeated serialized array-entry pattern |
| `Serialized_Object_Repetition` | Repeated serialized object pattern |
| `Potentially_Affected_PHP_Version` | Response header advertises a version within the configured affected range |

Results go to standard `notice.log`; the package creates no additional log
stream. The notice `sub` field supplies bounded context such as header name,
transaction depth, counts, and a short escaped POST-body sample. Samples are
limited to 64 raw bytes before escaping by default; set
`notice_body_sample_bytes=0` to omit them. Cookies and their digests are used
only in memory and are not logged by this package.

By default, each distinct request indicator can emit a notice per transaction.
Repeated matches of the same indicator are suppressed. Set `detect_only_once=T`
to stop body inspection after the first request finding in each transaction.
Version inventory notices are independent of request findings.

### Configuration

All settings use the `PHP2SHELL::` namespace:

| Setting | Default | Effect |
|---|---|---|
| `detect_only_once` | `F` | Report each distinct request indicator; `T` stops after the first finding |
| `max_trans_depth` | `3` | Inspect the first three HTTP transactions per connection; `0` means all |
| `inspect_cookies` | `T` | Use session cookies for correlation |
| `session_cookie_names` | `{"PHPSESSID"}` | Cookie names used to associate sessions |
| `correlation_window` | `1 min` | Maximum age of pending session correlation state |
| `max_pending_sessions` | `1000` | Cap retained entries in each correlation table |
| `inspect_post_bodies` | `T` | Inspect POST entity data and MIME headers |
| `http_body_analysis_byte_depth` | `8388608` | Conservative 8 MiB ceiling on POST-body inspection work, shared across MIME parts; `0` disables body delivery |
| `body_overlap_bytes` | `256` | Retained overlap for patterns crossing body chunks |
| `large_form_key_bytes` | `65536` | Form-name wire-byte threshold |
| `multipart_header_threshold` | `128` | Repeated recognized MIME headers needed for a finding |
| `notice_body_sample_bytes` | `64` | Maximum raw body bytes per notice sample; `0` omits samples |
| `detect_affected_php_versions` | `T` | Enable response-header version inventory |
| `php_version_notice_interval` | `1 hr` | Suppress version notices per server IP across ports and versions |
| `php_fixed_patch_versions` | `8.2: 35, 8.3: 36, 8.4: 27, 8.5: 12` | Provisional first fixed patch per branch |

For example:

```zeek
redef PHP2SHELL::detect_only_once = T;
redef PHP2SHELL::notice_body_sample_bytes = 0;
redef PHP2SHELL::session_cookie_names += { "custom_session" };
```

POST inspection uses file-analysis chunks with bounded overlap, rather than
assembling whole bodies. Form-name counting respects value separators and
raw NUL termination. Only eligible POST entities receive an analyzer; body
budgets and transaction limits intentionally constrain detection scope.
These indicators are incomplete and can also match benign traffic.

In a Zeek cluster, workers route small session observations to proxies with
`Cluster::publish_hrw()`. Both stages for the same session reach the same
proxy, which matches them and raises `PHP_Crash_Sequence` directly. The notice
retains the follow-up's connection ID, UID and transaction depth; `peer_descr`
identifies the proxy. Workers do not retain full connection or HTTP records
for callbacks.

Triggers and unmatched follow-ups expire after `correlation_window`, with
`max_pending_sessions` limiting each table. Proxies retain the first unmatched
follow-up for each session key. A trigger looks up that key directly to handle
messages arriving in reverse order; later unmatched follow-ups for the same
key are coalesced until that entry matches or expires. Matching uses observation
timestamps and the client, server, server port, HTTP host and session digest.
Standalone Zeek correlates locally. Normal proxy connectivity is required.

Proxy notices use standard notice suppression keyed by UID and transaction
depth for `correlation_window`. This is independent of worker findings and
does not stop worker body inspection. Simultaneous matches for different
session cookies on different proxies can still produce duplicate notices
before cluster suppression propagates.

### PHP version inventory

Outer `Server` and `X-Powered-By` response headers are checked, including
responses to GET. Header names are case-insensitive. The affected lower
bound is PHP 5.4.0. The following cutoffs assume the next patch after the
latest stable releases checked on 18 October 2026 will address both bugs:

| Branch | Latest stable when checked | Provisional first fixed release |
|---|---|---|
| 8.2 | 8.2.34 | 8.2.35 |
| 8.3 | 8.3.35 | 8.3.36 |
| 8.4 | 8.4.26 | 8.4.27 |
| 8.5 | 8.5.11 | 8.5.12 |

Configured fixed releases and later patches in the same branch do not alert.
Branches without a configured cutoff remain candidates. Common vendor
suffixes use the underlying numeric version. Banners can be absent, rewritten,
or reflect a vendor build with backported fixes, so these are inventory hints.

## Suricata rules

The three rules in
[suricata/php2shell.rules][rules]
run independently of Zeek. Installing the Zeek package with `zkg` does not
load these rules into Suricata. All three rules are enabled in the file;
Zeek configuration options do not affect them.

| SID | Inspection buffer | Observation |
|---|---|---|
| 3000650 | `http.request_body` with method `POST` | Detection marker in a request body |
| 3000651 | `http.response_header` | Potentially affected PHP version advertised by `Server` or `X-Powered-By` |
| 3000652 | `http.response_body` | Potentially affected PHP version in a phpinfo-shaped HTML heading |

### Loading the rules

Add the rule file to the existing `rule-files` list in your `suricata.yaml`,
keeping your other rule entries. Use the absolute path to your checkout:

```yaml
rule-files:
  - /path/to/php2shell-detect/suricata/php2shell.rules
```

Validate your configuration, then reload or restart Suricata using your
normal deployment procedure:

```sh
suricata -T -c /path/to/suricata.yaml
```

The rules were validated with Suricata 8.0.6. HTTP body inspection must be
enabled; request/response body limits and stream reassembly limits determine
which content reaches these rules. Encrypted HTTP requires decryption before
inspection.

### Interpreting alerts

Find these rules in EVE alert records using `alert.signature_id`, or by their
SID in your configured alert output. The POST marker can occur in legitimate
traffic and does not establish an exploit attempt. Suricata does not perform
the Zeek package's session correlation.

The version rules are software-inventory signals. Header names are matched
case-insensitively, and the body rule recognizes a phpinfo-shaped HTML
heading. Both use the [provisional version cutoffs](#php-version-inventory)
above; missing or rewritten banners and vendor backports limit their accuracy.
**TODO before release:** Verify both rules' affected ranges and first fixed
releases against official PHP advisories and release notes.

Each version rule limits alerts to one per server IP per hour, across clients,
ports, and advertised versions. They inspect responses, so `track by_src`
tracks the server. Each SID maintains its own limit; one server may therefore
produce both a header alert and a phpinfo alert in the same hour. The POST
marker rule has no hourly limit.

## Regression test

Install `btest` and ensure `zeek`, `zeek-cut`, `unzip`, `bash`, and `make`
are on `PATH`, then run:

```sh
make check
make test
make zam
```

`make zam` repeats the test with Zeek's ZAM optimizer enabled. The single
included btest uses the compressed merged upstream Zeek HTTP corpus and
compares complete TSV HTTP and notice logs. One PHP 8.0.26 inventory notice
is expected; `reporter.log` must be absent. See
[corpus provenance](testing/Traces/README.md) for input details and licensing.

[blog]: https://corelight.com/blog/php2shell-detection-before-disclosure
[rules]: suricata/php2shell.rules
