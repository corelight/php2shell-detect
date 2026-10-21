# @TEST-DOC: Merged upstream HTTP captures retain one expected PHP version notice without reporter errors.
# @TEST-EXEC: zeek -Cr $TRACES/trace.pcap $PACKAGE
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: btest-diff notice.log
# @TEST-EXEC: test "$(zeek-cut note < notice.log)" = "PHP2SHELL::Potentially_Affected_PHP_Version"
# @TEST-EXEC: ! test -f reporter.log
