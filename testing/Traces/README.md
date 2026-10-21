# Upstream HTTP regression corpus

`merged_zeek_HTTP_btest.pcap.zip` merges all 86 captures recursively under
`testing/btest/Traces/http/` in [Zeek](https://github.com/zeek/zeek/tree/1a89fc466b275fdfa6cbb7d4e30ab7300bf0f31a/testing/btest/Traces/http)
at commit `1a89fc466b275fdfa6cbb7d4e30ab7300bf0f31a`.
All source captures were tracked and unmodified. The inputs include eight
captures in subdirectories and two compressed captures; generator scripts
were excluded. The upstream copyright notice and terms are reproduced in
[COPYING.Zeek](COPYING.Zeek).

The corpus contains 13,216 packets. Nine raw IPv4 captures received synthetic
Ethernet headers; one loopback capture had its link-layer headers replaced
with synthetic Ethernet headers. IP packets were preserved. Inputs were
merged by timestamp into a classic PCAP, retaining packet order within each
input, including out-of-order timestamps. No packets were transmitted to
build or replay the corpus.

The ZIP is 4,627,718 bytes and expands to an 8,376,926-byte PCAP.
Its SHA-256 is
`09d144d3daec82cee906c40353a4aea08ce04457e2f56b8c815021024ee7a3df`.

The `upstream-http` btest extracts this archive and compares complete TSV
`http.log` and `notice.log` outputs. With default version cutoffs it expects
one version-inventory notice for PHP 8.0.26 and no `reporter.log`.
The merged replay produces 1,261 HTTP records; separate replays produce
1,266, so this is an aggregate regression test.
