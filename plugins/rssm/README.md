# Root Server Scaling Measurement (RSSM) plugin

This plugin collects data as described by the [RSSAC002v3 specification](https://www.icann.org/en/system/files/files/rssac-002-measurements-root-06jun16-en.pdf)
which has been created by [ICANN Root Server System Advisory Committee](https://www.icann.org/groups/rssac) (RSSAC).

## Additions

As the RSSAC002v3 specification states that measurements should be saved per
24 hours interval, this plugin produces additional metrics that can be used
to compile the 24 hours measurements allowing for variable time between
output generation.

Metric `dnscap-rssm-sources` has a hash entry called `sources` which lists
IP addresses and the number of times they appeared.

Metric `dnscap-rssm-aggregated-sources` has a hash entry called `aggregated-sources`
which lists the aggregated IPv6 addresses by a /64 net and the number of times
it has appeared.

## Merge Tool

The Perl script `dnscap-rssm-rssac002` is included and installed with `dnscap`
and can be used to multiple combine RSSM plugin RSSAC002v3 YAML output files
into one file.

The script will merge and remove metric specific to this plugin and replace
others to fill in correct values for the new time period. The earliest
`start-period` found will be used for all metrics.

**NOTE** no parsing of `start-period` is performed, it is up to the operator
to only give input files related to the same 24 hour period.

Options:
- `--no-recompile`: Disabled the combining of metrics and the removal of
  metrics specific to this plugin
- `--keep-dnscap-rssm`: Do the combining but keep the metrics specific to
  this plugin
- `--sort`: Output will always start with `version:`, `service:`,
  `start-period:` and `metric:`, rest of the values are not ordered by label.
  This option enabled sorting of them, which is not required by the
  specification but may help in debugging and testing cases.
