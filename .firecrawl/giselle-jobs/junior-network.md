Service Update

# isecjobs.com has shut down

isecjobs.com shut down on June 30, 2026 due to lower-than-expected demand.


To find future jobs and more please continue on foorilla.com.


[Continue on foo🦍](https://foorilla.com/hiring/infosec-privacy/)

For builders: [API access to the hiring feed](https://foorilla.com/api/) is available with an active foo🦍 PRO+ subscription.


How We Built It

## Import script used for the feed

For transparency, here is the standalone Python importer that mirrors the original isecjobs.com
ingestion flow: API-key auth, topic plus keyword passes, pagination, 429 retry/backoff, expired-job
filtering, deduplication, and JSON output.


You can run this directly, adapt it to your stack, or use it as a baseline for your own scheduled
importer.


Copy script [foorilla API](https://foorilla.com/api/)

Attribution note: data from foorilla API is licensed under
[CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).