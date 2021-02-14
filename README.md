# Certificate Transparency extension search tool

## Important links

* [known logs](https://github.com/google/certificate-transparency-community-site/blob/master/docs/google/known-logs.md)

## Example invocation

```
cargo run -- live-stream https://ct.googleapis.com/logs/argon2021/ | while IFS= read -r line; do printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$line"; done
```
