# Certificate Transparency extension search tool

Made to answer [a question](https://github.com/briansmith/webpki/issues/135#issuecomment-759120464) for whether there are publicly trusted certificates that use the NameConstraints extension.

## Important links

* [known logs](https://github.com/google/certificate-transparency-community-site/blob/master/docs/google/known-logs.md)

## Example invocation

```
cargo run -- live-stream https://ct.googleapis.com/logs/argon2021/ | while IFS= read -r line; do printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$line"; done

cargo run -- scan https://ct.googleapis.com/logs/argon2021/ 0 20 | while IFS= read -r line; do printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$line"; done
```

### License
[license]: #license

This crate is distributed under the terms of both the MIT license
and the Apache License (Version 2.0), at your option.

See [LICENSE](LICENSE) for details.

#### License of your contributions

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in the work by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
