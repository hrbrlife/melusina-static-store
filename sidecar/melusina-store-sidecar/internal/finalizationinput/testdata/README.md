The immutable public `welcome-0.1.31-RELEASE.json` is the original governed provider release document retained from the accepted Welcome 0.1.31 release. Source: `mel-release-msb-account-opening-20260828/apps/021x360jnqz798taefscu7r69a0xvvqyhfwfjadq8g2f9wuqm5h0/provider/candidate/ceremony/RELEASE.json`. SHA-256: `44c17a9a059a4494e5ec5c096b624adf9d6a3de2c8bfbf396231b8af7f84f8ab`. It contains public release claims and an original public author signature, no custody key. Tests exercise schema compatibility and exact transport preservation; they do not treat this historical descriptor as current on-chain authorization. Synthetic package/finalizer tests use visibly synthetic package bytes and signatures.

`welcome-0.1.31-ceremony.json` retains that same provider's original public
`provider/candidate/ceremony-state.json` bytes, SHA-256
`56a28714448af8914195130e5a106650a4fbd6daab29062fa10c982bf935d9e4`.
Its unchanged author signature is verified against the original exact payload
and joined with the matching final descriptor. It remains historical evidence,
not a current execution proof. The independent synthetic SDK fixture under
`releasefinalizer/testdata` supplies package, instruction and account fixtures
for pending, execution, materialization and restart tests without custody keys.
