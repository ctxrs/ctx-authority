# OS keychain reference notes

The OS keychain backend uses the platform keychain through the Rust `keyring`
crate instead of shelling out to platform commands.

Target stores:

- macOS Keychain
- Windows Credential Manager
- Linux Secret Service/libsecret

Implementation requirements:

- no secret value in logs or errors
- clear permission prompts when the OS requires them
- deterministic fake keychain store in tests instead of real keychain access
- stable service name for broker-owned entries
- v1 resolves only broker-owned trusted references; action-supplied
  `secret_ref` values are not honored

Testing requirements:

- unit tests must not read or write the real OS keychain
- tests use the backend store abstraction with fixture values
- fake store misses use generic errors that do not contain secret values

Public references:

- Rust `keyring` crate: https://docs.rs/keyring/latest/keyring/
- `keyring::Entry`: https://docs.rs/keyring/latest/keyring/struct.Entry.html
