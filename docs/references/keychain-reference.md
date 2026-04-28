# macOS Keychain reference notes

macOS Keychain is a likely local backend for early users.

Implementation requirements:

- no secret value in logs or errors
- clear permission prompts when the OS requires them
- deterministic fake backend in tests instead of real Keychain dependency

Reference links should be added when implementation begins.
