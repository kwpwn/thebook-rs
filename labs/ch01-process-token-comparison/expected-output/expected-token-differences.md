# Expected Token Differences

Exact output depends on account type, UAC policy, domain policy, and Windows edition.

## Standard user or non-elevated admin shell

Common observations:

- Integrity level: Medium.
- Some admin-related privileges absent or disabled.
- Administrators group may be marked deny-only for a split-token admin.

## Elevated admin shell

Common observations:

- Integrity level: High.
- Administrators group enabled.
- More privileges visible or available.
- `SeDebugPrivilege` may be present, often disabled until enabled by a tool.

## Correct comparison dimensions

Compare:

- user SID;
- group SIDs;
- integrity level;
- privilege list;
- enabled vs disabled privileges;
- session ID;
- parent process;
- command line.

## Correct conclusion

Correct:

> The elevated process has a different token state from the standard process, including integrity and privilege differences.

Incorrect:

> Admin equals SYSTEM.

