# Security policy

## What zipcheck is (and is not)

`zipcheck` is a **static risk scanner**. It reads archive metadata and reports
whether extraction is likely to be dangerous. It is not a sandbox, an antivirus,
or a guarantee that an archive is safe.

The scanner itself is designed to be safe against hostile inputs:

- it never extracts archive members to disk or memory beyond a bounded prefix;
- it never invokes `unzip`, `7z`, `tar`, `rar`, or any external program;
- it caps metadata reads, entry counts, nested depth, decompressed bytes and
  wall-clock time;
- it checks 7z/xz decoder dictionary sizes against a memory cap.

Those controls protect against resource exhaustion during the scan. They say
nothing about what happens if *you* later extract the archive with another tool.
Always extract untrusted archives in a disposable environment with disk, CPU,
memory and time quotas.

## Supported versions

Security fixes are applied to the latest `0.1.x` release.

## Reporting a vulnerability

Please **do not** attach a live archive bomb to a public issue. Instead:

1. Open a private GitHub security advisory for the repository.
2. Describe the problem and the smallest possible reproduction: a hex dump, a
   generator snippet, or a metadata-only fixture. A 50-byte file that declares
   a huge size is usually enough.
3. Include the version, Python version and operating system.

Useful reports include:

- a malformed archive that crashes, hangs or allocates unbounded memory;
- a bounded-decompression bypass that exceeds the documented caps;
- a parser confusion that makes a clearly dangerous archive report `clean`;
- path traversal or command execution (there should be none);
- a way to make the scanner write to disk or spawn a process.

## Known non-goals

- Decrypting AES/password-protected archives.
- Proving that an archive is benign. `clean` means "no rule fired", not "safe".
- Detecting bombs in formats that are not parsed.
- Protecting a machine from extraction performed by a different program.

## Safe testing

The repository's tests build metadata-only archives that are tiny on disk. The
optional `tools/generate_samples.py` creates real bombs; run it only inside a
VM/container, never on a workstation, and never extract its output.
