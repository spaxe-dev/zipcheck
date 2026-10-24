# Production deployment

## The uncomfortable truth

**No archive scanner can prove an upload is safe.** ZIP bombs are valid
archives. Headers can understate sizes. Encrypted data cannot be inspected.
Decompression libraries have bugs. If your web process opens and extracts a
user's archive, the attacker's input is running on your infrastructure.

`zipcheck` is therefore a **cheap pre-flight gate**, not the security boundary.
The boundary is an isolated extraction worker with hard OS quotas, followed by
sanitisation of whatever it produced.

This document describes the pipeline that is actually enforceable, and where
zipcheck fits.

---

## What zipcheck can and cannot guarantee

With static analysis only:

- ✅ recognises huge declared expansion, overlap/quine tricks, sparse TAR,
  entry-count bombs and shallow nesting;
- ❌ **cannot** detect a ZIP whose central directory says `1 byte` while its
  deflate stream expands to 10 GiB;
- ❌ cannot inspect AES/ZipCrypto payloads;
- ❌ cannot inspect 7z/RAR data without a decoder.

With `--verify`:

- ✅ decompresses supported content into a **counting sink** (no disk writes),
  stopping at `--verify-limit`;
- ✅ reports `METADATA_UNDERSTATED` if real output exceeds the declaration;
- ✅ reports `UNDERSTATED_COMPRESSED_SIZE` if a stream continues past its
  declared compressed size (a one-byte member hiding a large stream);
- ✅ recursively captures and verifies nested archives up to 8 MiB per member,
  with a shared 256 MiB nested-output budget;
- ✅ reports `VERIFICATION_LIMIT` when the cap is reached;
- ✅ feeds the measured output into the same expansion policy;
- ❌ still cannot decode 7z, RAR, Zstandard or encrypted members;
- ❌ does not fully verify nested members larger than the capture cap (they are
  probed and marked unverified);
- ❌ still consumes CPU up to the timeout and output cap;
- ❌ still has parser/decompressor attack surface.

With `--require-verified`:

- ✅ adds `UNVERIFIED` to every result that verification could not fully cover;
- ✅ any archive that cannot be content-verified becomes `unknown` (exit `3`),
  unless static analysis already found a `HIGH`/`CRITICAL` issue;
- ❌ does not make the scanner a sandbox.

For a production upload pipeline, use the fail-closed preset:

```bash
zipcheck --production \
         --verify-limit 256MiB \
         --timeout 30 \
         --json \
         /quarantine/upload.bin
```

(`--production` is exactly `--verify --require-verified`.)

Even when an archive verifies, the statically parsable structure is still
checked: contradictory local/central headers (`HEADER_MISMATCH`) and entries
hidden from the EOCD count (`ENTRY_COUNT_MISMATCH`) are HIGH findings.

Run that process **outside** your web/API process, as an unprivileged user with
a clock limit, and treat exit code `0` only as permission to proceed to
sandboxed extraction — never as permission to hand the file to a privileged
service.

---

## Reference pipeline

```
 upload ──► ingress limits ──► static+verified scan ──► quarantine queue
                               (unprivileged, capped)          │
                                                               ▼
                                              disposable extraction worker
                                              (no network, cgroups, tmpfs)
                                                               │
                                                               ▼
                                              output validation + sanitisation
                                                               │
                                                               ▼
                                                   serve / store safe result
```

### 1. Ingress

- Enforce a maximum upload size before reading the whole body.
- Sniff the format yourself; do not trust `Content-Type` or the extension.
- Allowlist only the formats your product actually needs. Every extra format is
  another parser and another attack surface.
- Reject encrypted archives unless the product has a deliberate flow for them.
- Rate-limit per account/IP and put uploads on a queue.

### 2. Pre-flight scan

Run zipcheck in a separate process, low-privilege user, no network, with a hard
timeout. Suggested thresholds:

| Setting | Suggested |
|---|---|
| `--verify-limit` | 128–512 MiB, based on the maximum output you are willing to accept |
| `--timeout` | 10–60 s |
| `--depth` | 4–6 |
| `--fail-on` | `suspicious` |
| `--production` | on for user uploads (verify + reject unverifiable) |

Exit codes:

| Code | Action |
|---|---|
| `0` | proceed to sandboxed extraction |
| `1` | reject or hold for review |
| `2` | reject |
| `3` | reject or hold (could not verify) |
| `4` | reject (I/O or invocation problem) |

JSON output includes `verified`, `verified_uncompressed`,
`verification_capped`, `verification_detail` and `nested_unverified` so the
decision is auditable.

### 3. Quarantine

- Copy the bytes to storage the web process cannot execute.
- Never let the scanner or extractor see credentials, sockets, or the host
  filesystem.
- Queue jobs with per-tenant quotas; enforce a maximum queue depth.

### 4. Sandboxed extraction (the actual boundary)

Use a disposable container/microVM per job. Minimum controls:

```bash
docker run --rm \
  --network none \
  --read-only \
  --tmpfs /work:rw,noexec,nosuid,size=512m,nr_inodes=20000 \
  --memory 512m --memory-swap 512m \
  --cpus 0.5 \
  --pids-limit 64 \
  --ulimit fsize=524288:524288 \
  --ulimit nofile=256:256 \
  --user 65534:65534 \
  -v "$PWD/upload:/in:ro" \
  extractor-image \
  /in/upload.bin /work/out
```

Then:

- run with a wall-clock timeout and kill the whole container/VM on expiry;
- make `/work` a quota-limited tmpfs or a dedicated volume with `size=`;
- restrict syscalls (seccomp profile), use gVisor/Firecracker for stronger
  isolation;
- never mount the Docker socket, SSH keys, cloud metadata credentials, or the
  application database;
- limit inodes as well as bytes (`nr_inodes` or filesystem project quotas).

**Do not** call `unzip`, `7z`, `tar` or `rar` as root, and do not use a single
long-lived worker process to extract many tenants' files.

### 5. Output validation and sanitisation

After extraction, before anything reads the files:

- count total bytes and inodes; compare against the quota and expected values;
- reject absolute paths, `..`, NUL bytes and Windows reserved names;
- reject symlinks, hardlinks, device nodes, FIFOs and setuid/setgid bits
  (or strip them);
- reject duplicate/case-colliding names if your storage is case-insensitive;
- limit filename length and component count;
- scan or re-encode documents/images rather than serving raw extracted files;
- delete the worker and its disk after the job.

`zipcheck` flags `UNSAFE_PATH` for `..`/absolute names, but path sanitisation is
the extractor's job. A scanner finding is not a substitute.

### 6. Failure handling

Fail closed:

- scanner crash, timeout, unparseable output → reject/hold;
- verification cap reached → reject;
- unsupported format/encryption when `--require-verified` → reject/hold;
- worker killed by OOM/CPU/disk quota → reject, alert;
- output larger than expected → reject.

Monitor `unknown` rates, cap hits, worker kills, extraction bytes/inodes and
p99 scan durations. A sudden increase in `unknown` is a signal, not noise.

---

## Format-specific notes

| Format | Static | `--verify` | Production note |
|---|---|---|---|
| ZIP/ZIP64 | yes | deflate, stored, bzip2, lzma + nested images (≤8 MiB) | reject AES/ZipCrypto unless decrypted in worker |
| TAR | yes | declared plan + nested members (≤8 MiB) | sparse holes need filesystem quota; reject devices/symlinks |
| gzip | yes | all members + nested images (≤8 MiB) | multi-member legal, but `METADATA_UNDERSTATED` marks it unverified |
| bzip2 | probe | yes | exact size measured |
| xz/LZMA | yes | first stream | concatenated streams are not fully verified |
| Zstandard | header | no | requires `--require-verified` rejection or an external decoder |
| 7-Zip | header | no | extract only in a sandbox with libarchive/7z; encrypted headers unknown |
| RAR 4/5 | header | no | same; reject multi-volume unless explicitly supported |

If you accept 7z or RAR, add a sandboxed decoder step and re-check the actual
bytes produced. Static header sizes are not enough.

---

## What "production ready" means here

zipcheck is production-ready as:

- a fast rejection gate for obvious bombs;
- a metadata auditor for ZIP/TAR/gzip/bzip2/xz;
- a bounded verifier for forged ZIP/gzip metadata within the supported methods,
  including recursively nested archives under the capture cap;
- a source of machine-readable evidence for your decision log.

It is **not** production-ready as:

- the only check before calling an extractor in your web process;
- a substitute for cgroups, seccomp, read-only filesystems, quotas and
  timeouts;
- a guarantee against a determined attacker with a decoder zero-day.

If the product promise is "we safely accept arbitrary archives", budget for an
isolated extraction service. That service is the security boundary; zipcheck
is the smoke detector in front of it.
