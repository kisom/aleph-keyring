# Hardware test log

Results of the manual checks in [testing.md](testing.md), newest first.
Each release's notes summarize the entries since the previous release.

## 2026-09-26, commit 080466d (Plan 2)

Host: Omarchy (Arch), kernel 7.2.5-3-omarchy, libfido2 1.17, tpm2-tss 4.2.

### FIDO2: YubiKey 5 (firmware 5.7.4)

The key reports `FIDO_2_0`, `FIDO_2_1_PRE` and `FIDO_2_1`, supports
`hmac-secret` and `credProtect`, has a client PIN, and has no built-in UV.

| Step | Result |
|---|---|
| 1–2. Enroll with the PIN, then unlock (`fido2_hardware`) | Pass: six touches, 9.8 s |
| CTAP 2.1 check: the secret without UV differs from the secret with it | Pass: the key was accepted, and the test's with-PIN versus touch-only comparison differed |
| 3. A second key makes enrollment refuse | Not run: only one key was available |
| 4. A wrong PIN gives `Fido2PinInvalid` and costs one retry | Pass: retries went 8 → 7, and the next correct PIN restored 8 |

### Real TPM (`tpm_hardware`, run through `newgrp tss`)

| Step | Result |
|---|---|
| 1. Status, then one seal and one unseal | Pass, 0.62 s |

`Status` reported:

| Field | Value |
|---|---|
| `parent` | `AlephPrimary` |
| `owner_auth_set` | false |
| `lockout_auth_set` | false |
| `in_lockout` | false |
| `max_tries` | 32 |
| `recovery_time` | 7200 s |
| `lockout_recovery` | 86400 s |
| `failed_tries` | 0 |

What these values imply for later plans:

- The per-uid window is 2 × 7200 s, so two failed unseals lock that user
  out of TPM unlock for up to 4 hours. Plan 3/4 therefore checks a typed
  password with PAM before it reaches the TPM, so typos never count
  against the TPM's budget, and shows a retry-after time in the prompter.
- `lockoutAuth` is empty, the Linux default. `aleph setup` (Plan 4)
  explains the consequence (spec §2) and offers to set it.
