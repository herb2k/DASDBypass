## Root Cause: Why `classCLocked` Never Unlocks on T1 Macs (Tahoe + OCLP)

### Symptom

`dasd` repeatedly logs:

```
{name: File Protection Policy, policyWeight: 0.010, response: {100, 0.00, [{classCLocked == 1 AND activityFileProtection == ClassC}]}}
], Decision: AMNP}
```

`classCLocked` stays `1` permanently, blocking `cloudphotod`/`photoanalysisd` maintenance activities — iCloud Photos, Messages, and Maps never sync in the background.

### Root cause

1. `classCLocked` corresponds to Apple's **Class C** data-protection tier (`NSFileProtectionCompleteUntilFirstUserAuthentication`). Per Apple's own documentation, Class C data unlocks once at first successful authentication after boot and stays unlocked for the rest of that boot session, regardless of later screen locks — it only re-locks on reboot. Modern Tahoe expects a Secure-Enclave-class backend to answer this check at all.

2. OCLP's T1 support kit — `AppleKeyStore-Tahoe.kext`, `AppleSSE.kext`, `AppleCredentialManager.kext`, `corecrypto_T1.kext`, `KernelRelayHost.kext` — **fully replaces** Tahoe's native `AppleKeyStore`/`AppleSSE`/`AppleCredentialManager` kexts via `Add` + `Block` pairs in `config.plist` (same bundle IDs, mutually exclusive — not supplementary). Disabling these entries (see [BridgePatcher#605](https://github.com/bridgepatcher/BridgePatcher/issues/605)) lets Tahoe's real kexts load instead: background sync works again, but Touch ID breaks (no SSE/CredentialManager backend left for biometrics).

3. **`AppleKeyStore-Tahoe.kext` is actually a Ventura-era (macOS 13) binary**, not Tahoe-native. Confirmed by diffing it against the genuine stock Tahoe kext, which is still present untouched at `/System/Library/Extensions/AppleKeyStore.kext` (different hash, size, and a real Apple signature chain — it's simply inert because OCLP's `Block` directive prevents it from loading):
   - Stock Tahoe imports post-quantum cryptographic primitives (`_cckem_mlkem768/1024`, `_cckem_kyber768/1024`, `_ccmldsa65/87`, SIV-mode AEAD `_ccsiv_*`/`_ccaes_siv_*`, blob-style DER encoding `_ccder_blob_*`, plus `_CTEvaluateBAA`/`_CTParseCertificateSet` attestation calls) — all part of Apple's PQ3/Advanced Data Protection key-wrapping rollout (~2024+).
   - OCLP's kext imports only older-generation primitives (`_ccgcm_*` plain GCM, non-blob `_ccder_decode_*`/`_ccder_encode_*`, a different `CTEvaluateBAA*` call shape) with **zero** post-quantum symbols — exactly what a 2022 Ventura binary would contain.
   - OCLP's kext also directly imports `KernelRelay`/`KernelRelayEndpoint` classes at the binary level, confirming it's wired through OCLP's custom relay bridge to the T1 chip rather than whatever transport the native kext uses.

4. The T1 chip (Touch ID/Touch Bar controller) was **never** a Secure Enclave for file-system Data Protection, even on its original native macOS — it only ever handled Touch ID, Apple Pay, and Secure Boot. FileVault on T1 Macs has always been software-only encryption. Tahoe now structurally requires *some* SEP-class answer for Class C, which T1 was never built to provide, and OCLP's Ventura-sourced substitute speaks an older key-wrapping protocol generation than the rest of Tahoe expects.

**Net effect:** this is not a patchable bug in the usual sense — it's a genuine cross-OS-generation protocol mismatch (a 2022 kext inside a 2025+ system expecting a newer cryptographic handshake), compounded by T1 hardware that never supported this function at all. Live `dtrace` tracing confirmed the real kernel query (`IOConnectCallMethod`, selector `0x23`, handle `-501`) consistently returns `kIOReturnBadArgument` (`0xe00002c2`), is evaluated once per `dasd` process lifetime (not re-checked per scoring pass), and is then cached — permanently wrong — for the life of that process.

### Dead ends ruled out

- FileVault on/off — no effect, tested cleanly with the kernel patch applied.
- Restarting `dasd` alone — re-evaluates and fails identically every time.
- `_DASFileProtectionPolicy`'s `scoreActivities:withState:` / `shouldScavengeActivities:withState:` — confirmed via raw `class_getInstanceMethod` tracing to not exist at all on this macOS build. Only `responseForActivity:withState:` is real.
- Live screen-lock-state gating via `CGSessionCopyCurrentDictionary()` — returns `NULL` when called from inside `dasd`'s actual sandbox, despite working correctly from a plain root binary.
- `com.apple.screenIsUnlocked` distributed notification — never received inside `dasd`'s sandbox, for the same underlying reason.

### Kernel patches applied to `AppleKeyStore-Tahoe.kext` (`patch_applekeystore.py`)

- **Patch #1:** added a missing selector allow-list entry (`0x07`/`0x11`/`0x23`) for handle `-6` (session keybag), bypassing an entitlement check gap. Fixed the original `-17` (`4294967279`) error.
- **Patch #2:** added a missing `err_sks_to_aks()` translation call for the handle `-3` branch. Confirmed applied via checksum, but later proven unrelated to the persistent `classCLocked`/`-8` symptom.

### Working fix: `das_bypass_v4.m`

A drop-in replacement for the original `das_bypass.m`, installed the same way (same `DYLD_INSERT_LIBRARIES` + `local.dasdbypass.plist` mechanism — no plist changes needed):

- Patches only `responseForActivity:withState:` — the one selector confirmed to actually exist on this build — instead of blanket-swizzling three methods, two of which don't exist.
- Uses `SCDynamicStoreCopyConsoleUser()` (SystemConfiguration.framework) — the one lower-level API confirmed to actually work from `dasd`'s sandboxed context — to detect "has a console user logged in since boot."
- Latches permanently unlocked the first time that's true (checked on load, and as a live fallback on every scoring call until latched), and stays latched for the rest of that `dasd` process's life.
- This matches real Class C semantics precisely: unlocks at first authentication, stays unlocked through later screen locks, resets only on reboot — rather than v1's blanket "always unrestricted," which would have masked all Class-C gating permanently rather than reproducing real behavior.
- Confirmed working live: loads, patches, latches correctly on console-user detection, and sync survives a full lock/unlock cycle without re-blocking.

### Bottom line

Given the depth of the underlying kernel/kext version mismatch (bridging two generations of Apple's SEP key-wrapping protocol with no source access isn't a reasonable binary-patching target), the userspace fix in `das_bypass_v4.m` is the correct and sufficient solution — it reproduces the intended observable behavior without requiring the underlying kernel subsystem to actually work.

### Further Analysis of the MobileKeyBag:

`MKBDeviceUnlockedSinceBoot()` → 1 — the device has been authenticated at least once this boot (true, correctly).
`MKBUserUnlockedSinceBoot(uid=501)` → 0 — your user’s class-key unlock state is still false, even though you’re logged in and have unlocked the screen multiple times.

That split is exactly the fault line. The device-level flag is presumably set early/cheaply (just “someone passed the login screen”), but the per-user flag is almost certainly what actually gates Class C (classCLocked) — and setting it to true requires committing the user’s class keys as unlocked, which means re-wrapping them through the SEP. That’s the step that structurally doesn’t exist in a working form on T1-only hardware (consistent with everything the kext disassembly showed: no software fallback for the no-SEP case). So MKB correctly knows the device unlocked, but can never correctly mark your Class C keys as unlocked, because that specific operation has nowhere to go.
