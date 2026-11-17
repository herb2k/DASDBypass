## Temporary workaround T1 OCLP 3.0.0 RC3/RC4 patched Macs running macOS Tahoe (26.7.1 or 26.7.2)

This .dylib bypasses the "classCLocked" File Protection Mechanism which prevents iCloud Photos, Messages, Maps from Synchronizing on patched Macs.

**Disclaimer:** This was created with the assistance of AI. *I am not a reverse engineer, and am not pretending to be one!* Test and apply at your own risk. 

I am not sure what other protections are reduced by applying this patch, however, from my research - the "classCLocked" data would be normally unlocked while logged into macOS and/or anytime FileVault is open (see *NSFileProtectionCompleteUntilFirstUserAuthentication*: https://support.apple.com/en-ca/guide/security/secb010e978a/web)

Symptom: dasd logs {name: File Protection Policy, ..., Decision: AMNP} with classCLocked == 1 permanently, blocking cloudphotod/photoanalysisd maintenance activities — iCloud Photos, Messages, and Maps never sync.

[Further Explanation of why this bypass is needed](https://github.com/herb2k/DASDBypass/blob/main/CLASSC_FINDINGS.md)

### Pre-requisites

Modify SIP to Allow Debugging (Reboot into Recovery Terminal)

       csrutil enable --without debug

Update: This may not be required after further testing. 

### Installation

1. Compile the .dylib

       sudo mkdir -p /usr/local/lib

       clang -dynamiclib -framework Foundation das_bypass.m -o /usr/local/lib/das_bypass.dylib

2. Locally Sign the .dylib

       codesign -s - --force /usr/local/lib/das_bypass.dylib
   
4. Install/Test the .dylib

       sudo launchctl setenv DYLD_INSERT_LIBRARIES /usr/local/lib/das_bypass.dylib

5. Restart dasd

       sudo launchctl kickstart -k system/com.apple.dasd


### Behaviour on Reboot
This will still need to be re-applied after rebooting. (Step 3 and 4).

A shortcut added to Login Items would make this work automatically. 

the sudoers file can be updated to bypass the password entry.

Update: @MW on the Discord created a LaunchDaemon .plist that re-applies the patch after a short delay on reboots.

Place local.dasdbypass.plist in the /Library/LaunchDaemons folder.


### V4 Build (Generated)

Further analysis has shown that the Root cause of classCLocked (Class C / NSFileProtectionCompleteUntilFirstUserAuthentication) structurally does not appear to be able to be resolved on this T1-only hardware (no SEP) (that is, without fully disabling the T1 patches), so Apple’s real check always reports “locked” — not an OCLP bug, confirmed via Apple’s own documentation and extensive live tracing.

V4 (final): patches only the one selector that’s real (responseForActivity:withState:), and only bypasses once SCDynamicStoreCopyConsoleUser() confirms a real console login has occurred since boot — latching permanently from that point, exactly mirroring genuine Class C semantics (unlocks at first auth, stays unlocked regardless of later screen locks, resets only on reboot).

V4 installs the same way as the original. 

If using the original, just build and re-sign this one, it should install to the same directory as the original.


#### V4 Build and Install Instructions
(Different Framework Target - SystemConfiguration)

       sudo clang -dynamiclib -framework Foundation -framework SystemConfiguration das_bypass_v4.m -o /usr/local/lib/das_bypass.dylib
       sudo codesign -s - --force /usr/local/lib/das_bypass.dylib
