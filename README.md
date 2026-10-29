## Temporary workaround T1 OCLP 3.0.0 RC3/RC4 patched Macs running macOS Tahoe (26.7.1 or 26.7.2)

This .dylib bypasses the "classCLocked" File Protection Mechanism which prevents iCloud Photos, Messages, Maps from Synchronizing on patched Macs.

**Disclaimer:** This was created with the assistance of AI. *I am not a reverse engineer, and am not pretending to be one!* Test and apply at your own risk. 

I am not sure what other protections are reduced by applying this patch, however, from my research - the "classCLocked" data would be normally unlocked while logged into macOS and/or anytime FileVault is open (see *NSFileProtectionCompleteUntilFirstUserAuthentication*: https://support.apple.com/en-ca/guide/security/secb010e978a/web)

### Pre-requisites

Modify SIP to Allow Debugging (Reboot into Recovery Terminal)

       csrutil enable --without debug

### Installation

1. Compile the .dylib

              sudo mkdir -p /usr/local/lib

              clang -dynamiclib -framework Foundation das_bypass.m -o /usr/local/lib/das_bypass.dylib

2. Sign the .dylib

       codesign -s - --force /usr/local/lib/das_bypass.dylib
3. Install the .dylib

       sudo launchctl setenv DYLD_INSERT_LIBRARIES /usr/local/lib/das_bypass.dylib

4. Restart dasd

       sudo launchctl kickstart -k system/com.apple.dasd


### Behaviour on Reboot
This will still need to be re-applied after rebooting. (Step 3 and 4).

A shortcut added to Login Items would make this work automatically. 

the sudoers file can be updated to bypass the password entry.
