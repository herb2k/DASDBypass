##Temporary workaround T1 OCLP 3.0.0 RC3/RC4 patched Macs running macOS Tahoe (26.7.1 or 26.7.2)

1. Compile the .dylib

       clang -dynamiclib -framework Foundation das_bypass.m -o /tmp/das_bypass.dylib

2. Sign the .dylib

       codesign -s - --force /tmp/das_bypass.dylib
3. Install the .dylib

       sudo launchctl setenv DYLD_INSERT_LIBRARIES /tmp/das_bypass.dylib
4. Restart dasd

       sudo launchctl kickstart -k system/com.apple.dasd
