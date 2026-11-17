#import <Foundation/Foundation.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import <CoreFoundation/CoreFoundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#include <libgen.h>
#include <mach-o/dyld.h>

/*
 * das_bypass_v4.m - "unlock-once-per-boot" replacement for das_bypass.m
 *
 * v3 tried to detect real lock state via CGSessionCopyCurrentDictionary()
 * and the "com.apple.screenIsUnlocked" distributed notification. Confirmed
 * live (via debug logging inside dasd itself): CGSessionCopyCurrentDictionary()
 * returns NULL every single time when called from WITHIN dasd's actual
 * sandboxed process context (it worked fine from a plain standalone root
 * binary - the restriction is specific to dasd's sandbox, which blocks the
 * WindowServer-mediated session query). The distributed notification never
 * arrived either, for the same underlying reason.
 *
 * This version uses SCDynamicStoreCopyConsoleUser() (SystemConfiguration.
 * framework) instead - a lower-level, non-WindowServer-mediated API
 * commonly usable from daemons/sandboxed processes, which reports who (if
 * anyone) is logged in at the console. Critically, it stays non-NULL
 * through later screen locks (only clears on logout, not on lock) - which
 * is actually a MORE precise match for Class C's real "unlocks at first
 * authentication after boot, stays unlocked until reboot" semantics than
 * screen-lock state ever was, since we only need "has anyone authenticated
 * since boot", not live lock state.
 *
 * Behavior:
 *   - On load, and on every responseForActivity:withState: call (which
 *     fires very frequently - confirmed thousands of times per minute live)
 *     until latched: checks SCDynamicStoreCopyConsoleUser(). If it returns a
 *     real (non-NULL, non-root) username, latches "unlocked" permanently for
 *     the rest of this dasd process's life (in practice, for the rest of
 *     this boot).
 *   - Once latched: always returns nil (matches real Class C staying
 *     unlocked regardless of later screen locks).
 *   - Before first login (e.g. briefly sitting at the login window on a
 *     fresh boot): falls through to Apple's real original implementation,
 *     matching genuine pre-first-authentication behavior.
 *
 * Only responseForActivity:withState: is patched - confirmed via raw
 * class_getInstanceMethod tracing to be the only one of the three original
 * selectors that actually exists on this macOS build.
 *
 * Build/install: identical to das_bypass.m (see README.md), just compile
 * this file instead:
 *
 *   sudo mkdir -p /usr/local/lib
 *   clang -dynamiclib -framework Foundation -framework SystemConfiguration \
 *       das_bypass_v4.m -o /usr/local/lib/das_bypass.dylib
 *   codesign -s - --force /usr/local/lib/das_bypass.dylib
 *   sudo launchctl setenv DYLD_INSERT_LIBRARIES /usr/local/lib/das_bypass.dylib
 *   sudo launchctl kickstart -k system/com.apple.dasd
 *
 * (local.dasdbypass.plist needs no changes - it just re-applies whatever
 * dylib sits at that path on every boot.)
 */

typedef id (*ResponseForActivityIMP)(id self, SEL _cmd, id activity, id state);
static ResponseForActivityIMP original_responseForActivity = NULL;

static volatile BOOL hasUnlockedSinceBoot = NO;
static int debugLogCallsRemaining = 5; // log the first few checks verbosely to diagnose

static BOOL IsConsoleUserLoggedIn(void) {
    BOOL shouldLog = debugLogCallsRemaining > 0;
    if (shouldLog) debugLogCallsRemaining--;

    uid_t uid = (uid_t)-1;
    gid_t gid = (gid_t)-1;
    CFStringRef consoleUser = SCDynamicStoreCopyConsoleUser(NULL, &uid, &gid);

    if (!consoleUser) {
        if (shouldLog) NSLog(@"[DEBUG] DAS Bypass v4: SCDynamicStoreCopyConsoleUser() returned NULL (nobody logged in at console yet).");
        return NO;
    }

    NSString *username = (__bridge NSString *)consoleUser;
    BOOL loggedIn = (uid != (uid_t)-1 && uid != 0 && ![username isEqualToString:@"loginwindow"]);
    if (shouldLog) {
        NSLog(@"[DEBUG] DAS Bypass v4: console user = %@ (uid=%d) -> loggedIn=%d", username, uid, loggedIn);
    }
    CFRelease(consoleUser);
    return loggedIn;
}

static id Patched_ResponseForActivity(id self, SEL _cmd, id activity, id state) {
    if (!hasUnlockedSinceBoot) {
        if (IsConsoleUserLoggedIn()) {
            hasUnlockedSinceBoot = YES;
            NSLog(@"[+] DAS Bypass v4: console user detected - latching permanently unlocked for the rest of this boot session.");
        }
    }

    if (hasUnlockedSinceBoot) {
        // Matches real Class C behavior: stays unlocked for the whole boot
        // session once the first authentication has happened, regardless
        // of later screen locks.
        return nil;
    }
    // Nobody has logged in at the console yet this boot (e.g. sitting at
    // the login window) - defer to Apple's real logic, which should
    // correctly keep Class C data (and gated sync activities) blocked
    // until first login.
    if (original_responseForActivity) {
        return original_responseForActivity(self, _cmd, activity, state);
    }
    return nil;
}

__attribute__((constructor))
static void init_bypass(void) {
    @autoreleasepool {
        // --- STRICT EXCLUSIVE PROCESS TARGET FILTER (unchanged from v1-v3) ---
        char path[PATH_MAX];
        uint32_t size = sizeof(path);
        if (_NSGetExecutablePath(path, &size) == 0) {
            char *base = basename(path);
            if (strcmp(base, "dasd") != 0) {
                return;
            }
        } else {
            return;
        }
        // ----------------------------------------------

        NSLog(@"[+] DAS Bypass v4 (unlock-once-per-boot, SCDynamicStore-based) Dylib Loaded into process %d", getpid());

        if (IsConsoleUserLoggedIn()) {
            hasUnlockedSinceBoot = YES;
            NSLog(@"[+] DAS Bypass v4: console user already logged in at load time - latching immediately.");
        } else {
            NSLog(@"[*] DAS Bypass v4: nobody logged in at console at load time - will keep checking on every scoring pass.");
        }

        void *duetHandle = dlopen("/System/Library/PrivateFrameworks/DuetActivityScheduler.framework/DuetActivityScheduler", RTLD_NOW);
        if (!duetHandle) {
            NSLog(@"[-] DAS Bypass v4: Failed to dlopen DuetActivityScheduler framework: %s", dlerror());
        }

        Class fpPolicy = objc_getClass("_DASFileProtectionPolicy");

        if (!fpPolicy) {
            int numClasses = objc_getClassList(NULL, 0);
            if (numClasses > 0) {
                Class *classes = (__typeof__(classes))malloc(sizeof(Class) * numClasses);
                numClasses = objc_getClassList(classes, numClasses);
                for (int i = 0; i < numClasses; i++) {
                    const char *className = class_getName(classes[i]);
                    if (strstr(className, "FileProtection") != NULL) {
                        fpPolicy = classes[i];
                        NSLog(@"[+] DAS Bypass v4: Dynamically located variant policy class: %s", className);
                        break;
                    }
                }
                free(classes);
            }
        }

        if (!fpPolicy) {
            NSLog(@"[-] DAS Bypass v4: Critical - No valid FileProtection policy classes could be resolved.");
            return;
        }

        SEL sel = sel_registerName("responseForActivity:withState:");
        Method originalMethod = class_getInstanceMethod(fpPolicy, sel);
        if (originalMethod) {
            original_responseForActivity = (ResponseForActivityIMP)method_getImplementation(originalMethod);
            method_setImplementation(originalMethod, (IMP)Patched_ResponseForActivity);
            NSLog(@"[+] DAS Bypass v4: Patched responseForActivity:withState: on %s (original IMP saved @ %p)", class_getName(fpPolicy), original_responseForActivity);
        } else {
            NSLog(@"[-] DAS Bypass v4: responseForActivity:withState: not found on %s - nothing patched.", class_getName(fpPolicy));
        }

        // scoreActivities:withState: / shouldScavengeActivities:withState:
        // confirmed (via raw class_getInstanceMethod tracing) not to exist
        // on this macOS build's _DASFileProtectionPolicy - intentionally
        // not referenced.
    }
}
