#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#include <libgen.h>
#include <mach-o/dyld.h>

static id Swizzled_PolicyResponse(id self, SEL _cmd, id activities, id state) {
    return nil; // Satisfies the unrestricted policy pointer requirement
}

__attribute__((constructor))
static void init_bypass(void) {
    @autoreleasepool {
		// --- STRICT EXCLUSIVE PROCESS TARGET FILTER ---
        char path[PATH_MAX];
        uint32_t size = sizeof(path);
        if (_NSGetExecutablePath(path, &size) == 0) {
            char *base = basename(path);
            
            // If the current process is NOT dasd, exit immediately.
            // This completely isolates the dylib from all other system apps.
            if (strcmp(base, "dasd") != 0) {
                return; 
            }
        } else {
            return; // Fail-safe: exit if path cannot be read
        }
        // ----------------------------------------------

        NSLog(@"[+] DAS Bypass Dylib Loaded into process %d", getpid());
        
        // Force-load the private DuetActivityScheduler library where the policy classes live
        void *duetHandle = dlopen("/System/Library/PrivateFrameworks/DuetActivityScheduler.framework/DuetActivityScheduler", RTLD_NOW);
        if (!duetHandle) {
            NSLog(@"[-] DAS Bypass: Failed to dlopen DuetActivityScheduler framework: %s", dlerror());
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
                        NSLog(@"[+] DAS Bypass: Dynamically located variant policy class: %s", className);
                        break;
                    }
                }
                free(classes);
            }
        }

        if (!fpPolicy) {
            NSLog(@"[-] DAS Bypass: Critical - No valid FileProtection policy classes could be resolved.");
            return;
        }

        SEL selectors[] = {
            sel_registerName("scoreActivities:withState:"),
            sel_registerName("shouldScavengeActivities:withState:"),
            sel_registerName("responseForActivity:withState:")
        };

        for (int i = 0; i < 3; i++) {
            Method originalMethod = class_getInstanceMethod(fpPolicy, selectors[i]);
            if (originalMethod) {
                method_setImplementation(originalMethod, (IMP)Swizzled_PolicyResponse);
                NSLog(@"[+] DAS Bypass: Successfully swizzled selector: %s on class: %s", sel_getName(selectors[i]), class_getName(fpPolicy));
            }
        }
    }
}
