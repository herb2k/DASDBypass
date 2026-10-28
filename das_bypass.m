#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>

static id Swizzled_PolicyResponse(id self, SEL _cmd, id activities, id state) {
    return nil; // Satisfies the unrestricted policy pointer requirement
}

__attribute__((constructor))
static void init_bypass(void) {
    @autoreleasepool {
        NSLog(@"[+] DAS Bypass Dylib Loaded into process %d", getpid());
        
        // Force-load the private DuetActivityScheduler library where the policy classes live
        // This ensures the ObjC runtime registers the classes before we search for them
        void *duetHandle = dlopen("/System/Library/PrivateFrameworks/DuetActivityScheduler.framework/DuetActivityScheduler", RTLD_NOW);
        if (!duetHandle) {
            NSLog(@"[-] DAS Bypass: Failed to dlopen DuetActivityScheduler framework: %s", dlerror());
        }

        Class fpPolicy = objc_getClass("_DASFileProtectionPolicy");
        
        // Fallback: If it's still missing, try a broad loop lookup across all loaded classes
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
