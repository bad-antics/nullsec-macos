/*
 * ═══════════════════════════════════════════════════════════════════
 *  NULLSEC macOS Endpoint Security Monitor
 *  Real-time security event monitoring using Endpoint Security framework
 *  @author bad-antics | x.com/AnonAntics
 * ═══════════════════════════════════════════════════════════════════
 *
 *  Compile: clang -framework Foundation -framework EndpointSecurity \
 *           -o es_monitor es_monitor.m
 *  Run: sudo ./es_monitor
 */

#import <Foundation/Foundation.h>
#import <EndpointSecurity/EndpointSecurity.h>
#import <bsm/libbsm.h>

#define VERSION "2.0.0"
#define AUTHOR "bad-antics"
#define DISCORD "x.com/AnonAntics"

static const char* BANNER = 
"╭──────────────────────────────────────────╮\n"
"│    🍎 NULLSEC macOS ES MONITOR          │\n"
"│    ═══════════════════════════════════  │\n"
"│                                          │\n"
"│   🔍 Endpoint Security Monitoring        │\n"
"│   📊 Process & File Events               │\n"
"│   🛡️  Real-time Threat Detection          │\n"
"│                                          │\n"
"│          bad-antics | NullSec            │\n"
"╰──────────────────────────────────────────╯\n";

// ═══════════════════════════════════════════════════════════════════
// License Management
// ═══════════════════════════════════════════════════════════════════

typedef enum {
    LicenseTierFree = 0,
    LicenseTierPremium = 1,
    LicenseTierEnterprise = 2
} LicenseTier;

typedef struct {
    char key[25];
    LicenseTier tier;
    bool valid;
} License;

License currentLicense = { "", LicenseTierFree, false };

bool validateLicense(const char* key) {
    if (!key || strlen(key) != 24) return false;
    if (strncmp(key, "NMAC-", 5) != 0) return false;
    
    strncpy(currentLicense.key, key, 24);
    currentLicense.key[24] = '\0';
    currentLicense.valid = true;
    
    char typeCode[3] = { key[5], key[6], '\0' };
    if (strcmp(typeCode, "PR") == 0) {
        currentLicense.tier = LicenseTierPremium;
    } else if (strcmp(typeCode, "EN") == 0) {
        currentLicense.tier = LicenseTierEnterprise;
    } else {
        currentLicense.tier = LicenseTierFree;
    }
    
    return true;
}

bool isPremium(void) {
    return currentLicense.valid && currentLicense.tier != LicenseTierFree;
}

const char* getTierName(void) {
    switch (currentLicense.tier) {
        case LicenseTierPremium: return "Premium ⭐";
        case LicenseTierEnterprise: return "Enterprise 💎";
        default: return "Free";
    }
}

// ═══════════════════════════════════════════════════════════════════
// Logging
// ═══════════════════════════════════════════════════════════════════

void logSuccess(const char* msg) {
    printf("\033[32m✅ %s\033[0m\n", msg);
}

void logError(const char* msg) {
    printf("\033[31m❌ %s\033[0m\n", msg);
}

void logWarning(const char* msg) {
    printf("\033[33m⚠️  %s\033[0m\n", msg);
}

void logInfo(const char* msg) {
    printf("\033[36mℹ️  %s\033[0m\n", msg);
}

void logEvent(const char* type, const char* msg) {
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    char timeStr[26];
    strftime(timeStr, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    
    printf("[%s] \033[35m[%s]\033[0m %s\n", timeStr, type, msg);
}

// ═══════════════════════════════════════════════════════════════════
// Endpoint Security Client
// ═══════════════════════════════════════════════════════════════════

static es_client_t* g_client = NULL;
static bool g_running = true;

// Get process path from es_process_t
NSString* getProcessPath(const es_process_t* process) {
    if (process && process->executable && process->executable->path.data) {
        return [NSString stringWithUTF8String:process->executable->path.data];
    }
    return @"unknown";
}

// Get process name from es_process_t
NSString* getProcessName(const es_process_t* process) {
    NSString* path = getProcessPath(process);
    return [path lastPathComponent];
}

// Handle EXEC events
void handleExec(const es_message_t* msg) {
    const es_process_t* proc = msg->process;
    const es_event_exec_t* exec = &msg->event.exec;
    
    NSString* parentName = getProcessName(proc);
    NSString* childPath = @"unknown";
    
    if (exec->target && exec->target->executable) {
        childPath = [NSString stringWithUTF8String:exec->target->executable->path.data];
    }
    
    // Check for suspicious executions
    NSArray* suspicious = @[
        @"/bin/sh", @"/bin/bash", @"/usr/bin/python",
        @"/usr/bin/osascript", @"/usr/bin/curl", @"/usr/bin/wget"
    ];
    
    BOOL isSuspicious = NO;
    for (NSString* susp in suspicious) {
        if ([childPath containsString:susp]) {
            isSuspicious = YES;
            break;
        }
    }
    
    if (isSuspicious) {
        NSString* eventMsg = [NSString stringWithFormat:@"⚠️ %@ spawned %@ (PID: %d)",
                             parentName, [childPath lastPathComponent], 
                             audit_token_to_pid(proc->audit_token)];
        logEvent("EXEC", [eventMsg UTF8String]);
    } else {
        NSString* eventMsg = [NSString stringWithFormat:@"%@ → %@",
                             parentName, [childPath lastPathComponent]];
        logEvent("EXEC", [eventMsg UTF8String]);
    }
}

// Handle OPEN events
void handleOpen(const es_message_t* msg) {
    const es_process_t* proc = msg->process;
    const es_event_open_t* open = &msg->event.open;
    
    if (!open->file || !open->file->path.data) return;
    
    NSString* filePath = [NSString stringWithUTF8String:open->file->path.data];
    NSString* procName = getProcessName(proc);
    
    // Monitor sensitive locations
    NSArray* sensitiveLocations = @[
        @"/etc/passwd", @"/etc/shadow", @"/etc/sudoers",
        @"/var/db/dslocal", @"Keychain", @".ssh/",
        @"Library/Keychains", @"Login Data", @"Cookies"
    ];
    
    for (NSString* loc in sensitiveLocations) {
        if ([filePath containsString:loc]) {
            NSString* eventMsg = [NSString stringWithFormat:@"🔴 %@ accessed %@",
                                 procName, filePath];
            logEvent("OPEN", [eventMsg UTF8String]);
            return;
        }
    }
    
    // Only log if premium (too noisy otherwise)
    if (isPremium()) {
        NSString* eventMsg = [NSString stringWithFormat:@"%@ opened %@",
                             procName, [filePath lastPathComponent]];
        logEvent("OPEN", [eventMsg UTF8String]);
    }
}

// Handle KEXTLOAD events
void handleKextLoad(const es_message_t* msg) {
    const es_event_kextload_t* kext = &msg->event.kextload;
    
    if (kext->identifier.data) {
        NSString* eventMsg = [NSString stringWithFormat:@"🟠 Kernel extension: %s",
                             kext->identifier.data];
        logEvent("KEXT", [eventMsg UTF8String]);
    }
}

// Handle MMAP events (code injection detection)
void handleMmap(const es_message_t* msg) {
    if (!isPremium()) return;  // Premium feature
    
    const es_process_t* proc = msg->process;
    const es_event_mmap_t* mmap = &msg->event.mmap;
    
    // Check for executable anonymous mappings
    if ((mmap->protection & PROT_EXEC) && (mmap->protection & PROT_WRITE)) {
        NSString* procName = getProcessName(proc);
        NSString* eventMsg = [NSString stringWithFormat:@"⚠️ RWX mapping by %@ (potential injection)",
                             procName];
        logEvent("MMAP", [eventMsg UTF8String]);
    }
}

// Handle SIGNAL events
void handleSignal(const es_message_t* msg) {
    if (!isPremium()) return;  // Premium feature
    
    const es_process_t* proc = msg->process;
    const es_event_signal_t* signal = &msg->event.signal;
    
    int sig = signal->sig;
    
    // Monitor suspicious signals
    if (sig == SIGKILL || sig == SIGSTOP || sig == SIGCONT) {
        NSString* procName = getProcessName(proc);
        pid_t targetPid = audit_token_to_pid(signal->target->audit_token);
        
        NSString* eventMsg = [NSString stringWithFormat:@"%@ sent signal %d to PID %d",
                             procName, sig, targetPid];
        logEvent("SIGNAL", [eventMsg UTF8String]);
    }
}

// Main event handler
void handleEvent(es_client_t* client, const es_message_t* msg) {
    switch (msg->event_type) {
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            handleExec(msg);
            break;
            
        case ES_EVENT_TYPE_NOTIFY_OPEN:
            handleOpen(msg);
            break;
            
        case ES_EVENT_TYPE_NOTIFY_KEXTLOAD:
            handleKextLoad(msg);
            break;
            
        case ES_EVENT_TYPE_NOTIFY_MMAP:
            handleMmap(msg);
            break;
            
        case ES_EVENT_TYPE_NOTIFY_SIGNAL:
            handleSignal(msg);
            break;
            
        default:
            break;
    }
}

// Initialize Endpoint Security client
bool initESClient(void) {
    es_new_client_result_t result = es_new_client(&g_client, ^(es_client_t* client,
                                                               const es_message_t* msg) {
        handleEvent(client, msg);
    });
    
    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
        switch (result) {
            case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
                logError("Missing entitlement - run with sudo or sign with ES entitlement");
                break;
            case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
                logError("Not permitted - check System Preferences > Security & Privacy");
                break;
            case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
                logError("Not privileged - run as root");
                break;
            default:
                logError("Failed to create ES client");
                break;
        }
        return false;
    }
    
    return true;
}

// Subscribe to events
bool subscribeEvents(void) {
    es_event_type_t events[] = {
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_NOTIFY_OPEN,
        ES_EVENT_TYPE_NOTIFY_KEXTLOAD,
    };
    
    size_t eventCount = sizeof(events) / sizeof(events[0]);
    
    // Add premium events
    if (isPremium()) {
        es_event_type_t premiumEvents[] = {
            ES_EVENT_TYPE_NOTIFY_MMAP,
            ES_EVENT_TYPE_NOTIFY_SIGNAL,
        };
        
        // Combine arrays
        es_event_type_t allEvents[10];
        memcpy(allEvents, events, eventCount * sizeof(es_event_type_t));
        memcpy(allEvents + eventCount, premiumEvents, sizeof(premiumEvents));
        eventCount += sizeof(premiumEvents) / sizeof(es_event_type_t);
        
        es_return_t ret = es_subscribe(g_client, allEvents, (uint32_t)eventCount);
        if (ret != ES_RETURN_SUCCESS) {
            logError("Failed to subscribe to events");
            return false;
        }
    } else {
        es_return_t ret = es_subscribe(g_client, events, (uint32_t)eventCount);
        if (ret != ES_RETURN_SUCCESS) {
            logError("Failed to subscribe to events");
            return false;
        }
    }
    
    return true;
}

// Cleanup
void cleanup(void) {
    if (g_client) {
        es_unsubscribe_all(g_client);
        es_delete_client(g_client);
        g_client = NULL;
    }
}

// Signal handler
void signalHandler(int sig) {
    printf("\n");
    logInfo("Shutting down...");
    g_running = false;
}

// ═══════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════

int main(int argc, const char* argv[]) {
    @autoreleasepool {
        printf("\033[36m%s\033[0m", BANNER);
        printf("  Version %s | %s\n", VERSION, AUTHOR);
        printf("  🔑 Premium: %s\n\n", DISCORD);
        
        // Parse arguments
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
                if (validateLicense(argv[++i])) {
                    char msg[100];
                    snprintf(msg, sizeof(msg), "License activated: %s", getTierName());
                    logSuccess(msg);
                }
            } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                printf("Usage: %s [-k LICENSE_KEY]\n", argv[0]);
                printf("\nOptions:\n");
                printf("  -k KEY    License key for premium features\n");
                printf("  -h        Show this help\n");
                return 0;
            }
        }
        
        // Check if running as root
        if (geteuid() != 0) {
            logError("This tool requires root privileges. Run with sudo.");
            return 1;
        }
        
        // Initialize ES client
        logInfo("Initializing Endpoint Security client...");
        
        if (!initESClient()) {
            return 1;
        }
        
        logSuccess("ES client initialized");
        
        // Subscribe to events
        if (!subscribeEvents()) {
            cleanup();
            return 1;
        }
        
        char eventMsg[100];
        snprintf(eventMsg, sizeof(eventMsg), "Subscribed to events (%s)", getTierName());
        logSuccess(eventMsg);
        
        // Setup signal handler
        signal(SIGINT, signalHandler);
        signal(SIGTERM, signalHandler);
        
        printf("\n");
        printf("═══════════════════════════════════════════\n");
        printf("  📊 Monitoring system events...\n");
        printf("  Press Ctrl+C to stop\n");
        printf("═══════════════════════════════════════════\n\n");
        
        // Main loop
        while (g_running) {
            [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
        }
        
        // Cleanup
        cleanup();
        
        printf("\n─────────────────────────────────────────\n");
        printf("  🍎 NullSec macOS ES Monitor\n");
        printf("  🔑 Premium: %s\n", DISCORD);
        printf("  👤 Author: %s\n", AUTHOR);
        printf("─────────────────────────────────────────\n\n");
        
        return 0;
    }
}
