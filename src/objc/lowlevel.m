// NullSec macOS - Objective-C Low-Level Tools
// Direct access to macOS internals
// @author bad-antics
// @discord x.com/AnonAntics

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import <IOKit/IOKitLib.h>
#import <DiskArbitration/DiskArbitration.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <sys/sysctl.h>
#import <pwd.h>

#define VERSION @"2.0.0"
#define AUTHOR @"bad-antics"
#define DISCORD @"x.com/AnonAntics"

#pragma mark - License Management

typedef NS_ENUM(NSInteger, LicenseTier) {
    LicenseTierFree = 0,
    LicenseTierPremium = 1,
    LicenseTierEnterprise = 2
};

@interface License : NSObject
@property (nonatomic, copy) NSString *key;
@property (nonatomic, assign) LicenseTier tier;
@property (nonatomic, assign) BOOL valid;
- (instancetype)initWithKey:(NSString *)key;
- (BOOL)isPremium;
@end

@implementation License

- (instancetype)initWithKey:(NSString *)key {
    self = [super init];
    if (self) {
        _key = key ?: @"";
        _tier = LicenseTierFree;
        _valid = NO;
        [self validate];
    }
    return self;
}

- (void)validate {
    if (self.key.length != 24 || ![self.key hasPrefix:@"NMAC-"]) {
        self.tier = LicenseTierFree;
        self.valid = NO;
        return;
    }
    
    NSArray *parts = [self.key componentsSeparatedByString:@"-"];
    if (parts.count != 5) {
        self.tier = LicenseTierFree;
        self.valid = NO;
        return;
    }
    
    NSString *tierCode = [parts[1] substringToIndex:MIN(2, [parts[1] length])];
    if ([tierCode isEqualToString:@"PR"]) {
        self.tier = LicenseTierPremium;
    } else if ([tierCode isEqualToString:@"EN"]) {
        self.tier = LicenseTierEnterprise;
    } else {
        self.tier = LicenseTierFree;
    }
    self.valid = YES;
}

- (BOOL)isPremium {
    return self.valid && self.tier != LicenseTierFree;
}

@end

#pragma mark - Console Colors

@interface Console : NSObject
+ (void)success:(NSString *)message;
+ (void)error:(NSString *)message;
+ (void)warning:(NSString *)message;
+ (void)info:(NSString *)message;
@end

@implementation Console

+ (void)success:(NSString *)message {
    printf("\033[32m✅ %s\033[0m\n", [message UTF8String]);
}

+ (void)error:(NSString *)message {
    printf("\033[31m❌ %s\033[0m\n", [message UTF8String]);
}

+ (void)warning:(NSString *)message {
    printf("\033[33m⚠️  %s\033[0m\n", [message UTF8String]);
}

+ (void)info:(NSString *)message {
    printf("\033[34mℹ️  %s\033[0m\n", [message UTF8String]);
}

@end

#pragma mark - Process Inspector

@interface ProcessInspector : NSObject
@property (nonatomic, strong) License *license;
- (instancetype)initWithLicense:(License *)license;
- (NSArray *)getAllProcesses;
- (NSDictionary *)getProcessInfo:(pid_t)pid;
- (void)displayProcesses;
@end

@implementation ProcessInspector

- (instancetype)initWithLicense:(License *)license {
    self = [super init];
    if (self) {
        _license = license;
    }
    return self;
}

- (NSArray *)getAllProcesses {
    NSMutableArray *processes = [NSMutableArray array];
    
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t size;
    
    if (sysctl(mib, 4, NULL, &size, NULL, 0) < 0) {
        return processes;
    }
    
    struct kinfo_proc *procList = (struct kinfo_proc *)malloc(size);
    if (!procList) return processes;
    
    if (sysctl(mib, 4, procList, &size, NULL, 0) >= 0) {
        int count = (int)(size / sizeof(struct kinfo_proc));
        
        for (int i = 0; i < count; i++) {
            NSMutableDictionary *procInfo = [NSMutableDictionary dictionary];
            procInfo[@"pid"] = @(procList[i].kp_proc.p_pid);
            procInfo[@"name"] = [NSString stringWithUTF8String:procList[i].kp_proc.p_comm];
            procInfo[@"uid"] = @(procList[i].kp_eproc.e_ucred.cr_uid);
            [processes addObject:procInfo];
        }
    }
    
    free(procList);
    return processes;
}

- (NSDictionary *)getProcessInfo:(pid_t)pid {
    NSMutableDictionary *info = [NSMutableDictionary dictionary];
    
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    struct kinfo_proc proc;
    size_t size = sizeof(proc);
    
    if (sysctl(mib, 4, &proc, &size, NULL, 0) >= 0) {
        info[@"pid"] = @(proc.kp_proc.p_pid);
        info[@"ppid"] = @(proc.kp_eproc.e_ppid);
        info[@"name"] = [NSString stringWithUTF8String:proc.kp_proc.p_comm];
        info[@"uid"] = @(proc.kp_eproc.e_ucred.cr_uid);
        info[@"priority"] = @(proc.kp_proc.p_priority);
        info[@"nice"] = @(proc.kp_proc.p_nice);
        
        // Get username
        struct passwd *pw = getpwuid(proc.kp_eproc.e_ucred.cr_uid);
        if (pw) {
            info[@"user"] = [NSString stringWithUTF8String:pw->pw_name];
        }
        
        // Get path (requires premium)
        if ([self.license isPremium]) {
            char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
            if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) > 0) {
                info[@"path"] = [NSString stringWithUTF8String:pathbuf];
            }
        }
    }
    
    return info;
}

- (void)displayProcesses {
    printf("\n📋 Process List:\n\n");
    
    NSArray *processes = [self getAllProcesses];
    
    // Sort by name
    NSArray *sorted = [processes sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        return [a[@"name"] compare:b[@"name"]];
    }];
    
    printf("  Found %lu processes\n\n", (unsigned long)sorted.count);
    
    // Group by user
    NSMutableDictionary *byUser = [NSMutableDictionary dictionary];
    for (NSDictionary *proc in sorted) {
        NSNumber *uid = proc[@"uid"];
        if (!byUser[uid]) {
            byUser[uid] = [NSMutableArray array];
        }
        [byUser[uid] addObject:proc];
    }
    
    int shown = 0;
    for (NSDictionary *proc in sorted) {
        if (shown >= 30) {
            printf("  ... and %lu more processes\n", (unsigned long)(sorted.count - shown));
            break;
        }
        printf("  [%5d] %s (UID: %d)\n",
               [proc[@"pid"] intValue],
               [proc[@"name"] UTF8String],
               [proc[@"uid"] intValue]);
        shown++;
    }
}

@end

#pragma mark - IOKit Inspector

@interface IOKitInspector : NSObject
- (NSDictionary *)getPlatformInfo;
- (NSArray *)getUSBDevices;
- (void)displayPlatformInfo;
- (void)displayUSBDevices;
@end

@implementation IOKitInspector

- (NSDictionary *)getPlatformInfo {
    NSMutableDictionary *info = [NSMutableDictionary dictionary];
    
    io_registry_entry_t platformExpert = IOServiceGetMatchingService(
        kIOMainPortDefault,
        IOServiceMatching("IOPlatformExpertDevice")
    );
    
    if (platformExpert) {
        CFTypeRef serialNumberRef = IORegistryEntryCreateCFProperty(
            platformExpert,
            CFSTR(kIOPlatformSerialNumberKey),
            kCFAllocatorDefault, 0
        );
        if (serialNumberRef) {
            info[@"serialNumber"] = (__bridge_transfer NSString *)serialNumberRef;
        }
        
        CFTypeRef uuidRef = IORegistryEntryCreateCFProperty(
            platformExpert,
            CFSTR(kIOPlatformUUIDKey),
            kCFAllocatorDefault, 0
        );
        if (uuidRef) {
            info[@"uuid"] = (__bridge_transfer NSString *)uuidRef;
        }
        
        CFTypeRef modelRef = IORegistryEntryCreateCFProperty(
            platformExpert,
            CFSTR("model"),
            kCFAllocatorDefault, 0
        );
        if (modelRef) {
            NSData *modelData = (__bridge_transfer NSData *)modelRef;
            info[@"model"] = [[NSString alloc] initWithData:modelData encoding:NSUTF8StringEncoding];
        }
        
        IOObjectRelease(platformExpert);
    }
    
    return info;
}

- (NSArray *)getUSBDevices {
    NSMutableArray *devices = [NSMutableArray array];
    
    CFMutableDictionaryRef matchingDict = IOServiceMatching(kIOUSBDeviceClassName);
    if (!matchingDict) return devices;
    
    io_iterator_t iterator;
    kern_return_t kr = IOServiceGetMatchingServices(kIOMainPortDefault, matchingDict, &iterator);
    
    if (kr != KERN_SUCCESS) return devices;
    
    io_object_t usbDevice;
    while ((usbDevice = IOIteratorNext(iterator))) {
        NSMutableDictionary *deviceInfo = [NSMutableDictionary dictionary];
        
        CFTypeRef vendorRef = IORegistryEntryCreateCFProperty(
            usbDevice, CFSTR("idVendor"), kCFAllocatorDefault, 0
        );
        if (vendorRef) {
            deviceInfo[@"vendorId"] = (__bridge_transfer NSNumber *)vendorRef;
        }
        
        CFTypeRef productRef = IORegistryEntryCreateCFProperty(
            usbDevice, CFSTR("idProduct"), kCFAllocatorDefault, 0
        );
        if (productRef) {
            deviceInfo[@"productId"] = (__bridge_transfer NSNumber *)productRef;
        }
        
        CFTypeRef nameRef = IORegistryEntryCreateCFProperty(
            usbDevice, CFSTR("USB Product Name"), kCFAllocatorDefault, 0
        );
        if (nameRef) {
            deviceInfo[@"name"] = (__bridge_transfer NSString *)nameRef;
        }
        
        CFTypeRef vendorNameRef = IORegistryEntryCreateCFProperty(
            usbDevice, CFSTR("USB Vendor Name"), kCFAllocatorDefault, 0
        );
        if (vendorNameRef) {
            deviceInfo[@"vendor"] = (__bridge_transfer NSString *)vendorNameRef;
        }
        
        [devices addObject:deviceInfo];
        IOObjectRelease(usbDevice);
    }
    
    IOObjectRelease(iterator);
    return devices;
}

- (void)displayPlatformInfo {
    printf("\n🖥️  Platform Information:\n\n");
    
    NSDictionary *info = [self getPlatformInfo];
    
    for (NSString *key in [info.allKeys sortedArrayUsingSelector:@selector(compare:)]) {
        printf("  %s: %s\n", [key UTF8String], [info[key] UTF8String]);
    }
}

- (void)displayUSBDevices {
    printf("\n🔌 USB Devices:\n\n");
    
    NSArray *devices = [self getUSBDevices];
    
    printf("  Found %lu USB devices\n\n", (unsigned long)devices.count);
    
    for (NSDictionary *device in devices) {
        NSString *name = device[@"name"] ?: @"Unknown Device";
        NSString *vendor = device[@"vendor"] ?: @"Unknown Vendor";
        NSNumber *vendorId = device[@"vendorId"] ?: @0;
        NSNumber *productId = device[@"productId"] ?: @0;
        
        printf("  • %s\n", [name UTF8String]);
        printf("    Vendor: %s (0x%04X)\n", [vendor UTF8String], [vendorId intValue]);
        printf("    Product ID: 0x%04X\n\n", [productId intValue]);
    }
}

@end

#pragma mark - Memory Inspector

@interface MemoryInspector : NSObject
@property (nonatomic, strong) License *license;
- (instancetype)initWithLicense:(License *)license;
- (NSDictionary *)getMemoryInfo;
- (void)displayMemoryInfo;
@end

@implementation MemoryInspector

- (instancetype)initWithLicense:(License *)license {
    self = [super init];
    if (self) {
        _license = license;
    }
    return self;
}

- (NSDictionary *)getMemoryInfo {
    NSMutableDictionary *info = [NSMutableDictionary dictionary];
    
    // Get physical memory
    int64_t physMem;
    size_t size = sizeof(physMem);
    if (sysctlbyname("hw.memsize", &physMem, &size, NULL, 0) == 0) {
        info[@"physicalMemory"] = @(physMem);
    }
    
    // Get VM statistics
    mach_port_t hostPort = mach_host_self();
    vm_statistics64_data_t vmStats;
    mach_msg_type_number_t infoCount = HOST_VM_INFO64_COUNT;
    
    kern_return_t kr = host_statistics64(hostPort, HOST_VM_INFO64,
                                          (host_info64_t)&vmStats, &infoCount);
    
    if (kr == KERN_SUCCESS) {
        vm_size_t pageSize;
        host_page_size(hostPort, &pageSize);
        
        info[@"freeMemory"] = @((uint64_t)vmStats.free_count * pageSize);
        info[@"activeMemory"] = @((uint64_t)vmStats.active_count * pageSize);
        info[@"inactiveMemory"] = @((uint64_t)vmStats.inactive_count * pageSize);
        info[@"wiredMemory"] = @((uint64_t)vmStats.wire_count * pageSize);
        info[@"compressedMemory"] = @((uint64_t)vmStats.compressor_page_count * pageSize);
        info[@"pageIns"] = @(vmStats.pageins);
        info[@"pageOuts"] = @(vmStats.pageouts);
    }
    
    return info;
}

- (void)displayMemoryInfo {
    printf("\n💾 Memory Information:\n\n");
    
    NSDictionary *info = [self getMemoryInfo];
    
    uint64_t total = [info[@"physicalMemory"] unsignedLongLongValue];
    printf("  Total Physical: %.2f GB\n", total / 1024.0 / 1024.0 / 1024.0);
    
    uint64_t free = [info[@"freeMemory"] unsignedLongLongValue];
    printf("  Free: %.2f GB\n", free / 1024.0 / 1024.0 / 1024.0);
    
    uint64_t active = [info[@"activeMemory"] unsignedLongLongValue];
    printf("  Active: %.2f GB\n", active / 1024.0 / 1024.0 / 1024.0);
    
    uint64_t inactive = [info[@"inactiveMemory"] unsignedLongLongValue];
    printf("  Inactive: %.2f GB\n", inactive / 1024.0 / 1024.0 / 1024.0);
    
    uint64_t wired = [info[@"wiredMemory"] unsignedLongLongValue];
    printf("  Wired: %.2f GB\n", wired / 1024.0 / 1024.0 / 1024.0);
    
    uint64_t compressed = [info[@"compressedMemory"] unsignedLongLongValue];
    printf("  Compressed: %.2f GB\n", compressed / 1024.0 / 1024.0 / 1024.0);
    
    printf("\n  Page Ins: %llu\n", [info[@"pageIns"] unsignedLongLongValue]);
    printf("  Page Outs: %llu\n", [info[@"pageOuts"] unsignedLongLongValue]);
}

@end

#pragma mark - TCC Database Reader

@interface TCCReader : NSObject
@property (nonatomic, strong) License *license;
- (instancetype)initWithLicense:(License *)license;
- (NSArray *)readTCCDatabase;
- (void)displayTCCEntries;
@end

@implementation TCCReader

- (instancetype)initWithLicense:(License *)license {
    self = [super init];
    if (self) {
        _license = license;
    }
    return self;
}

- (NSArray *)readTCCDatabase {
    if (![self.license isPremium]) {
        [Console warning:@"TCC database access requires premium license"];
        [Console info:@"Get premium at x.com/AnonAntics"];
        return @[];
    }
    
    NSMutableArray *entries = [NSMutableArray array];
    
    // TCC database paths
    NSArray *dbPaths = @[
        @"/Library/Application Support/com.apple.TCC/TCC.db",
        [NSString stringWithFormat:@"%@/Library/Application Support/com.apple.TCC/TCC.db",
         NSHomeDirectory()]
    ];
    
    for (NSString *dbPath in dbPaths) {
        if (![[NSFileManager defaultManager] fileExistsAtPath:dbPath]) {
            continue;
        }
        
        // Read using sqlite3 command
        NSTask *task = [[NSTask alloc] init];
        task.launchPath = @"/usr/bin/sqlite3";
        task.arguments = @[dbPath, @"SELECT service, client, auth_value FROM access"];
        
        NSPipe *pipe = [NSPipe pipe];
        task.standardOutput = pipe;
        task.standardError = pipe;
        
        @try {
            [task launch];
            [task waitUntilExit];
            
            NSData *data = [[pipe fileHandleForReading] readDataToEndOfFile];
            NSString *output = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            
            for (NSString *line in [output componentsSeparatedByString:@"\n"]) {
                if (line.length == 0) continue;
                
                NSArray *parts = [line componentsSeparatedByString:@"|"];
                if (parts.count >= 3) {
                    [entries addObject:@{
                        @"service": parts[0],
                        @"client": parts[1],
                        @"authorized": @([parts[2] intValue] == 2)
                    }];
                }
            }
        } @catch (NSException *exception) {
            // Ignore errors
        }
    }
    
    return entries;
}

- (void)displayTCCEntries {
    printf("\n🔒 TCC (Privacy) Database:\n\n");
    
    NSArray *entries = [self readTCCDatabase];
    
    if (entries.count == 0) {
        printf("  No entries found or access denied\n");
        return;
    }
    
    printf("  Found %lu privacy permission entries\n\n", (unsigned long)entries.count);
    
    // Group by service
    NSMutableDictionary *byService = [NSMutableDictionary dictionary];
    for (NSDictionary *entry in entries) {
        NSString *service = entry[@"service"];
        if (!byService[service]) {
            byService[service] = [NSMutableArray array];
        }
        [byService[service] addObject:entry];
    }
    
    for (NSString *service in [byService.allKeys sortedArrayUsingSelector:@selector(compare:)]) {
        printf("  %s:\n", [service UTF8String]);
        
        for (NSDictionary *entry in byService[service]) {
            NSString *icon = [entry[@"authorized"] boolValue] ? @"✅" : @"❌";
            printf("    %s %s\n", [icon UTF8String], [entry[@"client"] UTF8String]);
        }
        printf("\n");
    }
}

@end

#pragma mark - Main

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        License *license = [[License alloc] initWithKey:nil];
        
        // Parse arguments
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--key") == 0) {
                if (i + 1 < argc) {
                    license = [[License alloc] initWithKey:[NSString stringWithUTF8String:argv[i+1]]];
                    NSString *tier = @[@"FREE", @"PREMIUM", @"ENTERPRISE"][license.tier];
                    [Console info:[NSString stringWithFormat:@"License tier: %@", tier]];
                    i++;
                }
            } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                printf("NullSec macOS Low-Level Tools v%s\n", [VERSION UTF8String]);
                printf("%s | %s\n\n", [AUTHOR UTF8String], [DISCORD UTF8String]);
                printf("Usage: lowlevel [options]\n\n");
                printf("Options:\n");
                printf("  -k, --key KEY    License key\n");
                printf("  -h, --help       Show help\n");
                printf("  -v, --version    Show version\n");
                return 0;
            } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
                printf("NullSec macOS Low-Level Tools v%s\n", [VERSION UTF8String]);
                return 0;
            }
        }
        
        // Print banner
        printf("\033[36m");
        printf("╭──────────────────────────────────────────╮\n");
        printf("│     🍎 NULLSEC MACOS LOW-LEVEL TOOLS     │\n");
        printf("│       ════════════════════════════       │\n");
        printf("│                                          │\n");
        printf("│   🔧 Objective-C Direct System Access    │\n");
        printf("│   📡 IOKit • Mach • TCC Database         │\n");
        printf("│   💾 Process & Memory Inspection         │\n");
        printf("│                                          │\n");
        printf("│            bad-antics | NullSec         │\n");
        printf("╰──────────────────────────────────────────╯\n");
        printf("\033[0m\n");
        
        // Menu loop
        BOOL running = YES;
        while (running) {
            printf("\n📋 Low-Level Tools Menu:\n\n");
            printf("  [1] Platform Info (IOKit)\n");
            printf("  [2] USB Devices\n");
            printf("  [3] Process List\n");
            printf("  [4] Memory Info\n");
            printf("  [5] TCC Database (Premium)\n");
            printf("  [0] Exit\n\n");
            printf("Select: ");
            
            int choice;
            scanf("%d", &choice);
            
            switch (choice) {
                case 1:
                    [[[IOKitInspector alloc] init] displayPlatformInfo];
                    break;
                case 2:
                    [[[IOKitInspector alloc] init] displayUSBDevices];
                    break;
                case 3:
                    [[[ProcessInspector alloc] initWithLicense:license] displayProcesses];
                    break;
                case 4:
                    [[[MemoryInspector alloc] initWithLicense:license] displayMemoryInfo];
                    break;
                case 5:
                    [[[TCCReader alloc] initWithLicense:license] displayTCCEntries];
                    break;
                case 0:
                    running = NO;
                    break;
                default:
                    [Console error:@"Invalid option"];
            }
        }
        
        printf("\n─────────────────────────────────────────\n");
        printf("🍎 NullSec macOS Low-Level Tools\n");
        printf("🔑 Premium: x.com/AnonAntics\n");
        printf("🐦 GitHub: bad-antics\n");
        printf("─────────────────────────────────────────\n\n");
    }
    return 0;
}
