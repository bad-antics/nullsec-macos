// NullSec macOS Security Toolkit - Swift
// Native Apple security analysis
// @author bad-antics
// @discord x.com/AnonAntics

import Foundation
import Security
import SystemConfiguration
import IOKit
import DiskArbitration

// MARK: - Configuration

let VERSION = "2.0.0"
let AUTHOR = "bad-antics"
let DISCORD = "x.com/AnonAntics"

let BANNER = """
╭──────────────────────────────────────────╮
│        🍎 NULLSEC MACOS TOOLKIT          │
│       ════════════════════════════       │
│                                          │
│   🔧 Native Security Analysis v2.0       │
│   📡 SIP • Keychain • Network            │
│   💾 Forensics & Hardening               │
│                                          │
│            bad-antics | NullSec         │
╰──────────────────────────────────────────╯
"""

// MARK: - Color Output

enum Colors {
    static let reset = "\u{001B}[0m"
    static let red = "\u{001B}[31m"
    static let green = "\u{001B}[32m"
    static let yellow = "\u{001B}[33m"
    static let blue = "\u{001B}[34m"
    static let cyan = "\u{001B}[36m"
    
    static func success(_ msg: String) {
        print("\(green)✅ \(msg)\(reset)")
    }
    
    static func error(_ msg: String) {
        print("\(red)❌ \(msg)\(reset)")
    }
    
    static func warning(_ msg: String) {
        print("\(yellow)⚠️  \(msg)\(reset)")
    }
    
    static func info(_ msg: String) {
        print("\(blue)ℹ️  \(msg)\(reset)")
    }
}

// MARK: - License System

enum LicenseTier: String {
    case free = "FREE"
    case premium = "PREMIUM"
    case enterprise = "ENTERPRISE"
}

struct License {
    var key: String
    var tier: LicenseTier
    var valid: Bool
    
    init(_ licenseKey: String? = nil) {
        key = licenseKey ?? ""
        tier = .free
        valid = false
        validate()
    }
    
    mutating func validate() {
        guard key.count == 24, key.hasPrefix("NMAC-") else {
            tier = .free
            valid = false
            return
        }
        
        let parts = key.split(separator: "-")
        guard parts.count == 5 else {
            tier = .free
            valid = false
            return
        }
        
        let tierCode = String(parts[1].prefix(2))
        switch tierCode {
        case "PR": tier = .premium
        case "EN": tier = .enterprise
        default: tier = .free
        }
        valid = true
    }
    
    func isPremium() -> Bool {
        return valid && tier != .free
    }
}

// MARK: - SIP (System Integrity Protection) Checker

struct SIPChecker {
    
    func checkSIPStatus() -> (enabled: Bool, details: [String: Bool]) {
        var details: [String: Bool] = [:]
        
        // Run csrutil status
        let task = Process()
        task.launchPath = "/usr/bin/csrutil"
        task.arguments = ["status"]
        
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = pipe
        
        do {
            try task.run()
            task.waitUntilExit()
            
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""
            
            let enabled = output.contains("enabled")
            
            // Parse individual protections
            details["Filesystem Protections"] = !output.contains("Filesystem Protections: disabled")
            details["Debugging Restrictions"] = !output.contains("Debugging Restrictions: disabled")
            details["DTrace Restrictions"] = !output.contains("DTrace Restrictions: disabled")
            details["NVRAM Protections"] = !output.contains("NVRAM Protections: disabled")
            details["BaseSystem Verification"] = !output.contains("BaseSystem Verification: disabled")
            
            return (enabled, details)
        } catch {
            return (true, details) // Assume enabled if we can't check
        }
    }
    
    func displayStatus() {
        print("\n🛡️  System Integrity Protection Status:\n")
        
        let (enabled, details) = checkSIPStatus()
        
        if enabled {
            Colors.success("SIP is ENABLED")
        } else {
            Colors.warning("SIP is DISABLED")
        }
        
        print("\nProtection Details:")
        for (protection, status) in details.sorted(by: { $0.key < $1.key }) {
            let icon = status ? "✅" : "⚠️"
            let statusText = status ? "Enabled" : "Disabled"
            print("  \(icon) \(protection): \(statusText)")
        }
    }
}

// MARK: - Gatekeeper Checker

struct GatekeeperChecker {
    
    func checkGatekeeperStatus() -> (enabled: Bool, source: String) {
        let task = Process()
        task.launchPath = "/usr/sbin/spctl"
        task.arguments = ["--status"]
        
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = pipe
        
        do {
            try task.run()
            task.waitUntilExit()
            
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""
            
            let enabled = output.contains("assessments enabled")
            
            // Get allowed sources
            var source = "Unknown"
            if enabled {
                source = "App Store and identified developers"
            } else {
                source = "Anywhere (Gatekeeper disabled)"
            }
            
            return (enabled, source)
        } catch {
            return (true, "Unknown")
        }
    }
    
    func displayStatus() {
        print("\n🚪 Gatekeeper Status:\n")
        
        let (enabled, source) = checkGatekeeperStatus()
        
        if enabled {
            Colors.success("Gatekeeper is ENABLED")
        } else {
            Colors.warning("Gatekeeper is DISABLED")
        }
        
        print("  Allowed Sources: \(source)")
    }
}

// MARK: - Firewall Checker

struct FirewallChecker {
    
    func checkFirewallStatus() -> (enabled: Bool, stealthMode: Bool, blockAll: Bool) {
        let task = Process()
        task.launchPath = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        task.arguments = ["--getglobalstate"]
        
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = pipe
        
        var enabled = false
        var stealthMode = false
        var blockAll = false
        
        do {
            try task.run()
            task.waitUntilExit()
            
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""
            
            enabled = output.contains("enabled")
            
            // Check stealth mode
            let stealthTask = Process()
            stealthTask.launchPath = "/usr/libexec/ApplicationFirewall/socketfilterfw"
            stealthTask.arguments = ["--getstealthmode"]
            let stealthPipe = Pipe()
            stealthTask.standardOutput = stealthPipe
            try stealthTask.run()
            stealthTask.waitUntilExit()
            let stealthData = stealthPipe.fileHandleForReading.readDataToEndOfFile()
            let stealthOutput = String(data: stealthData, encoding: .utf8) ?? ""
            stealthMode = stealthOutput.contains("enabled")
            
            // Check block all
            let blockTask = Process()
            blockTask.launchPath = "/usr/libexec/ApplicationFirewall/socketfilterfw"
            blockTask.arguments = ["--getblockall"]
            let blockPipe = Pipe()
            blockTask.standardOutput = blockPipe
            try blockTask.run()
            blockTask.waitUntilExit()
            let blockData = blockPipe.fileHandleForReading.readDataToEndOfFile()
            let blockOutput = String(data: blockData, encoding: .utf8) ?? ""
            blockAll = blockOutput.contains("enabled")
            
        } catch {
            // Ignore errors
        }
        
        return (enabled, stealthMode, blockAll)
    }
    
    func displayStatus() {
        print("\n🔥 Firewall Status:\n")
        
        let (enabled, stealthMode, blockAll) = checkFirewallStatus()
        
        if enabled {
            Colors.success("Firewall is ENABLED")
        } else {
            Colors.warning("Firewall is DISABLED")
        }
        
        let stealthIcon = stealthMode ? "✅" : "⚠️"
        let stealthStatus = stealthMode ? "Enabled" : "Disabled"
        print("  \(stealthIcon) Stealth Mode: \(stealthStatus)")
        
        let blockIcon = blockAll ? "🔒" : "🔓"
        let blockStatus = blockAll ? "Enabled" : "Disabled"
        print("  \(blockIcon) Block All Incoming: \(blockStatus)")
    }
}

// MARK: - FileVault Checker

struct FileVaultChecker {
    
    func checkFileVaultStatus() -> (enabled: Bool, progress: Int?) {
        let task = Process()
        task.launchPath = "/usr/bin/fdesetup"
        task.arguments = ["status"]
        
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = pipe
        
        do {
            try task.run()
            task.waitUntilExit()
            
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""
            
            if output.contains("FileVault is On") {
                return (true, nil)
            } else if output.contains("Encryption in progress") {
                // Try to extract progress percentage
                if let range = output.range(of: "\\d+%", options: .regularExpression) {
                    let progressStr = output[range].dropLast()
                    if let progress = Int(progressStr) {
                        return (false, progress)
                    }
                }
                return (false, 0)
            }
            
            return (false, nil)
        } catch {
            return (false, nil)
        }
    }
    
    func displayStatus() {
        print("\n🔐 FileVault Status:\n")
        
        let (enabled, progress) = checkFileVaultStatus()
        
        if enabled {
            Colors.success("FileVault is ENABLED")
            print("  💾 Disk encryption is active")
        } else if let progress = progress {
            Colors.warning("FileVault encryption in progress: \(progress)%")
        } else {
            Colors.error("FileVault is DISABLED")
            Colors.warning("  Your disk is not encrypted!")
        }
    }
}

// MARK: - Keychain Auditor

struct KeychainAuditor {
    let license: License
    
    func auditKeychain() -> [(service: String, account: String, created: Date?)] {
        guard license.isPremium() else {
            Colors.warning("Keychain audit requires premium license")
            Colors.info("Get premium at x.com/AnonAntics")
            return []
        }
        
        var items: [(service: String, account: String, created: Date?)] = []
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        if status == errSecSuccess, let itemArray = result as? [[String: Any]] {
            for item in itemArray {
                let service = item[kSecAttrService as String] as? String ?? "Unknown"
                let account = item[kSecAttrAccount as String] as? String ?? "Unknown"
                let created = item[kSecAttrCreationDate as String] as? Date
                
                items.append((service, account, created))
            }
        }
        
        return items
    }
    
    func displayAudit() {
        print("\n🔑 Keychain Audit:\n")
        
        let items = auditKeychain()
        
        if items.isEmpty {
            if !license.isPremium() {
                return
            }
            print("  No accessible keychain items found")
            return
        }
        
        let dateFormatter = DateFormatter()
        dateFormatter.dateStyle = .short
        dateFormatter.timeStyle = .short
        
        print("  Found \(items.count) keychain items:\n")
        
        for (index, item) in items.prefix(20).enumerated() {
            let createdStr = item.created.map { dateFormatter.string(from: $0) } ?? "Unknown"
            print("  [\(index + 1)] \(item.service)")
            print("      Account: \(item.account)")
            print("      Created: \(createdStr)\n")
        }
        
        if items.count > 20 {
            print("  ... and \(items.count - 20) more items")
        }
    }
}

// MARK: - Network Analyzer

struct NetworkAnalyzer {
    
    func getNetworkInterfaces() -> [String: String] {
        var interfaces: [String: String] = [:]
        
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        
        guard getifaddrs(&ifaddr) == 0, let firstAddr = ifaddr else {
            return interfaces
        }
        
        defer { freeifaddrs(ifaddr) }
        
        var ptr = firstAddr
        while true {
            let name = String(cString: ptr.pointee.ifa_name)
            
            if ptr.pointee.ifa_addr?.pointee.sa_family == UInt8(AF_INET) {
                var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                getnameinfo(ptr.pointee.ifa_addr, socklen_t(ptr.pointee.ifa_addr.pointee.sa_len),
                           &hostname, socklen_t(hostname.count), nil, 0, NI_NUMERICHOST)
                let address = String(cString: hostname)
                interfaces[name] = address
            }
            
            guard let next = ptr.pointee.ifa_next else { break }
            ptr = next
        }
        
        return interfaces
    }
    
    func getWiFiInfo() -> (ssid: String?, bssid: String?) {
        // Use CoreWLAN through shell
        let task = Process()
        task.launchPath = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        task.arguments = ["-I"]
        
        let pipe = Pipe()
        task.standardOutput = pipe
        
        do {
            try task.run()
            task.waitUntilExit()
            
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""
            
            var ssid: String?
            var bssid: String?
            
            for line in output.components(separatedBy: "\n") {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.hasPrefix("SSID:") {
                    ssid = trimmed.replacingOccurrences(of: "SSID: ", with: "")
                } else if trimmed.hasPrefix("BSSID:") {
                    bssid = trimmed.replacingOccurrences(of: "BSSID: ", with: "")
                }
            }
            
            return (ssid, bssid)
        } catch {
            return (nil, nil)
        }
    }
    
    func displayStatus() {
        print("\n🌐 Network Status:\n")
        
        let interfaces = getNetworkInterfaces()
        
        print("  Network Interfaces:")
        for (name, address) in interfaces.sorted(by: { $0.key < $1.key }) {
            print("    \(name): \(address)")
        }
        
        let (ssid, bssid) = getWiFiInfo()
        
        print("\n  WiFi:")
        if let ssid = ssid {
            print("    SSID: \(ssid)")
            if let bssid = bssid {
                print("    BSSID: \(bssid)")
            }
        } else {
            print("    Not connected to WiFi")
        }
    }
}

// MARK: - System Info

struct SystemInfo {
    
    func getSystemInfo() -> [String: String] {
        var info: [String: String] = [:]
        
        // macOS version
        let version = ProcessInfo.processInfo.operatingSystemVersion
        info["macOS Version"] = "\(version.majorVersion).\(version.minorVersion).\(version.patchVersion)"
        
        // Hostname
        info["Hostname"] = Host.current().localizedName ?? "Unknown"
        
        // Hardware model
        var size = 0
        sysctlbyname("hw.model", nil, &size, nil, 0)
        var model = [CChar](repeating: 0, count: size)
        sysctlbyname("hw.model", &model, &size, nil, 0)
        info["Hardware Model"] = String(cString: model)
        
        // CPU
        sysctlbyname("machdep.cpu.brand_string", nil, &size, nil, 0)
        var cpu = [CChar](repeating: 0, count: size)
        sysctlbyname("machdep.cpu.brand_string", &cpu, &size, nil, 0)
        info["CPU"] = String(cString: cpu)
        
        // RAM
        let ram = ProcessInfo.processInfo.physicalMemory
        info["RAM"] = "\(ram / 1024 / 1024 / 1024) GB"
        
        // Serial number (requires admin)
        let task = Process()
        task.launchPath = "/usr/sbin/ioreg"
        task.arguments = ["-l", "-d", "2"]
        let pipe = Pipe()
        task.standardOutput = pipe
        do {
            try task.run()
            task.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""
            if let range = output.range(of: "\"IOPlatformSerialNumber\" = \"[^\"]+\"", options: .regularExpression) {
                let serialLine = String(output[range])
                if let start = serialLine.lastIndex(of: "\""), let end = serialLine.index(start, offsetBy: 12, limitedBy: serialLine.endIndex) {
                    let serial = String(serialLine[serialLine.index(after: start)..<end])
                    info["Serial Number"] = serial
                }
            }
        } catch {}
        
        return info
    }
    
    func displayInfo() {
        print("\n💻 System Information:\n")
        
        let info = getSystemInfo()
        
        for (key, value) in info.sorted(by: { $0.key < $1.key }) {
            print("  \(key): \(value)")
        }
    }
}

// MARK: - Launch Items Scanner

struct LaunchItemsScanner {
    
    func scanLaunchItems() -> [(path: String, name: String, type: String)] {
        var items: [(path: String, name: String, type: String)] = []
        
        let paths = [
            ("/Library/LaunchDaemons", "System Daemon"),
            ("/Library/LaunchAgents", "System Agent"),
            ("~/Library/LaunchAgents", "User Agent")
        ]
        
        let fm = FileManager.default
        
        for (path, type) in paths {
            let expandedPath = NSString(string: path).expandingTildeInPath
            
            guard let contents = try? fm.contentsOfDirectory(atPath: expandedPath) else {
                continue
            }
            
            for file in contents where file.hasSuffix(".plist") {
                items.append((
                    path: "\(expandedPath)/\(file)",
                    name: file.replacingOccurrences(of: ".plist", with: ""),
                    type: type
                ))
            }
        }
        
        return items
    }
    
    func displayItems() {
        print("\n🚀 Launch Items:\n")
        
        let items = scanLaunchItems()
        
        var byType: [String: [(path: String, name: String)]] = [:]
        
        for item in items {
            if byType[item.type] == nil {
                byType[item.type] = []
            }
            byType[item.type]?.append((item.path, item.name))
        }
        
        for (type, typeItems) in byType.sorted(by: { $0.key < $1.key }) {
            print("  \(type) (\(typeItems.count)):")
            for item in typeItems.prefix(10) {
                print("    • \(item.name)")
            }
            if typeItems.count > 10 {
                print("    ... and \(typeItems.count - 10) more")
            }
            print()
        }
    }
}

// MARK: - Main Menu

class MainMenu {
    var license: License
    
    init(license: License) {
        self.license = license
    }
    
    func showBanner() {
        print("\(Colors.cyan)\(BANNER)\(Colors.reset)")
    }
    
    func showMenu() {
        let tierBadge: String
        switch license.tier {
        case .free: tierBadge = "🆓"
        case .premium: tierBadge = "⭐"
        case .enterprise: tierBadge = "💎"
        }
        
        print("\n📋 NullSec macOS Menu \(tierBadge)\n")
        print("  [1] SIP Status")
        print("  [2] Gatekeeper Status")
        print("  [3] Firewall Status")
        print("  [4] FileVault Status")
        print("  [5] Network Status")
        print("  [6] System Info")
        print("  [7] Launch Items")
        print("  [8] Keychain Audit (Premium)")
        print("  [9] Full Security Scan")
        print("  [0] Exit")
        print()
    }
    
    func run() {
        showBanner()
        
        var running = true
        while running {
            showMenu()
            print("Select: ", terminator: "")
            
            guard let input = readLine(), let choice = Int(input) else {
                continue
            }
            
            switch choice {
            case 1:
                SIPChecker().displayStatus()
            case 2:
                GatekeeperChecker().displayStatus()
            case 3:
                FirewallChecker().displayStatus()
            case 4:
                FileVaultChecker().displayStatus()
            case 5:
                NetworkAnalyzer().displayStatus()
            case 6:
                SystemInfo().displayInfo()
            case 7:
                LaunchItemsScanner().displayItems()
            case 8:
                KeychainAuditor(license: license).displayAudit()
            case 9:
                // Full scan
                SIPChecker().displayStatus()
                GatekeeperChecker().displayStatus()
                FirewallChecker().displayStatus()
                FileVaultChecker().displayStatus()
                NetworkAnalyzer().displayStatus()
            case 0:
                running = false
            default:
                Colors.error("Invalid option")
            }
        }
        
        print("\n─────────────────────────────────────────")
        print("🍎 NullSec macOS Toolkit")
        print("🔑 Premium: x.com/AnonAntics")
        print("🐦 GitHub: bad-antics")
        print("─────────────────────────────────────────\n")
    }
}

// MARK: - Entry Point

func main() {
    var license = License()
    
    let args = CommandLine.arguments
    var i = 1
    while i < args.count {
        switch args[i] {
        case "-k", "--key":
            if i + 1 < args.count {
                license = License(args[i + 1])
                Colors.info("License tier: \(license.tier.rawValue)")
                i += 1
            }
        case "-h", "--help":
            print("NullSec macOS Toolkit v\(VERSION)")
            print("\(AUTHOR) | \(DISCORD)\n")
            print("Usage: nullsec-macos [options]")
            print()
            print("Options:")
            print("  -k, --key KEY    License key")
            print("  -h, --help       Show help")
            print("  -v, --version    Show version")
            return
        case "-v", "--version":
            print("NullSec macOS Toolkit v\(VERSION)")
            return
        default:
            break
        }
        i += 1
    }
    
    MainMenu(license: license).run()
}

main()
