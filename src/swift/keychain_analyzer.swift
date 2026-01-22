/*
 * ═══════════════════════════════════════════════════════════════════
 *  NULLSEC MACOS SWIFT KEYCHAIN ANALYZER
 *  Secure keychain analysis and credential auditing
 *  @author bad-antics | discord.gg/killers
 * ═══════════════════════════════════════════════════════════════════
 */

import Foundation
import Security

let VERSION = "2.0.0"
let AUTHOR = "bad-antics"
let DISCORD = "discord.gg/killers"

let BANNER = """

╭──────────────────────────────────────────╮
│     🍎 NULLSEC MACOS KEYCHAIN TOOL      │
│     ════════════════════════════        │
│                                          │
│   🔐 Keychain Analysis & Auditing        │
│   🔑 Credential Discovery                │
│   🛡️  Security Assessment                │
│                                          │
│          bad-antics | NullSec            │
╰──────────────────────────────────────────╯

"""

// ═══════════════════════════════════════════════════════════════════
// License Management
// ═══════════════════════════════════════════════════════════════════

enum LicenseTier {
    case free
    case premium
    case enterprise
    
    var description: String {
        switch self {
        case .free: return "Free"
        case .premium: return "Premium ⭐"
        case .enterprise: return "Enterprise 💎"
        }
    }
}

struct License {
    var key: String = ""
    var tier: LicenseTier = .free
    var valid: Bool = false
    
    static func validate(_ key: String) -> License {
        var license = License()
        
        guard key.count == 24 else { return license }
        guard key.hasPrefix("NMAC-") else { return license }
        
        license.key = key
        license.valid = true
        
        let typeCode = String(key.dropFirst(5).prefix(2))
        switch typeCode {
        case "PR": license.tier = .premium
        case "EN": license.tier = .enterprise
        default: license.tier = .free
        }
        
        return license
    }
    
    var isPremium: Bool {
        return valid && tier != .free
    }
}

// ═══════════════════════════════════════════════════════════════════
// Console Helpers
// ═══════════════════════════════════════════════════════════════════

func printSuccess(_ msg: String) {
    print("\u{001B}[32m✅ \(msg)\u{001B}[0m")
}

func printError(_ msg: String) {
    print("\u{001B}[31m❌ \(msg)\u{001B}[0m")
}

func printWarning(_ msg: String) {
    print("\u{001B}[33m⚠️  \(msg)\u{001B}[0m")
}

func printInfo(_ msg: String) {
    print("\u{001B}[36mℹ️  \(msg)\u{001B}[0m")
}

func printHeader(_ title: String) {
    print("\n═══════════════════════════════════════════")
    print("  \(title)")
    print("═══════════════════════════════════════════\n")
}

// ═══════════════════════════════════════════════════════════════════
// Keychain Item Types
// ═══════════════════════════════════════════════════════════════════

struct KeychainItem {
    var service: String
    var account: String
    var label: String
    var itemClass: String
    var creationDate: Date?
    var modificationDate: Date?
    var accessGroup: String?
}

// ═══════════════════════════════════════════════════════════════════
// Keychain Operations
// ═══════════════════════════════════════════════════════════════════

func listKeychains() {
    printHeader("🔑 KEYCHAIN FILES")
    
    // Default keychain locations
    let keychainPaths = [
        "\(NSHomeDirectory())/Library/Keychains/login.keychain-db",
        "\(NSHomeDirectory())/Library/Keychains/login.keychain",
        "/Library/Keychains/System.keychain",
        "/System/Library/Keychains/SystemRootCertificates.keychain"
    ]
    
    let fileManager = FileManager.default
    
    for path in keychainPaths {
        let exists = fileManager.fileExists(atPath: path)
        let icon = exists ? "🟢" : "⚪"
        
        if exists {
            if let attrs = try? fileManager.attributesOfItem(atPath: path) {
                let size = attrs[.size] as? Int64 ?? 0
                let sizeStr = ByteCountFormatter.string(fromByteCount: size, countStyle: .file)
                print("  \(icon) \(path)")
                print("      Size: \(sizeStr)")
            }
        } else {
            print("  \(icon) \(path) (not found)")
        }
    }
    print()
}

func getInternetPasswords(license: License) -> [KeychainItem] {
    var items: [KeychainItem] = []
    
    let query: [String: Any] = [
        kSecClass as String: kSecClassInternetPassword,
        kSecReturnAttributes as String: true,
        kSecMatchLimit as String: kSecMatchLimitAll
    ]
    
    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    
    if status == errSecSuccess, let itemArray = result as? [[String: Any]] {
        for itemDict in itemArray {
            var item = KeychainItem(
                service: itemDict[kSecAttrServer as String] as? String ?? "Unknown",
                account: itemDict[kSecAttrAccount as String] as? String ?? "Unknown",
                label: itemDict[kSecAttrLabel as String] as? String ?? "",
                itemClass: "Internet Password"
            )
            item.creationDate = itemDict[kSecAttrCreationDate as String] as? Date
            item.modificationDate = itemDict[kSecAttrModificationDate as String] as? Date
            items.append(item)
        }
    }
    
    return items
}

func getGenericPasswords(license: License) -> [KeychainItem] {
    var items: [KeychainItem] = []
    
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecReturnAttributes as String: true,
        kSecMatchLimit as String: kSecMatchLimitAll
    ]
    
    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    
    if status == errSecSuccess, let itemArray = result as? [[String: Any]] {
        for itemDict in itemArray {
            var item = KeychainItem(
                service: itemDict[kSecAttrService as String] as? String ?? "Unknown",
                account: itemDict[kSecAttrAccount as String] as? String ?? "Unknown",
                label: itemDict[kSecAttrLabel as String] as? String ?? "",
                itemClass: "Generic Password"
            )
            item.creationDate = itemDict[kSecAttrCreationDate as String] as? Date
            item.accessGroup = itemDict[kSecAttrAccessGroup as String] as? String
            items.append(item)
        }
    }
    
    return items
}

func getCertificates(license: License) -> [KeychainItem] {
    var items: [KeychainItem] = []
    
    let query: [String: Any] = [
        kSecClass as String: kSecClassCertificate,
        kSecReturnAttributes as String: true,
        kSecMatchLimit as String: kSecMatchLimitAll
    ]
    
    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    
    if status == errSecSuccess, let itemArray = result as? [[String: Any]] {
        for itemDict in itemArray {
            let item = KeychainItem(
                service: itemDict[kSecAttrIssuer as String] as? String ?? "Unknown",
                account: itemDict[kSecAttrSubject as String] as? String ?? "Unknown",
                label: itemDict[kSecAttrLabel as String] as? String ?? "",
                itemClass: "Certificate"
            )
            items.append(item)
        }
    }
    
    return items
}

func getSecureNotes(license: License) -> [KeychainItem] {
    var items: [KeychainItem] = []
    
    // Secure notes are generic passwords with specific type
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrType as String: "note",
        kSecReturnAttributes as String: true,
        kSecMatchLimit as String: kSecMatchLimitAll
    ]
    
    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    
    if status == errSecSuccess, let itemArray = result as? [[String: Any]] {
        for itemDict in itemArray {
            let item = KeychainItem(
                service: "Secure Note",
                account: itemDict[kSecAttrAccount as String] as? String ?? "Unknown",
                label: itemDict[kSecAttrLabel as String] as? String ?? "",
                itemClass: "Secure Note"
            )
            items.append(item)
        }
    }
    
    return items
}

// ═══════════════════════════════════════════════════════════════════
// Analysis Functions
// ═══════════════════════════════════════════════════════════════════

func analyzeInternetPasswords(license: License) {
    printHeader("🌐 INTERNET PASSWORDS")
    
    let items = getInternetPasswords(license: license)
    let limit = license.isPremium ? items.count : min(10, items.count)
    
    if items.isEmpty {
        print("  No internet passwords found (or access denied)")
        print()
        return
    }
    
    print("  \(String(format: "%-30s", "SERVER"))  \(String(format: "%-25s", "ACCOUNT"))")
    print("  \(String(repeating: "─", count: 60))")
    
    for i in 0..<limit {
        let item = items[i]
        let server = String(item.service.prefix(30))
        let account = String(item.account.prefix(25))
        print("  \(String(format: "%-30s", server))  \(String(format: "%-25s", account))")
    }
    
    if !license.isPremium && items.count > 10 {
        print("\n  ... and \(items.count - 10) more entries")
        printWarning("Full list is Premium: \(DISCORD)")
    }
    
    print("\n  Total internet passwords: \(items.count)\n")
}

func analyzeGenericPasswords(license: License) {
    printHeader("🔐 GENERIC PASSWORDS")
    
    let items = getGenericPasswords(license: license)
    let limit = license.isPremium ? items.count : min(10, items.count)
    
    if items.isEmpty {
        print("  No generic passwords found (or access denied)")
        print()
        return
    }
    
    print("  \(String(format: "%-30s", "SERVICE"))  \(String(format: "%-25s", "ACCOUNT"))")
    print("  \(String(repeating: "─", count: 60))")
    
    for i in 0..<limit {
        let item = items[i]
        let service = String(item.service.prefix(30))
        let account = String(item.account.prefix(25))
        print("  \(String(format: "%-30s", service))  \(String(format: "%-25s", account))")
    }
    
    if !license.isPremium && items.count > 10 {
        print("\n  ... and \(items.count - 10) more entries")
        printWarning("Full list is Premium: \(DISCORD)")
    }
    
    print("\n  Total generic passwords: \(items.count)\n")
}

func analyzeCertificates(license: License) {
    printHeader("📜 CERTIFICATES")
    
    if !license.isPremium {
        printWarning("Certificate analysis is a Premium feature")
        print("  Get keys at: \(DISCORD)\n")
        return
    }
    
    let items = getCertificates(license: license)
    
    if items.isEmpty {
        print("  No certificates found (or access denied)")
        print()
        return
    }
    
    for item in items.prefix(20) {
        print("  📄 \(item.label.isEmpty ? "Unknown" : item.label)")
        print("      Issuer: \(item.service)")
    }
    
    print("\n  Total certificates: \(items.count)\n")
}

func securityAudit(license: License) {
    printHeader("🛡️  KEYCHAIN SECURITY AUDIT")
    
    var score = 0
    var total = 0
    
    // Check 1: Login keychain exists
    total += 1
    let loginKeychain = "\(NSHomeDirectory())/Library/Keychains/login.keychain-db"
    if FileManager.default.fileExists(atPath: loginKeychain) {
        print("  🟢 Login keychain exists")
        score += 1
    } else {
        print("  🔴 Login keychain not found")
    }
    
    // Check 2: System keychain exists
    total += 1
    if FileManager.default.fileExists(atPath: "/Library/Keychains/System.keychain") {
        print("  🟢 System keychain exists")
        score += 1
    } else {
        print("  🔴 System keychain not found")
    }
    
    // Check 3: Keychain auto-lock (simulated check)
    total += 1
    // In real implementation, query SecKeychainCopySettings
    print("  🟡 Auto-lock: Check manually in Keychain Access")
    
    // Check 4: Old/weak credentials
    total += 1
    let passwords = getGenericPasswords(license: license)
    let oldPasswords = passwords.filter { item in
        guard let modDate = item.modificationDate else { return false }
        let yearAgo = Calendar.current.date(byAdding: .year, value: -1, to: Date())!
        return modDate < yearAgo
    }
    
    if oldPasswords.count > 10 {
        print("  🟡 \(oldPasswords.count) passwords older than 1 year")
    } else {
        print("  🟢 Most passwords are recent")
        score += 1
    }
    
    // Premium checks
    if license.isPremium {
        // Check 5: Duplicate accounts
        total += 1
        var accountCounts: [String: Int] = [:]
        for item in passwords {
            accountCounts[item.account, default: 0] += 1
        }
        let duplicates = accountCounts.filter { $0.value > 1 }
        if duplicates.isEmpty {
            print("  🟢 No duplicate account entries")
            score += 1
        } else {
            print("  🟡 \(duplicates.count) accounts have duplicate entries")
        }
    }
    
    let percentage = total > 0 ? (score * 100 / total) : 0
    print("\n  ─────────────────────────────────────────")
    print("  Security Score: \(score)/\(total) (\(percentage)%)")
    
    if percentage >= 80 {
        printSuccess("Keychain security is good")
    } else if percentage >= 50 {
        printWarning("Some security improvements recommended")
    } else {
        printError("Keychain security needs attention")
    }
    print()
}

func keychainStatistics(license: License) {
    printHeader("📊 KEYCHAIN STATISTICS")
    
    let internetPasswords = getInternetPasswords(license: license)
    let genericPasswords = getGenericPasswords(license: license)
    let certificates = getCertificates(license: license)
    
    print("  Item Counts:")
    print("  ─────────────────────────────────")
    print("  🌐 Internet Passwords: \(internetPasswords.count)")
    print("  🔐 Generic Passwords:  \(genericPasswords.count)")
    print("  📜 Certificates:       \(certificates.count)")
    print("  ─────────────────────────────────")
    print("  📦 Total Items:        \(internetPasswords.count + genericPasswords.count + certificates.count)")
    
    if license.isPremium {
        // Service breakdown
        var serviceCounts: [String: Int] = [:]
        for item in genericPasswords {
            let service = item.service.components(separatedBy: ".").last ?? item.service
            serviceCounts[service, default: 0] += 1
        }
        
        print("\n  Top Services:")
        print("  ─────────────────────────────────")
        
        let sorted = serviceCounts.sorted { $0.value > $1.value }
        for (service, count) in sorted.prefix(10) {
            print("    \(String(format: "%-25s", service)): \(count)")
        }
    }
    
    print()
}

// ═══════════════════════════════════════════════════════════════════
// Main Menu
// ═══════════════════════════════════════════════════════════════════

func showMenu(license: inout License) {
    while true {
        let tierBadge = license.isPremium ? "⭐" : "🆓"
        
        print("\n  📋 NullSec macOS Keychain Analyzer \(tierBadge)\n")
        print("  [1] List Keychains")
        print("  [2] Internet Passwords")
        print("  [3] Generic Passwords")
        print("  [4] Certificates (Premium)")
        print("  [5] Security Audit")
        print("  [6] Statistics")
        print("  [7] Full Report")
        print("  [8] Enter License Key")
        print("  [0] Exit")
        print("\n  Select: ", terminator: "")
        
        guard let input = readLine()?.trimmingCharacters(in: .whitespaces) else { break }
        
        switch input {
        case "1":
            listKeychains()
        case "2":
            analyzeInternetPasswords(license: license)
        case "3":
            analyzeGenericPasswords(license: license)
        case "4":
            analyzeCertificates(license: license)
        case "5":
            securityAudit(license: license)
        case "6":
            keychainStatistics(license: license)
        case "7":
            listKeychains()
            keychainStatistics(license: license)
            analyzeInternetPasswords(license: license)
            analyzeGenericPasswords(license: license)
            securityAudit(license: license)
        case "8":
            print("  License key: ", terminator: "")
            if let key = readLine()?.trimmingCharacters(in: .whitespaces) {
                license = License.validate(key)
                if license.valid {
                    printSuccess("License activated: \(license.tier.description)")
                } else {
                    printWarning("Invalid license key")
                }
            }
        case "0":
            return
        default:
            printError("Invalid option")
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Main Entry Point
// ═══════════════════════════════════════════════════════════════════

func main() {
    print("\u{001B}[36m\(BANNER)\u{001B}[0m")
    print("  Version \(VERSION) | \(AUTHOR)")
    print("  🔑 Premium: \(DISCORD)\n")
    
    var license = License()
    
    // Parse command line args
    let args = CommandLine.arguments
    var i = 1
    while i < args.count {
        if args[i] == "-k" || args[i] == "--key", i + 1 < args.count {
            license = License.validate(args[i + 1])
            if license.valid {
                printSuccess("License activated: \(license.tier.description)")
            }
            i += 1
        } else if args[i] == "-h" || args[i] == "--help" {
            print("  Usage: keychain_analyzer [options]\n")
            print("  Options:")
            print("    -k, --key KEY    License key")
            print("    -h, --help       Show help")
            return
        }
        i += 1
    }
    
    #if !os(macOS)
    printError("This tool is designed for macOS only")
    return
    #endif
    
    showMenu(license: &license)
    
    // Footer
    print("\n─────────────────────────────────────────")
    print("  🍎 NullSec macOS Keychain Analyzer")
    print("  🔑 Premium: \(DISCORD)")
    print("  👤 Author: \(AUTHOR)")
    print("─────────────────────────────────────────\n")
}

main()
