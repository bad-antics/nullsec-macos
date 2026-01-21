# NullSec macOS Security Suite

```
╭──────────────────────────────────────────╮
│        🍎 NULLSEC MACOS TOOLKIT          │
│       ════════════════════════════       │
│                                          │
│   🔧 Native macOS Security Tools         │
│   📡 Swift • Objective-C • AppleScript   │
│   💾 System Analysis & Hardening         │
│                                          │
│            @AnonAntics | NullSec         │
╰──────────────────────────────────────────╯
```

## Overview

NullSec macOS is an exclusive security toolkit built specifically for Apple macOS systems using native languages and APIs that provide deep system access unavailable on other platforms.

## Languages Used

| Language | Purpose | Why |
|----------|---------|-----|
| **Swift** | Main toolkit | Native Apple language with full system API access |
| **Objective-C** | Low-level tools | Direct access to macOS internals and legacy APIs |
| **AppleScript** | Automation | macOS-specific automation and app control |

## Features

### 🔐 Security Analysis
- System Integrity Protection (SIP) status checker
- Gatekeeper bypass detection
- Keychain analyzer
- FileVault encryption scanner
- XProtect signature checker

### 🛡️ Network Security
- Firewall rule manager
- Network extension analyzer
- Little Snitch rule auditor
- DNS traffic monitor
- VPN configuration inspector

### 💻 System Hardening
- Privacy permission auditor
- TCC database analyzer
- LaunchDaemon/LaunchAgent scanner
- Kernel extension inspector
- Application sandbox checker

### 🔍 Forensics Tools
- Spotlight metadata extractor
- Time Machine backup analyzer
- APFS snapshot browser
- iCloud data extractor (Premium)
- Safari history forensics (Premium)

### ⚙️ Automation
- AppleScript security macros
- Shortcuts integration
- Automator workflow tools

## Installation

### Requirements
- macOS 12.0+ (Monterey or later)
- Xcode Command Line Tools
- Admin privileges for some features

### Quick Install
```bash
# Clone the repository
git clone https://github.com/bad-antics/nullsec-macos.git
cd nullsec-macos

# Build with Swift
swift build -c release

# Or use the install script
./scripts/install.sh
```

## Usage

### Command Line
```bash
# Run main toolkit
nullsec-macos

# Specific tools
nullsec-macos --sip-check
nullsec-macos --keychain-audit
nullsec-macos --network-scan
nullsec-macos --forensics
```

### Swift Library
```swift
import NullSecMac

let toolkit = NullSecToolkit()
let sipStatus = toolkit.checkSIP()
let keychainItems = toolkit.auditKeychain()
```

## Premium Features

Premium features require a license from discord.gg/killers:
- iCloud data extraction
- Full keychain decryption
- Safari/Chrome forensics
- Time Machine remote access
- Network traffic interception

## Directory Structure

```
nullsec-macos/
├── src/
│   ├── swift/           # Main Swift tools
│   ├── objc/            # Objective-C components
│   └── applescript/     # AppleScript automations
├── resources/           # Icons, plists, etc.
├── scripts/             # Shell scripts
└── docs/                # Documentation
```

## Security Notice

⚠️ This toolkit is for authorized security testing only. Unauthorized use may violate computer crime laws. Always obtain proper authorization before testing.

## Credits

- **Author**: @AnonAntics
- **Organization**: NullSec
- **Twitter**: [@AnonAntics](https://twitter.com/AnonAntics)
- **Discord**: [discord.gg/killers](https://discord.gg/killers)

## License

Proprietary - See LICENSE file
Premium features require valid license from discord.gg/killers

---

**NullSec** - *Security Without Limits*
