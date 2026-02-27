-- NullSec macOS AppleScript Automation
-- @author bad-antics
-- @twitter x.com/AnonAntics

-- ╭──────────────────────────────────────────╮
-- │     🍎 NULLSEC MACOS AUTOMATION          │
-- │       ════════════════════════════       │
-- │                                          │
-- │   🔧 Native macOS Automation             │
-- │   📡 Security Scripts & Macros           │
-- │   💾 System Control via AppleScript      │
-- │                                          │
-- │            bad-antics | NullSec         │
-- ╰──────────────────────────────────────────╯

property VERSION : "2.0.0"
property AUTHOR : "bad-antics"
property DISCORD : "x.com/AnonAntics"

-- ═══════════════════════════════════════════
-- SYSTEM INFORMATION
-- ═══════════════════════════════════════════

on getSystemInfo()
	set sysInfo to {}
	
	-- Get macOS version
	set osVersion to system version of (system info)
	set end of sysInfo to "macOS Version: " & osVersion
	
	-- Get computer name
	set compName to computer name of (system info)
	set end of sysInfo to "Computer Name: " & compName
	
	-- Get user name
	set userName to short user name of (system info)
	set end of sysInfo to "User: " & userName
	
	-- Get home directory
	set homeDir to path to home folder as text
	set end of sysInfo to "Home: " & homeDir
	
	-- Get CPU
	try
		set cpuInfo to do shell script "sysctl -n machdep.cpu.brand_string"
		set end of sysInfo to "CPU: " & cpuInfo
	end try
	
	-- Get memory
	try
		set memInfo to do shell script "sysctl -n hw.memsize"
		set memGB to (memInfo as number) / 1024 / 1024 / 1024
		set end of sysInfo to "RAM: " & (round memGB) & " GB"
	end try
	
	return sysInfo
end getSystemInfo

-- ═══════════════════════════════════════════
-- SECURITY CHECKS
-- ═══════════════════════════════════════════

on checkFirewall()
	try
		set fwStatus to do shell script "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"
		if fwStatus contains "enabled" then
			return "Firewall: ✅ Enabled"
		else
			return "Firewall: ⚠️ Disabled"
		end if
	on error
		return "Firewall: ❓ Unknown"
	end try
end checkFirewall

on checkSIP()
	try
		set sipStatus to do shell script "csrutil status"
		if sipStatus contains "enabled" then
			return "SIP: ✅ Enabled"
		else
			return "SIP: ⚠️ Disabled"
		end if
	on error
		return "SIP: ❓ Unknown"
	end try
end checkSIP

on checkFileVault()
	try
		set fvStatus to do shell script "fdesetup status"
		if fvStatus contains "FileVault is On" then
			return "FileVault: ✅ Enabled"
		else
			return "FileVault: ⚠️ Disabled"
		end if
	on error
		return "FileVault: ❓ Unknown"
	end try
end checkFileVault

on checkGatekeeper()
	try
		set gkStatus to do shell script "spctl --status"
		if gkStatus contains "assessments enabled" then
			return "Gatekeeper: ✅ Enabled"
		else
			return "Gatekeeper: ⚠️ Disabled"
		end if
	on error
		return "Gatekeeper: ❓ Unknown"
	end try
end checkGatekeeper

on getSecurityStatus()
	set secStatus to {}
	set end of secStatus to checkFirewall()
	set end of secStatus to checkSIP()
	set end of secStatus to checkFileVault()
	set end of secStatus to checkGatekeeper()
	return secStatus
end getSecurityStatus

-- ═══════════════════════════════════════════
-- NETWORK UTILITIES
-- ═══════════════════════════════════════════

on getNetworkInfo()
	set netInfo to {}
	
	-- Get current WiFi SSID
	try
		set wifiSSID to do shell script "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I | grep ' SSID:' | cut -d':' -f2 | xargs"
		if wifiSSID is not "" then
			set end of netInfo to "WiFi SSID: " & wifiSSID
		end if
	end try
	
	-- Get local IP
	try
		set localIP to do shell script "ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || echo 'Not connected'"
		set end of netInfo to "Local IP: " & localIP
	end try
	
	-- Get public IP
	try
		set publicIP to do shell script "curl -s ifconfig.me --max-time 5"
		if publicIP is not "" then
			set end of netInfo to "Public IP: " & publicIP
		end if
	end try
	
	-- Get DNS servers
	try
		set dnsServers to do shell script "scutil --dns | grep 'nameserver' | head -3 | awk '{print $3}' | tr '\\n' ', ' | sed 's/,$//'"
		if dnsServers is not "" then
			set end of netInfo to "DNS Servers: " & dnsServers
		end if
	end try
	
	return netInfo
end getNetworkInfo

-- ═══════════════════════════════════════════
-- APPLICATION CONTROL
-- ═══════════════════════════════════════════

on getRunningApps()
	tell application "System Events"
		set appList to name of every process whose background only is false
	end tell
	return appList
end getRunningApps

on quitApp(appName)
	try
		tell application appName to quit
		return "Quit: " & appName
	on error
		return "Failed to quit: " & appName
	end try
end quitApp

on launchApp(appName)
	try
		tell application appName to activate
		return "Launched: " & appName
	on error
		return "Failed to launch: " & appName
	end try
end launchApp

on hideApp(appName)
	try
		tell application "System Events"
			set visible of process appName to false
		end tell
		return "Hidden: " & appName
	on error
		return "Failed to hide: " & appName
	end try
end hideApp

-- ═══════════════════════════════════════════
-- CLIPBOARD UTILITIES
-- ═══════════════════════════════════════════

on getClipboard()
	try
		set clipContent to the clipboard
		return clipContent
	on error
		return "Unable to read clipboard"
	end try
end getClipboard

on setClipboard(content)
	set the clipboard to content
	return "Clipboard set"
end setClipboard

on clearClipboard()
	set the clipboard to ""
	return "Clipboard cleared"
end clearClipboard

-- ═══════════════════════════════════════════
-- FILE UTILITIES
-- ═══════════════════════════════════════════

on getRecentFiles()
	set recentFiles to {}
	try
		set recentFolders to do shell script "ls -lt ~/Documents 2>/dev/null | head -10 | awk '{print $NF}'"
		set recentFiles to paragraphs of recentFolders
	end try
	return recentFiles
end getRecentFiles

on getDownloadsContents()
	set downloads to {}
	try
		set dlFiles to do shell script "ls -lt ~/Downloads 2>/dev/null | head -20 | awk '{print $NF}'"
		set downloads to paragraphs of dlFiles
	end try
	return downloads
end getDownloadsContents

-- ═══════════════════════════════════════════
-- SCREENSHOT UTILITIES
-- ═══════════════════════════════════════════

on takeScreenshot(savePath)
	try
		do shell script "screencapture -x " & quoted form of savePath
		return "Screenshot saved to: " & savePath
	on error
		return "Failed to take screenshot"
	end try
end takeScreenshot

on takeWindowScreenshot(savePath)
	try
		do shell script "screencapture -w " & quoted form of savePath
		return "Window screenshot saved to: " & savePath
	on error
		return "Failed to take screenshot"
	end try
end takeWindowScreenshot

-- ═══════════════════════════════════════════
-- SYSTEM ACTIONS
-- ═══════════════════════════════════════════

on emptyTrash()
	try
		tell application "Finder"
			empty the trash
		end tell
		return "Trash emptied"
	on error
		return "Failed to empty trash"
	end try
end emptyTrash

on lockScreen()
	try
		do shell script "pmset displaysleepnow"
		return "Screen locked"
	on error
		return "Failed to lock screen"
	end try
end lockScreen

on setVolume(level)
	-- level should be 0-100
	set volume output volume level
	return "Volume set to: " & level
end setVolume

on muteVolume()
	set volume output volume 0 with output muted
	return "Volume muted"
end muteVolume

on unmuteVolume()
	set volume without output muted
	return "Volume unmuted"
end unmuteVolume

-- ═══════════════════════════════════════════
-- MAIN DIALOG
-- ═══════════════════════════════════════════

on displayMainMenu()
	set menuOptions to {"System Info", "Security Status", "Network Info", "Running Apps", "Take Screenshot", "Lock Screen", "About"}
	
	set selectedOption to choose from list menuOptions with prompt "NullSec macOS Automation v" & VERSION & return & "bad-antics | x.com/AnonAntics" with title "NullSec macOS" default items {"System Info"}
	
	if selectedOption is false then
		return "Cancelled"
	end if
	
	set selected to item 1 of selectedOption
	
	if selected is "System Info" then
		set info to getSystemInfo()
		set infoText to ""
		repeat with i in info
			set infoText to infoText & i & return
		end repeat
		display dialog infoText with title "System Info" buttons {"OK"} default button "OK"
		
	else if selected is "Security Status" then
		set status to getSecurityStatus()
		set statusText to ""
		repeat with s in status
			set statusText to statusText & s & return
		end repeat
		display dialog statusText with title "Security Status" buttons {"OK"} default button "OK"
		
	else if selected is "Network Info" then
		set netInfo to getNetworkInfo()
		set netText to ""
		repeat with n in netInfo
			set netText to netText & n & return
		end repeat
		display dialog netText with title "Network Info" buttons {"OK"} default button "OK"
		
	else if selected is "Running Apps" then
		set apps to getRunningApps()
		set appText to "Running Applications:" & return & return
		repeat with a in apps
			set appText to appText & "• " & a & return
		end repeat
		display dialog appText with title "Running Apps" buttons {"OK"} default button "OK"
		
	else if selected is "Take Screenshot" then
		set savePath to POSIX path of (path to desktop) & "nullsec_screenshot_" & (do shell script "date +%Y%m%d_%H%M%S") & ".png"
		set result to takeScreenshot(savePath)
		display dialog result with title "Screenshot" buttons {"OK"} default button "OK"
		
	else if selected is "Lock Screen" then
		set result to lockScreen()
		
	else if selected is "About" then
		display dialog "NullSec macOS Automation" & return & "Version: " & VERSION & return & return & "Author: " & AUTHOR & return & "Discord: " & DISCORD & return & return & "Premium features at x.com/AnonAntics" with title "About NullSec" buttons {"OK"} default button "OK"
	end if
	
	return selected
end displayMainMenu

-- Run main menu
displayMainMenu()
