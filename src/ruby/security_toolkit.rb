#!/usr/bin/env ruby
# ═══════════════════════════════════════════════════════════════════
#  NULLSEC MACOS RUBY SECURITY TOOLKIT
#  Ruby-based macOS security analysis
#  @author bad-antics | x.com/AnonAntics
# ═══════════════════════════════════════════════════════════════════

require 'json'
require 'digest'
require 'base64'
require 'fileutils'
require 'open3'
require 'socket'
require 'time'

VERSION = '2.0.0'
AUTHOR = 'bad-antics'
DISCORD = 'x.com/AnonAntics'

BANNER = <<~BANNER
  ╭──────────────────────────────────────────╮
  │      🍎 NULLSEC MACOS RUBY TOOLKIT       │
  │      ══════════════════════════════      │
  │                                          │
  │   🔧 macOS Security Analysis             │
  │   📡 System Integrity Checking           │
  │   💾 Keychain & TCC Inspection           │
  │                                          │
  │          bad-antics | NullSec            │
  ╰──────────────────────────────────────────╯
BANNER

# ═══════════════════════════════════════════════════════════════════
# Console Helpers
# ═══════════════════════════════════════════════════════════════════

module Console
  def self.success(msg)
    puts "\e[32m✅ #{msg}\e[0m"
  end
  
  def self.error(msg)
    puts "\e[31m❌ #{msg}\e[0m"
  end
  
  def self.warning(msg)
    puts "\e[33m⚠️  #{msg}\e[0m"
  end
  
  def self.info(msg)
    puts "\e[36mℹ️  #{msg}\e[0m"
  end
  
  def self.cyan(msg)
    puts "\e[36m#{msg}\e[0m"
  end
  
  def self.header(title)
    puts "\n═══════════════════════════════════════════"
    puts "  #{title}"
    puts "═══════════════════════════════════════════\n"
  end
end

# ═══════════════════════════════════════════════════════════════════
# License Management
# ═══════════════════════════════════════════════════════════════════

module LicenseTier
  FREE = 'Free'
  PREMIUM = 'Premium ⭐'
  ENTERPRISE = 'Enterprise 💎'
end

class License
  attr_reader :key, :tier, :valid, :expires_at
  
  LICENSE_PATTERN = /^NMAC-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/
  
  def initialize(key = '')
    @key = key
    @tier = LicenseTier::FREE
    @valid = false
    @expires_at = nil
    validate!
  end
  
  def validate!
    return unless @key.match?(LICENSE_PATTERN)
    
    parts = @key.split('-')
    return if parts.length != 5
    
    tier_code = parts[1][0..1]
    @tier = case tier_code
            when 'PR' then LicenseTier::PREMIUM
            when 'EN' then LicenseTier::ENTERPRISE
            else LicenseTier::FREE
            end
    
    # Parse expiry
    expiry_code = parts[4]
    begin
      month = expiry_code[0..1].to_i
      year = 2024 + expiry_code[2..3].to_i
      @expires_at = Time.new(year, month, 1)
    rescue
      @expires_at = Time.now + (365 * 24 * 60 * 60)
    end
    
    @valid = true
  end
  
  def premium?
    @valid && @tier != LicenseTier::FREE
  end
  
  def expired?
    @expires_at && @expires_at < Time.now
  end
end

# ═══════════════════════════════════════════════════════════════════
# System Information
# ═══════════════════════════════════════════════════════════════════

class SystemInfo
  def self.get_macos_version
    output, _ = Open3.capture2('sw_vers -productVersion')
    output.strip
  end
  
  def self.get_build
    output, _ = Open3.capture2('sw_vers -buildVersion')
    output.strip
  end
  
  def self.get_hostname
    Socket.gethostname
  end
  
  def self.get_username
    ENV['USER'] || 'unknown'
  end
  
  def self.get_architecture
    output, _ = Open3.capture2('uname -m')
    output.strip
  end
  
  def self.get_serial
    output, _ = Open3.capture2('ioreg -l | grep IOPlatformSerialNumber')
    match = output.match(/"IOPlatformSerialNumber" = "([^"]+)"/)
    match ? match[1] : 'Unknown'
  end
  
  def self.get_model
    output, _ = Open3.capture2('sysctl -n hw.model')
    output.strip
  end
  
  def self.get_memory
    output, _ = Open3.capture2('sysctl -n hw.memsize')
    bytes = output.strip.to_i
    "#{bytes / (1024 * 1024 * 1024)} GB"
  end
  
  def self.display
    Console.header('💻 SYSTEM INFORMATION')
    
    puts "  macOS Version: #{get_macos_version}"
    puts "  Build: #{get_build}"
    puts "  Hostname: #{get_hostname}"
    puts "  Username: #{get_username}"
    puts "  Architecture: #{get_architecture}"
    puts "  Serial: #{get_serial}"
    puts "  Model: #{get_model}"
    puts "  Memory: #{get_memory}"
    puts
  end
end

# ═══════════════════════════════════════════════════════════════════
# Security Checks
# ═══════════════════════════════════════════════════════════════════

class SecurityChecker
  def initialize(license)
    @license = license
  end
  
  def check_sip
    output, _ = Open3.capture2('csrutil status')
    enabled = output.include?('enabled')
    
    if enabled
      Console.success('System Integrity Protection: Enabled')
    else
      Console.warning('System Integrity Protection: Disabled')
    end
    
    enabled
  end
  
  def check_gatekeeper
    output, _ = Open3.capture2('spctl --status')
    enabled = output.include?('enabled')
    
    if enabled
      Console.success('Gatekeeper: Enabled')
    else
      Console.warning('Gatekeeper: Disabled')
    end
    
    enabled
  end
  
  def check_filevault
    output, _ = Open3.capture2('fdesetup status')
    enabled = output.include?('On')
    
    if enabled
      Console.success('FileVault: Enabled')
    else
      Console.warning('FileVault: Disabled')
    end
    
    enabled
  end
  
  def check_firewall
    output, _ = Open3.capture2('/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate')
    enabled = output.include?('enabled')
    
    if enabled
      Console.success('Firewall: Enabled')
    else
      Console.warning('Firewall: Disabled')
    end
    
    enabled
  end
  
  def check_xprotect
    xprotect_path = '/Library/Apple/System/Library/CoreServices/XProtect.bundle'
    exists = File.exist?(xprotect_path)
    
    if exists
      Console.success('XProtect: Present')
      
      # Get version
      plist_path = "#{xprotect_path}/Contents/Info.plist"
      if File.exist?(plist_path)
        output, _ = Open3.capture2("defaults read '#{plist_path}' CFBundleShortVersionString 2>/dev/null")
        puts "       Version: #{output.strip}" unless output.strip.empty?
      end
    else
      Console.warning('XProtect: Not found')
    end
    
    exists
  end
  
  def check_mrt
    mrt_path = '/Library/Apple/System/Library/CoreServices/MRT.app'
    exists = File.exist?(mrt_path)
    
    if exists
      Console.success('MRT (Malware Removal Tool): Present')
    else
      Console.warning('MRT: Not found')
    end
    
    exists
  end
  
  def run_all
    Console.header('🔒 SECURITY STATUS')
    
    results = {
      sip: check_sip,
      gatekeeper: check_gatekeeper,
      filevault: check_filevault,
      firewall: check_firewall,
      xprotect: check_xprotect,
      mrt: check_mrt
    }
    
    # Calculate score
    score = results.values.count(true) * 100 / results.length
    
    puts
    puts "  📊 Security Score: #{score}/100"
    
    risk_level = case score
                 when 80..100 then '🟢 Low Risk'
                 when 60..79 then '🟡 Medium Risk'
                 when 40..59 then '🟠 High Risk'
                 else '🔴 Critical Risk'
                 end
    
    puts "  Risk Level: #{risk_level}"
    puts
    
    results
  end
end

# ═══════════════════════════════════════════════════════════════════
# Launch Agents/Daemons Analysis
# ═══════════════════════════════════════════════════════════════════

class LaunchItemsAnalyzer
  LAUNCH_PATHS = [
    '/Library/LaunchAgents',
    '/Library/LaunchDaemons',
    "#{ENV['HOME']}/Library/LaunchAgents",
    '/System/Library/LaunchAgents',
    '/System/Library/LaunchDaemons'
  ]
  
  def initialize(license)
    @license = license
  end
  
  def analyze
    Console.header('🚀 LAUNCH ITEMS ANALYSIS')
    
    items = []
    
    LAUNCH_PATHS.each do |path|
      next unless File.directory?(path)
      
      puts "  📂 #{path}"
      
      Dir.glob("#{path}/*.plist").each do |plist|
        name = File.basename(plist, '.plist')
        
        # Skip Apple items for cleaner output
        next if name.start_with?('com.apple.')
        
        info = analyze_plist(plist)
        items << info
        
        puts "      • #{name}"
        puts "        Program: #{info[:program]}" if info[:program]
      end
      puts
    end
    
    puts "  Total non-Apple items: #{items.length}"
    puts
    
    items
  end
  
  private
  
  def analyze_plist(path)
    output, _ = Open3.capture2("defaults read '#{path}' 2>/dev/null")
    
    program = nil
    if output.include?('Program')
      match = output.match(/Program = "?([^";]+)"?;/)
      program = match[1] if match
    end
    
    {
      path: path,
      name: File.basename(path, '.plist'),
      program: program
    }
  end
end

# ═══════════════════════════════════════════════════════════════════
# TCC Database Analysis (Premium)
# ═══════════════════════════════════════════════════════════════════

class TCCAnalyzer
  TCC_DB_PATHS = [
    '/Library/Application Support/com.apple.TCC/TCC.db',
    "#{ENV['HOME']}/Library/Application Support/com.apple.TCC/TCC.db"
  ]
  
  def initialize(license)
    @license = license
  end
  
  def analyze
    Console.header('🔐 TCC DATABASE ANALYSIS')
    
    unless @license.premium?
      Console.warning("Premium feature - Get keys at #{DISCORD}")
      puts
      return nil
    end
    
    TCC_DB_PATHS.each do |db_path|
      next unless File.exist?(db_path)
      
      puts "  📂 #{db_path}"
      puts
      
      # Try to read TCC database
      query = "SELECT client, service, auth_value FROM access LIMIT 20;"
      output, status = Open3.capture2("sqlite3 '#{db_path}' '#{query}' 2>/dev/null")
      
      if status.success? && !output.strip.empty?
        puts "  Client | Service | Auth"
        puts "  " + "-" * 50
        
        output.each_line do |line|
          parts = line.strip.split('|')
          puts "  #{parts[0]} | #{parts[1]} | #{parts[2]}"
        end
      else
        Console.warning("Cannot read TCC database (SIP protection)")
        puts "       Run with elevated privileges or disable SIP"
      end
      puts
    end
  end
end

# ═══════════════════════════════════════════════════════════════════
# Keychain Analysis (Premium)
# ═══════════════════════════════════════════════════════════════════

class KeychainAnalyzer
  def initialize(license)
    @license = license
  end
  
  def analyze
    Console.header('🔑 KEYCHAIN ANALYSIS')
    
    unless @license.premium?
      Console.warning("Premium feature - Get keys at #{DISCORD}")
      puts
      return nil
    end
    
    # List keychains
    output, _ = Open3.capture2('security list-keychains')
    keychains = output.scan(/"([^"]+)"/).flatten
    
    puts "  Configured Keychains:"
    keychains.each do |kc|
      puts "    • #{kc}"
    end
    puts
    
    # Count items in default keychain
    output, _ = Open3.capture2('security dump-keychain 2>/dev/null | grep -c "class:"')
    count = output.strip.to_i
    
    puts "  Default Keychain Items: ~#{count}"
    puts
    
    # Check for certificates
    output, _ = Open3.capture2('security find-certificate -a 2>/dev/null | grep -c "keychain:"')
    cert_count = output.strip.to_i
    
    puts "  Certificates: ~#{cert_count}"
    puts
    
    { keychains: keychains, item_count: count, cert_count: cert_count }
  end
end

# ═══════════════════════════════════════════════════════════════════
# Network Analysis
# ═══════════════════════════════════════════════════════════════════

class NetworkAnalyzer
  def initialize(license)
    @license = license
  end
  
  def analyze
    Console.header('🌐 NETWORK ANALYSIS')
    
    # Get network interfaces
    output, _ = Open3.capture2('ifconfig -a')
    
    interfaces = []
    current_if = nil
    
    output.each_line do |line|
      if line =~ /^(\w+):/
        current_if = { name: $1, ips: [] }
        interfaces << current_if
      elsif current_if && line =~ /inet (\d+\.\d+\.\d+\.\d+)/
        current_if[:ips] << $1
      end
    end
    
    puts "  Network Interfaces:"
    interfaces.each do |iface|
      next if iface[:ips].empty?
      puts "    #{iface[:name]}: #{iface[:ips].join(', ')}"
    end
    puts
    
    # Active connections
    output, _ = Open3.capture2('netstat -an | grep ESTABLISHED | head -20')
    connections = output.lines.length
    
    puts "  Established Connections: #{connections}"
    
    if @license.premium?
      puts
      puts "  Recent Connections:"
      output.each_line.first(10).each do |line|
        puts "    #{line.strip}"
      end
    end
    puts
    
    { interfaces: interfaces, connections: connections }
  end
end

# ═══════════════════════════════════════════════════════════════════
# Main Menu
# ═══════════════════════════════════════════════════════════════════

class Menu
  def initialize
    @license = License.new
    @security = SecurityChecker.new(@license)
    @launch_items = LaunchItemsAnalyzer.new(@license)
    @tcc = TCCAnalyzer.new(@license)
    @keychain = KeychainAnalyzer.new(@license)
    @network = NetworkAnalyzer.new(@license)
  end
  
  def set_license(key)
    @license = License.new(key)
    
    if @license.valid
      Console.success("License activated: #{@license.tier}")
    else
      Console.warning("Invalid license key")
    end
    
    # Update analyzers
    @security = SecurityChecker.new(@license)
    @launch_items = LaunchItemsAnalyzer.new(@license)
    @tcc = TCCAnalyzer.new(@license)
    @keychain = KeychainAnalyzer.new(@license)
    @network = NetworkAnalyzer.new(@license)
  end
  
  def show
    loop do
      tier_badge = @license.premium? ? '⭐' : '🆓'
      
      puts "\n  📋 NullSec macOS Ruby Menu #{tier_badge}\n"
      puts "  [1] System Information"
      puts "  [2] Security Status"
      puts "  [3] Launch Items"
      puts "  [4] TCC Database (Premium)"
      puts "  [5] Keychain Analysis (Premium)"
      puts "  [6] Network Analysis"
      puts "  [7] Full Scan"
      puts "  [8] Enter License Key"
      puts "  [0] Exit"
      puts
      
      print "  Select: "
      choice = gets&.chomp
      
      case choice
      when '1' then SystemInfo.display
      when '2' then @security.run_all
      when '3' then @launch_items.analyze
      when '4' then @tcc.analyze
      when '5' then @keychain.analyze
      when '6' then @network.analyze
      when '7'
        SystemInfo.display
        @security.run_all
        @launch_items.analyze
        @network.analyze
        @tcc.analyze if @license.premium?
        @keychain.analyze if @license.premium?
      when '8'
        print "  License key: "
        key = gets&.chomp
        set_license(key)
      when '0'
        break
      else
        Console.error("Invalid option")
      end
    end
  end
end

# ═══════════════════════════════════════════════════════════════════
# Main Entry Point
# ═══════════════════════════════════════════════════════════════════

def main
  Console.cyan(BANNER)
  puts "  Version #{VERSION} | #{AUTHOR}"
  puts "  🔑 Premium: #{DISCORD}\n"
  
  menu = Menu.new
  
  # Check for command line args
  if ARGV.include?('-k') || ARGV.include?('--key')
    idx = ARGV.index('-k') || ARGV.index('--key')
    if ARGV[idx + 1]
      menu.set_license(ARGV[idx + 1])
    end
  elsif ARGV.include?('-h') || ARGV.include?('--help')
    puts "  Usage: ruby security_toolkit.rb [options]"
    puts
    puts "  Options:"
    puts "    -k, --key KEY    License key"
    puts "    -h, --help       Show help"
    puts "    -v, --version    Show version"
    exit 0
  elsif ARGV.include?('-v') || ARGV.include?('--version')
    puts "  NullSec macOS Ruby Toolkit v#{VERSION}"
    exit 0
  end
  
  menu.show
  
  # Footer
  puts "\n─────────────────────────────────────────"
  puts "  🍎 NullSec macOS Ruby Toolkit"
  puts "  🔑 Premium: #{DISCORD}"
  puts "  👤 Author: #{AUTHOR}"
  puts "─────────────────────────────────────────\n"
end

main if __FILE__ == $0
