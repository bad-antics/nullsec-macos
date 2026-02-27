# ═══════════════════════════════════════════════════════════════════
#  NULLSEC MACOS PERL SECURITY ANALYZER
#  System security analysis and auditing for macOS
#  @author bad-antics | x.com/AnonAntics
# ═══════════════════════════════════════════════════════════════════

#!/usr/bin/env perl

use strict;
use warnings;
use feature qw(say);
use File::Basename;
use File::Find;
use Getopt::Long;
use POSIX qw(strftime);
use Term::ANSIColor;

our $VERSION = "2.0.0";
our $AUTHOR  = "bad-antics";
our $DISCORD = "x.com/AnonAntics";

my $BANNER = <<'BANNER';

╭──────────────────────────────────────────╮
│      🍎 NULLSEC MACOS PERL ANALYZER     │
│      ════════════════════════════       │
│                                          │
│   🔒 System Security Analysis            │
│   🛡️  Configuration Auditing             │
│   📊 Comprehensive Reports               │
│                                          │
│          bad-antics | NullSec            │
╰──────────────────────────────────────────╯

BANNER

# ═══════════════════════════════════════════════════════════════════
# License Management
# ═══════════════════════════════════════════════════════════════════

use constant {
    TIER_FREE       => 0,
    TIER_PREMIUM    => 1,
    TIER_ENTERPRISE => 2,
};

my %license = (
    key   => '',
    tier  => TIER_FREE,
    valid => 0,
);

sub tier_to_string {
    my $tier = shift;
    return "Premium ⭐"    if $tier == TIER_PREMIUM;
    return "Enterprise 💎" if $tier == TIER_ENTERPRISE;
    return "Free";
}

sub validate_license {
    my $key = shift;
    my %result = (key => '', tier => TIER_FREE, valid => 0);
    
    return %result unless defined $key && length($key) == 24;
    return %result unless $key =~ /^NMAC-/;
    
    $result{key}   = $key;
    $result{valid} = 1;
    
    my $type = substr($key, 5, 2);
    if ($type eq 'PR') {
        $result{tier} = TIER_PREMIUM;
    } elsif ($type eq 'EN') {
        $result{tier} = TIER_ENTERPRISE;
    }
    
    return %result;
}

sub is_premium {
    return $license{valid} && $license{tier} != TIER_FREE;
}

# ═══════════════════════════════════════════════════════════════════
# Console Helpers
# ═══════════════════════════════════════════════════════════════════

sub print_success {
    my $msg = shift;
    say colored("✅ $msg", 'green');
}

sub print_error {
    my $msg = shift;
    say colored("❌ $msg", 'red');
}

sub print_warning {
    my $msg = shift;
    say colored("⚠️  $msg", 'yellow');
}

sub print_info {
    my $msg = shift;
    say colored("ℹ️  $msg", 'cyan');
}

sub print_header {
    my $title = shift;
    say "\n═══════════════════════════════════════════";
    say "  $title";
    say "═══════════════════════════════════════════\n";
}

# ═══════════════════════════════════════════════════════════════════
# System Information
# ═══════════════════════════════════════════════════════════════════

sub get_system_info {
    print_header("🖥️  SYSTEM INFORMATION");
    
    my $hostname = `hostname -s 2>/dev/null` // 'Unknown';
    chomp $hostname;
    
    my $os_version = `sw_vers -productVersion 2>/dev/null` // 'Unknown';
    chomp $os_version;
    
    my $build = `sw_vers -buildVersion 2>/dev/null` // 'Unknown';
    chomp $build;
    
    my $hardware = `system_profiler SPHardwareDataType 2>/dev/null | grep "Model Name"` // '';
    $hardware =~ s/.*Model Name:\s*//;
    chomp $hardware;
    
    my $serial = `system_profiler SPHardwareDataType 2>/dev/null | grep "Serial Number"` // '';
    $serial =~ s/.*Serial Number.*:\s*//;
    chomp $serial;
    
    my $uptime = `uptime 2>/dev/null` // 'Unknown';
    $uptime =~ s/.*up\s+//;
    $uptime =~ s/,\s+\d+ user.*//;
    chomp $uptime;
    
    say "  Hostname:     $hostname";
    say "  macOS:        $os_version ($build)";
    say "  Hardware:     $hardware" if $hardware;
    say "  Serial:       $serial" if $serial;
    say "  Uptime:       $uptime";
    say "";
}

# ═══════════════════════════════════════════════════════════════════
# Security Assessment
# ═══════════════════════════════════════════════════════════════════

sub check_sip_status {
    my $sip = `csrutil status 2>/dev/null` // '';
    if ($sip =~ /enabled/) {
        return { status => 'enabled', secure => 1 };
    } elsif ($sip =~ /disabled/) {
        return { status => 'disabled', secure => 0 };
    }
    return { status => 'unknown', secure => 0 };
}

sub check_gatekeeper {
    my $gk = `spctl --status 2>/dev/null` // '';
    if ($gk =~ /assessments enabled/) {
        return { status => 'enabled', secure => 1 };
    }
    return { status => 'disabled', secure => 0 };
}

sub check_firewall {
    my $fw = `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null` // '';
    if ($fw =~ /enabled/) {
        return { status => 'enabled', secure => 1 };
    }
    return { status => 'disabled', secure => 0 };
}

sub check_filevault {
    my $fv = `fdesetup status 2>/dev/null` // '';
    if ($fv =~ /FileVault is On/) {
        return { status => 'enabled', secure => 1 };
    }
    return { status => 'disabled', secure => 0 };
}

sub check_remote_login {
    my $ssh = `systemsetup -getremotelogin 2>/dev/null` // '';
    if ($ssh =~ /On/) {
        return { status => 'enabled', secure => 0, note => 'SSH is open' };
    }
    return { status => 'disabled', secure => 1 };
}

sub check_remote_desktop {
    my $ard = `defaults read /Library/Preferences/com.apple.RemoteManagement.plist 2>/dev/null` // '';
    if ($ard && $ard !~ /does not exist/) {
        return { status => 'configured', secure => 0 };
    }
    return { status => 'disabled', secure => 1 };
}

sub run_security_check {
    print_header("🔒 SECURITY ASSESSMENT");
    
    my @checks = (
        { name => 'System Integrity Protection (SIP)', check => \&check_sip_status },
        { name => 'Gatekeeper',                       check => \&check_gatekeeper },
        { name => 'Application Firewall',             check => \&check_firewall },
        { name => 'FileVault Encryption',             check => \&check_filevault },
        { name => 'Remote Login (SSH)',               check => \&check_remote_login },
        { name => 'Remote Desktop (ARD)',             check => \&check_remote_desktop },
    );
    
    my $score = 0;
    my $total = scalar @checks;
    
    foreach my $item (@checks) {
        my $result = $item->{check}->();
        my $status_icon = $result->{secure} ? '🟢' : '🔴';
        $score++ if $result->{secure};
        
        printf "  %s %-35s %s", $status_icon, $item->{name}, $result->{status};
        say $result->{note} ? " ($result->{note})" : "";
    }
    
    my $percentage = int(($score / $total) * 100);
    say "\n  ────────────────────────────────────────────";
    say "  Security Score: $score/$total ($percentage%)";
    
    if ($percentage >= 80) {
        print_success("System is well secured");
    } elsif ($percentage >= 50) {
        print_warning("Some security settings need attention");
    } else {
        print_error("Multiple security issues detected");
    }
    
    say "";
}

# ═══════════════════════════════════════════════════════════════════
# User Accounts Analysis
# ═══════════════════════════════════════════════════════════════════

sub analyze_users {
    print_header("👥 USER ACCOUNTS");
    
    my @users = `dscl . -list /Users UniqueID 2>/dev/null`;
    
    say "  Admin Users:";
    my @admins = `dscl . -read /Groups/admin GroupMembership 2>/dev/null`;
    foreach my $line (@admins) {
        if ($line =~ /GroupMembership:\s*(.+)/) {
            my @members = split /\s+/, $1;
            foreach my $admin (@members) {
                say "    👤 $admin";
            }
        }
    }
    
    say "\n  Standard Users (UID >= 500):";
    my $count = 0;
    foreach my $user (@users) {
        if ($user =~ /^(\S+)\s+(\d+)/) {
            my ($name, $uid) = ($1, $2);
            if ($uid >= 500 && $name !~ /^_/) {
                say "    👤 $name (UID: $uid)";
                $count++;
            }
        }
    }
    
    say "\n  Total user accounts: $count";
    say "";
}

# ═══════════════════════════════════════════════════════════════════
# Launch Items Analysis
# ═══════════════════════════════════════════════════════════════════

sub analyze_launch_items {
    print_header("🚀 LAUNCH ITEMS");
    
    my @locations = (
        { path => '/Library/LaunchAgents',       type => 'System Agent' },
        { path => '/Library/LaunchDaemons',      type => 'System Daemon' },
        { path => "$ENV{HOME}/Library/LaunchAgents", type => 'User Agent' },
    );
    
    my $total = 0;
    
    foreach my $loc (@locations) {
        next unless -d $loc->{path};
        
        say "  📁 $loc->{type}: $loc->{path}";
        
        opendir(my $dh, $loc->{path}) or next;
        my @plists = grep { /\.plist$/ } readdir($dh);
        closedir($dh);
        
        foreach my $plist (@plists) {
            my $filepath = "$loc->{path}/$plist";
            my $label = `defaults read "$filepath" Label 2>/dev/null` // '';
            chomp $label;
            $label = $plist unless $label;
            $label =~ s/\.plist$//;
            
            my $program = `defaults read "$filepath" Program 2>/dev/null` // '';
            chomp $program;
            
            if ($program) {
                say "     • $label";
                say "       → $program";
            } else {
                say "     • $label";
            }
            $total++;
        }
        say "";
    }
    
    say "  Total launch items: $total";
    say "";
}

# ═══════════════════════════════════════════════════════════════════
# Network Connections
# ═══════════════════════════════════════════════════════════════════

sub analyze_network {
    print_header("📡 NETWORK CONNECTIONS");
    
    my @connections = `lsof -i -P 2>/dev/null | grep -E "LISTEN|ESTABLISHED"`;
    
    my %listening;
    my %established;
    
    foreach my $conn (@connections) {
        chomp $conn;
        my @parts = split /\s+/, $conn;
        next unless @parts >= 9;
        
        my ($cmd, $pid, $user) = @parts[0, 1, 2];
        my $status = $parts[-1];
        my $address = $parts[8];
        
        if ($status eq 'LISTEN' || $status eq '(LISTEN)') {
            $listening{$address} = { cmd => $cmd, pid => $pid, user => $user };
        } elsif ($status eq 'ESTABLISHED' || $status eq '(ESTABLISHED)') {
            $established{$address} = { cmd => $cmd, pid => $pid, user => $user };
        }
    }
    
    say "  Listening Services:";
    say "  ─────────────────────────────────────────────────";
    
    foreach my $addr (sort keys %listening) {
        my $info = $listening{$addr};
        printf "  %-25s %-15s PID: %s\n", $addr, $info->{cmd}, $info->{pid};
    }
    
    if (is_premium()) {
        say "\n  Established Connections:";
        say "  ─────────────────────────────────────────────────";
        
        foreach my $addr (sort keys %established) {
            my $info = $established{$addr};
            printf "  %-25s %-15s PID: %s\n", $addr, $info->{cmd}, $info->{pid};
        }
    } else {
        say "\n  Established connections: " . scalar(keys %established);
        print_warning("Full connection list is a Premium feature - $DISCORD");
    }
    
    say "";
}

# ═══════════════════════════════════════════════════════════════════
# Installed Applications
# ═══════════════════════════════════════════════════════════════════

sub analyze_applications {
    print_header("📦 INSTALLED APPLICATIONS");
    
    my @app_dirs = ('/Applications', "$ENV{HOME}/Applications");
    my @apps;
    
    foreach my $dir (@app_dirs) {
        next unless -d $dir;
        
        opendir(my $dh, $dir) or next;
        my @entries = grep { /\.app$/ } readdir($dh);
        closedir($dh);
        
        foreach my $app (@entries) {
            my $plist = "$dir/$app/Contents/Info.plist";
            next unless -f $plist;
            
            my $name = $app;
            $name =~ s/\.app$//;
            
            my $version = `defaults read "$plist" CFBundleShortVersionString 2>/dev/null` // '';
            chomp $version;
            
            my $id = `defaults read "$plist" CFBundleIdentifier 2>/dev/null` // '';
            chomp $id;
            
            push @apps, { name => $name, version => $version, id => $id };
        }
    }
    
    # Sort alphabetically
    @apps = sort { lc($a->{name}) cmp lc($b->{name}) } @apps;
    
    my $limit = is_premium() ? scalar @apps : 25;
    
    say "  Application Name                      Version";
    say "  ─────────────────────────────────────────────────";
    
    for (my $i = 0; $i < $limit && $i < @apps; $i++) {
        printf "  %-40s %s\n", $apps[$i]->{name}, $apps[$i]->{version};
    }
    
    if (!is_premium() && @apps > 25) {
        say "\n  ... and " . (@apps - 25) . " more applications";
        print_warning("Full list is a Premium feature - $DISCORD");
    }
    
    say "\n  Total applications: " . scalar @apps;
    say "";
}

# ═══════════════════════════════════════════════════════════════════
# Browser Extensions (Premium)
# ═══════════════════════════════════════════════════════════════════

sub analyze_browser_extensions {
    print_header("🌐 BROWSER EXTENSIONS");
    
    unless (is_premium()) {
        print_warning("Browser extension analysis is a Premium feature");
        say "  Get license keys at: $DISCORD\n";
        return;
    }
    
    # Safari Extensions
    say "  Safari Extensions:";
    my $safari_ext = "$ENV{HOME}/Library/Safari/Extensions";
    if (-d $safari_ext) {
        opendir(my $dh, $safari_ext) or return;
        my @exts = grep { /\.safariextz$/ } readdir($dh);
        closedir($dh);
        
        foreach my $ext (@exts) {
            $ext =~ s/\.safariextz$//;
            say "    • $ext";
        }
    } else {
        say "    (No extensions found)";
    }
    
    # Chrome Extensions
    say "\n  Chrome Extensions:";
    my $chrome_ext = "$ENV{HOME}/Library/Application Support/Google/Chrome/Default/Extensions";
    if (-d $chrome_ext) {
        opendir(my $dh, $chrome_ext) or return;
        my @exts = grep { /^[a-z]/ } readdir($dh);
        closedir($dh);
        
        foreach my $ext (@exts) {
            say "    • $ext";
        }
    } else {
        say "    (Chrome not installed or no extensions)";
    }
    
    say "";
}

# ═══════════════════════════════════════════════════════════════════
# Main Menu
# ═══════════════════════════════════════════════════════════════════

sub show_menu {
    while (1) {
        my $tier_badge = is_premium() ? "⭐" : "🆓";
        
        say "\n  📋 NullSec macOS Perl Analyzer $tier_badge\n";
        say "  [1] System Information";
        say "  [2] Security Assessment";
        say "  [3] User Accounts";
        say "  [4] Launch Items";
        say "  [5] Network Connections";
        say "  [6] Installed Applications";
        say "  [7] Browser Extensions (Premium)";
        say "  [8] Full Report";
        say "  [9] Enter License Key";
        say "  [0] Exit\n";
        
        print "  Select: ";
        my $choice = <STDIN>;
        chomp $choice;
        
        if ($choice eq '1') {
            get_system_info();
        } elsif ($choice eq '2') {
            run_security_check();
        } elsif ($choice eq '3') {
            analyze_users();
        } elsif ($choice eq '4') {
            analyze_launch_items();
        } elsif ($choice eq '5') {
            analyze_network();
        } elsif ($choice eq '6') {
            analyze_applications();
        } elsif ($choice eq '7') {
            analyze_browser_extensions();
        } elsif ($choice eq '8') {
            get_system_info();
            run_security_check();
            analyze_users();
            analyze_launch_items();
            analyze_network();
            analyze_applications();
            analyze_browser_extensions() if is_premium();
        } elsif ($choice eq '9') {
            print "  License key: ";
            my $key = <STDIN>;
            chomp $key;
            %license = validate_license($key);
            if ($license{valid}) {
                print_success("License activated: " . tier_to_string($license{tier}));
            } else {
                print_warning("Invalid license key");
            }
        } elsif ($choice eq '0') {
            last;
        } else {
            print_error("Invalid option");
        }
    }
}

# ═══════════════════════════════════════════════════════════════════
# Main Entry Point
# ═══════════════════════════════════════════════════════════════════

sub main {
    print colored($BANNER, 'cyan');
    say "  Version $VERSION | $AUTHOR";
    say "  🔑 Premium: $DISCORD\n";
    
    # Parse command line
    my $key = '';
    my $report = 0;
    my $help = 0;
    
    GetOptions(
        'key=s'  => \$key,
        'report' => \$report,
        'help'   => \$help,
    );
    
    if ($help) {
        say "  Usage: $0 [options]\n";
        say "  Options:";
        say "    --key KEY    License key";
        say "    --report     Generate full report";
        say "    --help       Show this help";
        exit 0;
    }
    
    if ($key) {
        %license = validate_license($key);
        if ($license{valid}) {
            print_success("License activated: " . tier_to_string($license{tier}));
        }
    }
    
    # Check if running on macOS
    unless ($^O eq 'darwin') {
        print_error("This tool is designed for macOS only");
        exit 1;
    }
    
    if ($report) {
        get_system_info();
        run_security_check();
        analyze_users();
        analyze_launch_items();
        analyze_network();
        analyze_applications();
        analyze_browser_extensions() if is_premium();
    } else {
        show_menu();
    }
    
    # Footer
    say "\n─────────────────────────────────────────";
    say "  🍎 NullSec macOS Perl Analyzer";
    say "  🔑 Premium: $DISCORD";
    say "  👤 Author: $AUTHOR";
    say "─────────────────────────────────────────\n";
}

main();
