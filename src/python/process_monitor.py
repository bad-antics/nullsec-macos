#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════
 NULLSEC MACOS PYTHON PROCESS MONITOR
 Advanced process monitoring and analysis for macOS
 @author bad-antics | discord.gg/killers
═══════════════════════════════════════════════════════════════════
"""

import os
import sys
import time
import subprocess
import re
import argparse
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

VERSION = "2.0.0"
AUTHOR = "bad-antics"
DISCORD = "discord.gg/killers"

BANNER = """
╭──────────────────────────────────────────╮
│    🍎 NULLSEC MACOS PROCESS MONITOR     │
│    ════════════════════════════════     │
│                                          │
│   📊 Real-time Process Monitoring        │
│   🔍 Resource Usage Analysis             │
│   ⚡ Performance Tracking                │
│                                          │
│          bad-antics | NullSec            │
╰──────────────────────────────────────────╯
"""

# ═══════════════════════════════════════════════════════════════════
# License Management
# ═══════════════════════════════════════════════════════════════════

class LicenseTier:
    FREE = 0
    PREMIUM = 1
    ENTERPRISE = 2

class License:
    def __init__(self, key: str = ""):
        self.key = key
        self.tier = LicenseTier.FREE
        self.valid = False
        
        if self._validate(key):
            self.valid = True
            self.key = key
    
    def _validate(self, key: str) -> bool:
        if not key or len(key) != 24:
            return False
        
        if not key.startswith("NMAC-"):
            return False
        
        type_code = key[5:7]
        if type_code == "PR":
            self.tier = LicenseTier.PREMIUM
        elif type_code == "EN":
            self.tier = LicenseTier.ENTERPRISE
        else:
            self.tier = LicenseTier.FREE
        
        return True
    
    @property
    def tier_name(self) -> str:
        if self.tier == LicenseTier.PREMIUM:
            return "Premium ⭐"
        elif self.tier == LicenseTier.ENTERPRISE:
            return "Enterprise 💎"
        return "Free"
    
    @property
    def is_premium(self) -> bool:
        return self.valid and self.tier != LicenseTier.FREE


# ═══════════════════════════════════════════════════════════════════
# Console Helpers
# ═══════════════════════════════════════════════════════════════════

class Colors:
    RESET = "\033[0m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    BOLD = "\033[1m"

def print_success(msg: str):
    print(f"{Colors.GREEN}✅ {msg}{Colors.RESET}")

def print_error(msg: str):
    print(f"{Colors.RED}❌ {msg}{Colors.RESET}")

def print_warning(msg: str):
    print(f"{Colors.YELLOW}⚠️  {msg}{Colors.RESET}")

def print_info(msg: str):
    print(f"{Colors.CYAN}ℹ️  {msg}{Colors.RESET}")

def print_header(title: str):
    print("\n═══════════════════════════════════════════")
    print(f"  {title}")
    print("═══════════════════════════════════════════\n")

def clear_screen():
    os.system("clear")


# ═══════════════════════════════════════════════════════════════════
# Process Information
# ═══════════════════════════════════════════════════════════════════

class ProcessInfo:
    def __init__(self):
        self.pid: int = 0
        self.ppid: int = 0
        self.user: str = ""
        self.name: str = ""
        self.cpu: float = 0.0
        self.mem: float = 0.0
        self.vsz: int = 0
        self.rss: int = 0
        self.state: str = ""
        self.started: str = ""
        self.time: str = ""
        self.command: str = ""

def get_processes() -> List[ProcessInfo]:
    """Get list of all running processes."""
    processes = []
    
    try:
        output = subprocess.check_output(
            ["ps", "-axo", "pid,ppid,user,%cpu,%mem,vsz,rss,state,start,time,comm"],
            text=True
        )
        
        lines = output.strip().split("\n")[1:]  # Skip header
        
        for line in lines:
            parts = line.split()
            if len(parts) < 11:
                continue
            
            proc = ProcessInfo()
            proc.pid = int(parts[0])
            proc.ppid = int(parts[1])
            proc.user = parts[2]
            proc.cpu = float(parts[3])
            proc.mem = float(parts[4])
            proc.vsz = int(parts[5])
            proc.rss = int(parts[6])
            proc.state = parts[7]
            proc.started = parts[8]
            proc.time = parts[9]
            proc.name = parts[10]
            proc.command = " ".join(parts[10:])
            
            processes.append(proc)
    
    except Exception as e:
        print_error(f"Error getting processes: {e}")
    
    return processes

def get_process_details(pid: int) -> Optional[Dict]:
    """Get detailed information about a specific process."""
    try:
        # Basic info
        info = subprocess.check_output(
            ["ps", "-p", str(pid), "-o", "pid,ppid,user,%cpu,%mem,vsz,rss,state,start,time,comm"],
            text=True
        ).strip().split("\n")
        
        if len(info) < 2:
            return None
        
        # Full command
        cmd = subprocess.check_output(
            ["ps", "-p", str(pid), "-o", "command="],
            text=True
        ).strip()
        
        # Open files (lsof)
        try:
            open_files = subprocess.check_output(
                ["lsof", "-p", str(pid)],
                text=True,
                stderr=subprocess.DEVNULL
            ).strip().split("\n")[1:11]  # First 10 files
        except:
            open_files = []
        
        # Network connections
        try:
            net_output = subprocess.check_output(
                ["lsof", "-i", "-P", "-n"],
                text=True,
                stderr=subprocess.DEVNULL
            )
            net_conns = [l for l in net_output.split("\n") if str(pid) in l][:5]
        except:
            net_conns = []
        
        parts = info[1].split()
        
        return {
            "pid": int(parts[0]),
            "ppid": int(parts[1]),
            "user": parts[2],
            "cpu": float(parts[3]),
            "mem": float(parts[4]),
            "vsz_kb": int(parts[5]),
            "rss_kb": int(parts[6]),
            "state": parts[7],
            "started": parts[8],
            "time": parts[9],
            "name": parts[10],
            "command": cmd,
            "open_files": open_files,
            "network": net_conns,
        }
    
    except Exception as e:
        return None


# ═══════════════════════════════════════════════════════════════════
# Process Display Functions
# ═══════════════════════════════════════════════════════════════════

def display_top_processes(processes: List[ProcessInfo], sort_by: str = "cpu", limit: int = 20):
    """Display top processes sorted by resource usage."""
    
    if sort_by == "cpu":
        processes.sort(key=lambda p: p.cpu, reverse=True)
        title = "🔥 TOP PROCESSES BY CPU"
    elif sort_by == "mem":
        processes.sort(key=lambda p: p.mem, reverse=True)
        title = "💾 TOP PROCESSES BY MEMORY"
    else:
        processes.sort(key=lambda p: p.pid)
        title = "📋 PROCESSES BY PID"
    
    print_header(title)
    
    print(f"  {'PID':>7}  {'USER':<12}  {'%CPU':>6}  {'%MEM':>6}  {'RSS (MB)':>10}  {'NAME':<25}")
    print("  " + "─" * 75)
    
    for proc in processes[:limit]:
        rss_mb = proc.rss / 1024
        name = proc.name[:25] if len(proc.name) > 25 else proc.name
        print(f"  {proc.pid:>7}  {proc.user:<12}  {proc.cpu:>6.1f}  {proc.mem:>6.1f}  {rss_mb:>10.1f}  {name:<25}")
    
    print()

def display_process_details(pid: int):
    """Display detailed information about a process."""
    
    details = get_process_details(pid)
    
    if not details:
        print_error(f"Process {pid} not found")
        return
    
    print_header(f"📊 PROCESS DETAILS: {details['name']} (PID {pid})")
    
    print(f"  PID:          {details['pid']}")
    print(f"  Parent PID:   {details['ppid']}")
    print(f"  User:         {details['user']}")
    print(f"  State:        {details['state']}")
    print(f"  Started:      {details['started']}")
    print(f"  CPU Time:     {details['time']}")
    print(f"  CPU Usage:    {details['cpu']}%")
    print(f"  Memory:       {details['mem']}%")
    print(f"  VSZ:          {details['vsz_kb'] / 1024:.1f} MB")
    print(f"  RSS:          {details['rss_kb'] / 1024:.1f} MB")
    print(f"\n  Command:\n    {details['command']}")
    
    if details['open_files']:
        print("\n  Open Files (first 10):")
        for f in details['open_files'][:10]:
            print(f"    {f}")
    
    if details['network']:
        print("\n  Network Connections:")
        for conn in details['network']:
            print(f"    {conn}")
    
    print()


# ═══════════════════════════════════════════════════════════════════
# Resource Analysis
# ═══════════════════════════════════════════════════════════════════

def get_system_resources() -> Dict:
    """Get system resource usage."""
    resources = {}
    
    # CPU info
    try:
        cpu_info = subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True).strip()
        cpu_count = int(subprocess.check_output(["sysctl", "-n", "hw.ncpu"], text=True).strip())
        resources["cpu_name"] = cpu_info
        resources["cpu_count"] = cpu_count
    except:
        resources["cpu_name"] = "Unknown"
        resources["cpu_count"] = 0
    
    # Memory info
    try:
        mem_total = int(subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True).strip())
        resources["mem_total_gb"] = mem_total / (1024 ** 3)
        
        # Get memory pressure
        vm_stat = subprocess.check_output(["vm_stat"], text=True)
        
        # Parse vm_stat
        pages = {}
        for line in vm_stat.split("\n"):
            if ":" in line:
                key, value = line.split(":")
                try:
                    pages[key.strip()] = int(value.strip().rstrip("."))
                except:
                    pass
        
        page_size = 4096  # Default page size
        
        free = pages.get("Pages free", 0) * page_size
        active = pages.get("Pages active", 0) * page_size
        inactive = pages.get("Pages inactive", 0) * page_size
        wired = pages.get("Pages wired down", 0) * page_size
        
        resources["mem_free_gb"] = free / (1024 ** 3)
        resources["mem_active_gb"] = active / (1024 ** 3)
        resources["mem_inactive_gb"] = inactive / (1024 ** 3)
        resources["mem_wired_gb"] = wired / (1024 ** 3)
        resources["mem_used_gb"] = (active + wired) / (1024 ** 3)
    except Exception as e:
        resources["mem_total_gb"] = 0
        resources["mem_used_gb"] = 0
    
    # Disk info
    try:
        df_output = subprocess.check_output(["df", "-h", "/"], text=True)
        lines = df_output.strip().split("\n")
        if len(lines) > 1:
            parts = lines[1].split()
            resources["disk_total"] = parts[1]
            resources["disk_used"] = parts[2]
            resources["disk_free"] = parts[3]
            resources["disk_percent"] = parts[4]
    except:
        pass
    
    return resources

def display_system_resources():
    """Display system resource usage."""
    print_header("🖥️  SYSTEM RESOURCES")
    
    resources = get_system_resources()
    
    print(f"  CPU:        {resources.get('cpu_name', 'Unknown')}")
    print(f"  Cores:      {resources.get('cpu_count', 'Unknown')}")
    
    print(f"\n  Memory:")
    print(f"    Total:    {resources.get('mem_total_gb', 0):.1f} GB")
    print(f"    Used:     {resources.get('mem_used_gb', 0):.1f} GB")
    print(f"    Free:     {resources.get('mem_free_gb', 0):.1f} GB")
    print(f"    Active:   {resources.get('mem_active_gb', 0):.1f} GB")
    print(f"    Wired:    {resources.get('mem_wired_gb', 0):.1f} GB")
    
    if "disk_total" in resources:
        print(f"\n  Disk (/):")
        print(f"    Total:    {resources.get('disk_total')}")
        print(f"    Used:     {resources.get('disk_used')} ({resources.get('disk_percent')})")
        print(f"    Free:     {resources.get('disk_free')}")
    
    print()


# ═══════════════════════════════════════════════════════════════════
# Process Tree
# ═══════════════════════════════════════════════════════════════════

def build_process_tree(processes: List[ProcessInfo]) -> Dict[int, List[ProcessInfo]]:
    """Build a tree of processes by parent-child relationship."""
    tree = defaultdict(list)
    
    for proc in processes:
        tree[proc.ppid].append(proc)
    
    return tree

def display_process_tree(license: License):
    """Display process hierarchy."""
    
    if not license.is_premium:
        print_warning(f"Process tree is a Premium feature. Get keys at {DISCORD}")
        print()
        return
    
    print_header("🌳 PROCESS TREE")
    
    processes = get_processes()
    tree = build_process_tree(processes)
    
    # Find root processes (PPID 0 or 1)
    roots = [p for p in processes if p.ppid == 0 or p.ppid == 1]
    
    def print_tree(proc: ProcessInfo, indent: int = 0):
        prefix = "  " + "│  " * indent + "├─ " if indent > 0 else "  "
        print(f"{prefix}{proc.name} (PID: {proc.pid}, CPU: {proc.cpu}%, MEM: {proc.mem}%)")
        
        if indent < 3:  # Limit depth
            children = tree.get(proc.pid, [])
            for child in children[:5]:  # Limit children
                print_tree(child, indent + 1)
    
    for root in roots[:10]:  # Limit roots
        print_tree(root)
    
    print()


# ═══════════════════════════════════════════════════════════════════
# Live Monitor
# ═══════════════════════════════════════════════════════════════════

def live_monitor(license: License, interval: int = 2):
    """Real-time process monitoring."""
    
    print_info("Starting live monitor (Press Ctrl+C to stop)")
    print()
    
    limit = 10 if not license.is_premium else 20
    
    try:
        while True:
            clear_screen()
            
            print(f"{Colors.CYAN}{BANNER}{Colors.RESET}")
            print(f"  Live Monitor | {datetime.now().strftime('%H:%M:%S')} | Refreshing every {interval}s")
            print(f"  {'Premium' if license.is_premium else 'Free'} Edition | Press Ctrl+C to exit\n")
            
            # Get resources
            resources = get_system_resources()
            
            # Quick resource summary
            mem_percent = (resources.get('mem_used_gb', 0) / resources.get('mem_total_gb', 1)) * 100
            print(f"  Memory: {resources.get('mem_used_gb', 0):.1f}/{resources.get('mem_total_gb', 0):.1f} GB ({mem_percent:.1f}%)")
            print(f"  Disk:   {resources.get('disk_used', 'N/A')} / {resources.get('disk_total', 'N/A')} ({resources.get('disk_percent', 'N/A')})")
            print()
            
            # Get processes
            processes = get_processes()
            processes.sort(key=lambda p: p.cpu, reverse=True)
            
            print(f"  {'PID':>7}  {'USER':<10}  {'%CPU':>6}  {'%MEM':>6}  {'NAME':<30}")
            print("  " + "─" * 65)
            
            for proc in processes[:limit]:
                name = proc.name[:30] if len(proc.name) > 30 else proc.name
                cpu_color = Colors.RED if proc.cpu > 50 else (Colors.YELLOW if proc.cpu > 20 else "")
                print(f"  {proc.pid:>7}  {proc.user:<10}  {cpu_color}{proc.cpu:>6.1f}{Colors.RESET}  {proc.mem:>6.1f}  {name:<30}")
            
            if not license.is_premium:
                print(f"\n  {Colors.YELLOW}Showing top {limit} processes. Upgrade for more: {DISCORD}{Colors.RESET}")
            
            time.sleep(interval)
    
    except KeyboardInterrupt:
        print("\n")
        print_info("Monitor stopped")


# ═══════════════════════════════════════════════════════════════════
# Process Search
# ═══════════════════════════════════════════════════════════════════

def search_processes(query: str):
    """Search for processes by name."""
    print_header(f"🔍 SEARCH: '{query}'")
    
    processes = get_processes()
    matches = [p for p in processes if query.lower() in p.name.lower() or query.lower() in p.command.lower()]
    
    if not matches:
        print(f"  No processes matching '{query}' found")
        print()
        return
    
    print(f"  {'PID':>7}  {'USER':<12}  {'%CPU':>6}  {'%MEM':>6}  {'NAME':<25}")
    print("  " + "─" * 65)
    
    for proc in matches:
        name = proc.name[:25] if len(proc.name) > 25 else proc.name
        print(f"  {proc.pid:>7}  {proc.user:<12}  {proc.cpu:>6.1f}  {proc.mem:>6.1f}  {name:<25}")
    
    print(f"\n  Found {len(matches)} matching processes")
    print()


# ═══════════════════════════════════════════════════════════════════
# Main Menu
# ═══════════════════════════════════════════════════════════════════

def show_menu(license: License):
    """Interactive menu."""
    
    while True:
        tier_badge = "⭐" if license.is_premium else "🆓"
        
        print(f"\n  📋 NullSec macOS Process Monitor {tier_badge}\n")
        print("  [1] System Resources")
        print("  [2] Top Processes (CPU)")
        print("  [3] Top Processes (Memory)")
        print("  [4] Process Details")
        print("  [5] Search Processes")
        print("  [6] Process Tree (Premium)")
        print("  [7] Live Monitor")
        print("  [8] Enter License Key")
        print("  [0] Exit")
        
        try:
            choice = input("\n  Select: ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        
        processes = get_processes()
        
        if choice == "1":
            display_system_resources()
        
        elif choice == "2":
            display_top_processes(processes, "cpu")
        
        elif choice == "3":
            display_top_processes(processes, "mem")
        
        elif choice == "4":
            try:
                pid = int(input("  Enter PID: ").strip())
                display_process_details(pid)
            except ValueError:
                print_error("Invalid PID")
        
        elif choice == "5":
            query = input("  Search query: ").strip()
            if query:
                search_processes(query)
        
        elif choice == "6":
            display_process_tree(license)
        
        elif choice == "7":
            try:
                interval = int(input("  Refresh interval (seconds, default 2): ").strip() or "2")
            except:
                interval = 2
            live_monitor(license, interval)
        
        elif choice == "8":
            key = input("  License key: ").strip()
            license = License(key)
            if license.valid:
                print_success(f"License activated: {license.tier_name}")
            else:
                print_warning("Invalid license key")
        
        elif choice == "0":
            break
        
        else:
            print_error("Invalid option")


# ═══════════════════════════════════════════════════════════════════
# Main Entry Point
# ═══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="NullSec macOS Process Monitor")
    parser.add_argument("-k", "--key", help="License key")
    parser.add_argument("-t", "--top", choices=["cpu", "mem"], help="Show top processes")
    parser.add_argument("-p", "--pid", type=int, help="Show process details")
    parser.add_argument("-s", "--search", help="Search processes")
    parser.add_argument("-l", "--live", action="store_true", help="Live monitor")
    parser.add_argument("-i", "--interval", type=int, default=2, help="Refresh interval")
    
    args = parser.parse_args()
    
    print(f"{Colors.CYAN}{BANNER}{Colors.RESET}")
    print(f"  Version {VERSION} | {AUTHOR}")
    print(f"  🔑 Premium: {DISCORD}\n")
    
    # Check if running on macOS
    if sys.platform != "darwin":
        print_error("This tool is designed for macOS only")
        sys.exit(1)
    
    license = License(args.key) if args.key else License()
    
    if license.valid:
        print_success(f"License activated: {license.tier_name}")
    
    # CLI mode
    if args.top:
        processes = get_processes()
        display_top_processes(processes, args.top)
        return
    
    if args.pid:
        display_process_details(args.pid)
        return
    
    if args.search:
        search_processes(args.search)
        return
    
    if args.live:
        live_monitor(license, args.interval)
        return
    
    # Interactive mode
    show_menu(license)
    
    # Footer
    print("\n─────────────────────────────────────────")
    print("  🍎 NullSec macOS Process Monitor")
    print(f"  🔑 Premium: {DISCORD}")
    print(f"  👤 Author: {AUTHOR}")
    print("─────────────────────────────────────────\n")


if __name__ == "__main__":
    main()
