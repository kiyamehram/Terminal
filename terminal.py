#!/usr/bin/env python3
"""
Author: NoneR00tk1t
Kali-Native Penetration Terminal v4.0
"""

import os
import sys
import subprocess
import shlex
import readline
import json
from pathlib import Path
from datetime import datetime
import argparse
import logging
from logging.handlers import RotatingFileHandler
from rich.console import Console
from rich.progress import Progress
from rich.panel import Panel
from rich.table import Table
import tkinter as tk
from tkinter import ttk, messagebox
import asyncio
from importlib import import_module
import requests
import yaml
import re

class KNTerminal:
    def __init__(self):
        self.project_name = None
        self.project_path = None
        self.history_file = os.path.expanduser("~/.knt_history")
        self.config_file = os.path.expanduser("~/.knt_config.yaml")
        self.console = Console() 
        self.scan_results = {}  
        self.setup_readline()
        self.setup_logging()
        self.load_config()
        self.load_plugins()
        
        self.builtin_commands = {
            'scan': self.cmd_scan,
            'exploit': self.cmd_exploit,
            'audit': self.cmd_audit,
            'project': self.cmd_project,
            'report': self.cmd_report,
            'auto': self.cmd_auto,
            'sim': self.cmd_simulate,
            'gui': self.cmd_gui,
            'clear': self.cmd_clear,
            'exit': self.cmd_exit,
            'help': self.cmd_help
        }

    def setup_readline(self):
        readline.parse_and_bind('tab: complete')
        readline.set_completer(self.completer)
        if os.path.exists(self.history_file):
            readline.read_history_file(self.history_file)

    def setup_logging(self):
        log_file = os.path.expanduser("~/.knt_logs")
        handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger = logging.getLogger('KNT')
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(handler)

    def load_config(self):
        default_config = {
            'max_history': 1000,
            'auto_save': True,
            'log_level': 'INFO',
            'metasploit_path': '/usr/share/metasploit-framework'
        }
        if not os.path.exists(self.config_file):
            with open(self.config_file, 'w') as f:
                yaml.safe_dump(default_config, f)

    def completer(self, text, state):
        options = [cmd for cmd in self.builtin_commands.keys() if cmd.startswith(text)]
        if state < len(options):
            return options[state]
        return None

    def load_plugins(self):
        plugins_path = Path.home() / "knt_plugins"
        plugins_path.mkdir(exist_ok=True)
        for plugin_file in plugins_path.glob("*.py"):
            try:
                module_name = plugin_file.stem
                spec = import_module.spec_from_file_location(module_name, plugin_file)
                plugin = import_module.from_spec(spec)
                spec.loader.exec_module(plugin)
                if hasattr(plugin, 'register'):
                    plugin.register(self)
                    self.console.print(f"[green][+] Loaded plugin: {module_name}[/green]")
            except Exception as e:
                self.console.print(f"[red][-] Failed to load plugin {plugin_file}: {e}[/red]")

    def print_banner(self):
        banner = """
66222222777  77762272660000     62                  000000000   26206000662266600666
600660006222660606000666660 00000007   7                     0           006660600000000000006
000000000006666666660000660                       0                     7006066666000000000662
00000000000000000000000000000                         7                00000006600000000000006
26000006060000000000000000002                        7   7           2       00600060066666006
26000000666060000600000                              7    2              600000006666000000006
706660606606666666006660002                               2                0000000000000000000
762222226622226600000000                    7     7       2                          066666662
76666666622660000000007                  7  726267       7      77                  0006622227
2662660000000000                     2 0662       76  7    7       7               00666262662
262222660600006600                2                  06    7        0            0006626600006
2666600000000000000000  7600    6               70 606   2                   70000066666600006
606600000000060666000000          2         0    0002260077          2           2000666606000
0000000000000000000000   06  6   0   0    60  6   2200600007   7    7  7    00002  06606000000
00000000000000000000  200      02   6   706       7000660  27   2     7  2     000000000000000
000000000000               20607  7   7 02    20  20022707  0   7  7   6         0000000060606
0007               0000    2 70    0   62   200  6026   026  07  2  27 70              6666606
             6  2   6  6067020   000 7000600027 206 6  2002  0 7 2   7  6 0 6        000666066
     2       7             0 0 70  2 2 2     77202626 667602 727 027 07 67 7002 70000000600006
                           07     060000 00   206002600070000600706  0  0 77   000000000000000
 2    0 027      20000000002 62727 0   6 000002   0600         77 26 0  6 7 00   0000000000000
  726 0000000000000000000      2 0  0  00000 7    076  6  0000006  6 2  0 7 700000000000000000
 77  0066222600000000006 00000 7 0     2 7 2      07   0 2 000   000 002277   0000000000000000
 700006622600066660000000000000  22                      60007  0  02 7         70000000000000
      00000000660060000000000              7   6  6               022  00000000000000000000000
 77  0000006660000600000000060000 6               027            06      000000060066622260000
  7 67  0666600000600000000000000 00 2  77        06                0000 000000060000000066222
 02777  06600000000000000000000000070  2                       620  00006000000060000000000666
 777   00000000000600000000007   02700       727  72     202  0 600  0000000000000000000000006
 727 200000000000000000        000  00002       607  2      0002000000000000000000000000000000
 27 6000000000000000000        20    000700             7000  00000000000000000060000000000000
 27 00000666600         02777    0722 26722006      00600000    000000000000000000000000000000
 27000 7000000     702   7022277  06727 07222600000622700006 7 67   60660000000000000000000000
 226      2     7777262727 07222277707   2622622222222060 07777 707  0000000000000666666660000
 267777777 70006 777276222272222277  2067 7026662226000   0 77  00 7   20000000066666666666600
 02 77622227  0000277222222222622600277200 7  0000007    02777007   22    06622266666666666606
 60006277666777700002727222222266 722222720220         7022206 7600222277 00000000000000000000
72226000627220627700002222222222200277222277062  707 606206720006272277207  700000000000000000
 6622200000272226227760026222222222006777222700     0600226067772222200222227  706660000000000
762662220000072226222272222226222277606067777700   0026072727262260222222222272700600000006000
 026662220000002722226662222266626227660000006260002262660000066222222266026622770000000000000
 022666662200000626666222266222226662022002722200000667272066222222262622226266226060600060000
 066666666226000062226666626666666222062260022222762222600220626666662622662620226000000000000
7006666666662220000626266662666666262066622600620766600626620066666666202266220222000000060000
2000666666666662200062666666666666662062662622660 26222266620026266666206226666662000000600000
0066660066666622226000022666666666662066666666660006666666620626666662260622606626000000660000
0606666666222626666000062666666666662066666666626770266666666666666666620002006662000000000000
2666666266000000000000000626666666662002666666666266666666620026666666620022006666006666000000
6666060000000066000000000066660666666666666666660266666666666026666666620060006666600000000000
0000000000000006660000000006666066666066666666666266666666660066666606660000006666200000000000
0000000000000006227260600000662622227727722727222772222222776222222222222000062222260000000000
        """
        self.console.print(Panel(banner, style="bold red", border_style="cyan"))
        self.console.print("Type 'help' for commands\n")

    def cmd_help(self, args):
        help_text = """
Available commands:
  scan <target> [options]    - Advanced network scan (nmap/masscan)
  exploit <target> [options] - Run Metasploit exploits with auto-suggestions
  audit <url> [options]      - Audit web applications (nikto/dirb/whatweb)
  project <action> [name]    - Manage projects (create/list/load/export)
  report [type]              - Generate reports (html/pdf/json)
  auto <script>              - Run automated penetration testing workflow
  sim <type>                 - Simulate attacks (brute-force/priv-esc)
  gui                        - Launch interactive GUI dashboard
  clear                      - Clear screen
  exit                       - Exit terminal

Examples:
  scan 192.168.1.1 --quick --vuln
  exploit 192.168.1.1 --suggest
  audit https://example.com --full
  project create MyPentest
  report json
  auto pentest_workflow.txt
  sim brute-force ftp://192.168.1.1
  gui
        """
        self.console.print(f"[cyan]{help_text}[/cyan]")

    async def cmd_scan(self, args):
        parser = argparse.ArgumentParser(prog='scan')
        parser.add_argument('target', help="Target IP or hostname")
        parser.add_argument('--quick', action='store_true', help="Quick scan mode")
        parser.add_argument('--vuln', action='store_true', help="Vulnerability scan")
        parser.add_argument('--masscan', action='store_true', help="Use masscan for faster port scanning")
        try:
            args = parser.parse_args(args)
        except SystemExit:
            self.console.print("[red]Usage: scan <target> [--quick] [--vuln] [--masscan][/red]")
            return

        self.console.print(f"[*] Scanning target: {args.target}")
        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning...", total=100)
            
            if args.masscan:
                cmd = ["masscan", "-p1-65535", "--rate=1000", args.target]
            else:
                cmd = ["nmap"]
                if args.quick:
                    cmd.extend(["-F", "--version-light"])
                else:
                    cmd.extend(["-sV", "-sC", "-O"])
                if args.vuln:
                    cmd.extend(["--script=vuln"])
                cmd.append(args.target)
            
            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=600)
                progress.update(task, advance=100)
                if process.returncode == 0:
                    output = stdout.decode()
                    self.console.print(f"\n[bold cyan]Scan Results:[/bold cyan]\n{output}")
                    
                    self.scan_results[args.target] = self.parse_scan_results(output)
                    
                    if self.project_path:
                        report_file = self.project_path / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                        report_file.write_text(output)
                        self.console.print(f"[green][+] Report saved to: {report_file}[/green]")
                else:
                    self.console.print(f"[red][-] Scan failed: {stderr.decode()}[/red]")
            except Exception as e:
                self.console.print(f"[red][-] Scan error: {e}[/red]")
                self.logger.error(f"Scan error: {e}")

    def parse_scan_results(self, output):
        results = {"ports": [], "services": [], "os": None, "vulnerabilities": []}
        lines = output.splitlines()
        for line in lines:
            if "open" in line and "tcp" in line:
                port = re.search(r"(\d+)/tcp", line)
                service = re.search(r"open\s+([^\s]+)", line)
                if port:
                    results["ports"].append(port.group(1))
                if service:
                    results["services"].append(service.group(1))
            if "OS details" in line:
                results["os"] = line.split(":")[-1].strip()
            if "VULNERABLE" in line:
                results["vulnerabilities"].append(line.strip())
        return results

    def suggest_exploits(self, target):
        if target not in self.scan_results:
            return ["No scan results available. Run 'scan' first."]
        
        results = self.scan_results[target]
        suggestions = []
        exploit_db = {
            "http": ["auxiliary/scanner/http/http_version", "exploit/multi/http/struts2_rest_xstream"],
            "smb": ["exploit/windows/smb/ms17_010_eternalblue", "auxiliary/scanner/smb/smb_version"],
            "ftp": ["auxiliary/scanner/ftp/ftp_version", "exploit/unix/ftp/vsftpd_234_backdoor"],
            "ssh": ["auxiliary/scanner/ssh/ssh_version", "exploit/multi/ssh/sshexec"]
        }
        
        for service in results["services"]:
            if service in exploit_db:
                suggestions.extend(exploit_db[service])
        
        if results["os"] and "Windows" in results["os"]:
            suggestions.append("exploit/windows/smb/ms17_010_eternalblue")
        elif results["os"] and "Linux" in results["os"]:
            suggestions.append("exploit/linux/local/network_manager_vpnc_username_priv_esc")
        
        return suggestions if suggestions else ["No exploits suggested for current scan results."]

    def cmd_exploit(self, args):
        parser = argparse.ArgumentParser(prog='exploit')
        parser.add_argument('target', help="Target IP or hostname")
        parser.add_argument('--module', help="Metasploit module path")
        parser.add_argument('--suggest', action='store_true', help="Suggest exploits based on scan results")
        try:
            args = parser.parse_args(args)
        except SystemExit:
            self.console.print("[red]Usage: exploit <target> [--module <module_path>] [--suggest][/red]")
            return

        self.console.print(f"[yellow]Warning: Exploits for ethical testing only, ensure authorization.[/yellow]")
        
        if args.suggest:
            suggestions = self.suggest_exploits(args.target)
            self.console.print("[cyan][+] Suggested Exploits:[/cyan]")
            for exploit in suggestions:
                self.console.print(f"  - {exploit}")
            return
        
        if not args.module:
            self.console.print("[red][-] Module required. Use --suggest to get recommendations.[/red]")
            return
        
        self.console.print(f"[*] Exploiting {args.target} with {args.module}")
        msf_cmd = f"use {args.module}; set RHOSTS {args.target}; exploit"
        try:
            result = subprocess.run(["msfconsole", "-q", "-x", msf_cmd], capture_output=True, text=True, timeout=600)
            self.console.print(f"[cyan][Metasploit Output]:[/cyan]\n{result.stdout}")
            if result.returncode != 0:
                self.console.print(f"[red][-] Exploit failed: {result.stderr}[/red]")
        except Exception as e:
            self.console.print(f"[red][-] Exploit error: {e}[/red]")
            self.logger.error(f"Exploit error: {e}")

    def cmd_audit(self, args):
        parser = argparse.ArgumentParser(prog='audit')
        parser.add_argument('url', help="Target URL")
        parser.add_argument('--full', action='store_true', help="Full audit mode")
        parser.add_argument('--vuln', action='store_true', help="Vulnerability scan")
        try:
            args = parser.parse_args(args)
        except SystemExit:
            self.console.print("[red]Usage: audit <url> [--full] [--vuln][/red]")
            return

        self.console.print(f"[*] Auditing: {args.url}")
        tools = ["nikto", "whatweb"]
        if args.full:
            tools.extend(["dirb"])
        if args.vuln:
            tools.extend(["sqlmap"])
        
        for tool in tools:
            with Progress() as progress:
                task = progress.add_task(f"[cyan]Running {tool}...", total=100)
                try:
                    result = subprocess.run([tool, args.url], capture_output=True, text=True, timeout=600)
                    progress.update(task, advance=100)
                    if result.returncode == 0:
                        self.console.print(f"[green][+] {tool} completed[/green]\n{result.stdout}")
                        if self.project_path:
                            report_file = self.project_path / f"{tool}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                            report_file.write_text(result.stdout)
                            self.console.print(f"[green][+] Report saved to: {report_file}[/green]")
                    else:
                        self.console.print(f"[red][-] {tool} failed: {result.stderr}[/red]")
                except Exception as e:
                    self.console.print(f"[red][-] {tool} error: {e}[/red]")
                    self.logger.error(f"{tool} error: {e}")

    def cmd_project(self, args):
        parser = argparse.ArgumentParser(prog='project')
        parser.add_argument('action', choices=['create', 'list', 'load', 'export'], help="Project action")
        parser.add_argument('name', nargs='?', help="Project name")
        try:
            args = parser.parse_args(args)
        except SystemExit:
            self.console.print("[red]Usage: project <create|list|load|export> [name][/red]")
            return

        projects_path = Path.home() / "knt_projects"
        projects_path.mkdir(exist_ok=True)
        
        if args.action == "create":
            if not args.name:
                self.console.print("[red]Project name required[/red]")
                return
            project_path = projects_path / args.name
            project_path.mkdir(parents=True, exist_ok=True)
            self.project_name = args.name
            self.project_path = project_path
            self.console.print(f"[green][+] Project '{args.name}' created at {project_path}[/green]")
        
        elif args.action == "list":
            self.console.print("Available projects:")
            for project in projects_path.iterdir():
                if project.is_dir():
                    self.console.print(f"  - {project.name}")
        
        elif args.action == "load":
            if not args.name:
                self.console.print("[red]Project name required[/red]")
                return
            project_path = projects_path / args.name
            if project_path.exists():
                self.project_name = args.name
                self.project_path = project_path
                self.console.print(f"[green][+] Loaded project: {args.name}[/green]")
            else:
                self.console.print(f"[red][-] Project not found: {args.name}[/red]")
        
        elif args.action == "export":
            if not self.project_path:
                self.console.print("[red][-] No active project[/red]")
                return
            export_file = self.project_path / f"{self.project_name}_export.tar.gz"
            try:
                subprocess.run(["tar", "-czf", str(export_file), "-C", str(self.project_path), "."], check=True)
                self.console.print(f"[green][+] Project exported to: {export_file}[/green]")
            except Exception as e:
                self.console.print(f"[red][-] Export failed: {e}[/red]")
                self.logger.error(f"Export failed: {e}")

    def cmd_report(self, args):
        if not self.project_path:
            self.console.print("[red][-] No active project[/red]")
            return
        
        report_type = args[0] if args else "html"
        report_file = self.project_path / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{report_type}"
        
        findings = []
        for file in self.project_path.glob("*.txt"):
            findings.append({"file": file.name, "content": file.read_text()})
        
        report_content = {
            "project": self.project_name,
            "generated": str(datetime.now()),
            "path": str(self.project_path),
            "findings": findings,
            "recommendations": [
                "Patch identified vulnerabilities",
                "Conduct regular security audits",
                "Implement network segmentation"
            ]
        }
        
        if report_type == "json":
            with open(report_file, 'w') as f:
                json.dump(report_content, f, indent=2)
        else:
            content = f"""
# Penetration Testing Report - {self.project_name}
Generated: {datetime.now()}

## Summary
- Project: {self.project_name}
- Path: {self.project_path}

## Findings
"""
            for finding in findings:
                content += f"\n### {finding['file']}\n{finding['content']}\n"
            content += "\n## Recommendations\n" + "\n".join(f"- {rec}" for rec in report_content["recommendations"])
            
            report_file.write_text(content)
            if report_type == "pdf":
                try:
                    subprocess.run(["pandoc", str(report_file), "-o", str(report_file.with_suffix('.pdf'))], check=True)
                    self.console.print(f"[green][+] PDF report generated: {report_file.with_suffix('.pdf')}[/green]")
                except Exception as e:
                    self.console.print(f"[red][-] PDF generation error: {e}[/red]")
                    self.logger.error(f"PDF generation error: {e}")
        
        self.console.print(f"[green][+] Report generated: {report_file}[/green]")

    def cmd_auto(self, args):
        parser = argparse.ArgumentParser(prog='auto')
        parser.add_argument('script', help="Automation script file")
        try:
            args = parser.parse_args(args)
        except SystemExit:
            self.console.print("[red]Usage: auto <script>[/red]")
            return
        
        script_path = Path(args.script)
        if not script_path.exists():
            self.console.print(f"[red][-] Script not found: {args.script}[/red]")
            return
        
        with open(script_path, 'r') as f:
            commands = f.read().splitlines()
        
        self.console.print(f"[*] Running automation script: {args.script}")
        with Progress() as progress:
            task = progress.add_task("[cyan]Executing workflow...", total=len(commands))
            for cmd in commands:
                if cmd.strip():
                    self.console.print(f"[cyan]Executing: {cmd}[/cyan]")
                    self.execute_command(cmd)
                    progress.update(task, advance=1)

    def cmd_simulate(self, args):
        parser = argparse.ArgumentParser(prog='sim')
        parser.add_argument('type', choices=['brute-force', 'priv-esc'], help="Attack simulation type")
        parser.add_argument('target', help="Target (e.g., ftp://192.168.1.1 or local)")
        try:
            args = parser.parse_args(args)
        except SystemExit:
            self.console.print("[red]Usage: sim <brute-force|priv-esc> <target>[/red]")
            return

        self.console.print(f"[yellow]Warning: Simulations for ethical testing only, ensure authorization.[/yellow]")
        self.console.print(f"[*] Simulating {args.type} on {args.target}")
        
        if args.type == "brute-force":
            if "ftp://" in args.target:
                cmd = ["hydra", "-l", "admin", "-P", "/usr/share/wordlists/rockyou.txt", args.target]
            else:
                cmd = ["hydra", "-l", "admin", "-P", "/usr/share/wordlists/rockyou.txt", f"ssh://{args.target}"]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                self.console.print(f"[cyan][Hydra Output]:[/cyan]\n{result.stdout}")
                if result.returncode != 0:
                    self.console.print(f"[red][-] Brute-force failed: {result.stderr}[/red]")
            except Exception as e:
                self.console.print(f"[red][-] Brute-force error: {e}[/red]")
                self.logger.error(f"Brute-force error: {e}")
        
        elif args.type == "priv-esc":
            if args.target == "local":
                cmd = ["sudo", "-l"]  
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                    self.console.print(f"[cyan][Priv-Esc Output]:[/cyan]\n{result.stdout}")
                    if result.returncode != 0:
                        self.console.print(f"[red][-] Priv-esc failed: {result.stderr}[/red]")
                except Exception as e:
                    self.console.print(f"[red][-] Priv-esc error: {e}[/red]")
                    self.logger.error(f"Priv-esc error: {e}")
            else:
                self.console.print("[red][-] Local privilege escalation only supported for 'local' target[/red]")

    def cmd_gui(self, args):
        self.console.print("[green][+] Entering GUI mode...[/green]")
        
        root = tk.Tk()
        root.title("KNT Penetration Testing Dashboard")
        root.geometry("1000x800")
        root.configure(bg="#1e1e2e")
        
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton", background="#4CAF50", foreground="white", font=("Arial", 12))
        style.configure("TLabel", background="#1e1e2e", foreground="white", font=("Arial", 12))
        style.configure("TEntry", fieldbackground="#3E3E3E", foreground="white")
        
        frame = ttk.Frame(root, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        label = ttk.Label(frame, text="KNT Penetration Testing Dashboard\nYour Ultimate Security Command Center", justify=tk.CENTER)
        label.pack(pady=20)
        
        buttons = [
            ("Run Network Scan", lambda: self.execute_gui_command("scan")),
            ("Run Web Audit", lambda: self.execute_gui_command("audit")),
            ("Run Exploit", lambda: self.execute_gui_command("exploit")),
            ("Manage Project", lambda: self.execute_gui_command("project")),
            ("Generate Report", lambda: self.execute_gui_command("report")),
            ("Run Automation", lambda: self.execute_gui_command("auto")),
            ("Simulate Attack", lambda: self.execute_gui_command("sim"))
        ]
        
        for text, cmd in buttons:
            btn = ttk.Button(frame, text=text, command=cmd)
            btn.pack(pady=5, fill=tk.X)
        
        result_frame = ttk.Frame(frame)
        result_frame.pack(fill=tk.BOTH, expand=True, pady=20)
        result_table = Table(show_header=True, header_style="bold magenta")
        result_table.add_column("Command", width=20)
        result_table.add_column("Target", width=20)
        result_table.add_column("Status", width=15)
        result_table.add_column("Details", width=45)
        self.console.print(result_table)
        
        cmd_label = ttk.Label(frame, text="Enter Command:")
        cmd_label.pack(pady=10)
        cmd_entry = ttk.Entry(frame, width=50)
        cmd_entry.pack(pady=10)
        
        output_text = tk.Text(frame, height=15, bg="#3E3E3E", fg="white", font=("Arial", 10))
        output_text.pack(fill=tk.BOTH, expand=True, pady=10)
        
        def run_command():
            command = cmd_entry.get()
            if command:
                output_text.insert(tk.END, f"> {command}\n")
                try:
                    parts = shlex.split(command)
                    if parts[0] in self.builtin_commands:
                        if asyncio.iscoroutinefunction(self.builtin_commands[parts[0]]):
                            result = asyncio.run(self.builtin_commands[parts[0]](parts[1:]))
                        else:
                            self.builtin_commands[parts[0]](parts[1:])
                        output_text.insert(tk.END, "Command executed.\n")
                        result_table.add_row(parts[0], parts[1] if len(parts) > 1 else "N/A", "Success", "Command executed")
                    else:
                        result = subprocess.run(parts, capture_output=True, text=True, timeout=600)
                        output_text.insert(tk.END, result.stdout + "\n" + result.stderr + "\n")
                        result_table.add_row(parts[0], parts[1] if len(parts) > 1 else "N/A", "Success" if result.returncode == 0 else "Failed", result.stdout[:40] + "...")
                    self.console.print(result_table)
                except Exception as e:
                    output_text.insert(tk.END, f"Error: {e}\n")
                    result_table.add_row(command, "N/A", "Failed", str(e))
                    self.console.print(result_table)
                output_text.see(tk.END)
            cmd_entry.delete(0, tk.END)
        
        run_btn = ttk.Button(frame, text="Run Command", command=run_command)
        run_btn.pack(pady=10)
        
        def back_to_terminal():
            root.destroy()
            self.console.print("[green][+] Returned to main terminal.[/green]")
        
        back_btn = ttk.Button(frame, text="Back to Terminal", command=back_to_terminal)
        back_btn.pack(pady=10)
        
        root.mainloop()

    def execute_gui_command(self, cmd_type):
        from rich.prompt import Prompt
        if cmd_type == "scan":
            target = Prompt.ask("Enter target IP/hostname")
            quick = Prompt.ask("Quick scan? [y/N]", default="N").lower() == "y"
            vuln = Prompt.ask("Vulnerability scan? [y/N]", default="N").lower() == "y"
            masscan = Prompt.ask("Use masscan? [y/N]", default="N").lower() == "y"
            cmd = f"scan {target} {'--quick' if quick else ''} {'--vuln' if vuln else ''} {'--masscan' if masscan else ''}".strip()
        elif cmd_type == "audit":
            url = Prompt.ask("Enter target URL")
            full = Prompt.ask("Full audit? [y/N]", default="N").lower() == "y"
            vuln = Prompt.ask("Vulnerability scan? [y/N]", default="N").lower() == "y"
            cmd = f"audit {url} {'--full' if full else ''} {'--vuln' if vuln else ''}".strip()
        elif cmd_type == "exploit":
            target = Prompt.ask("Enter target IP/hostname")
            suggest = Prompt.ask("Suggest exploits? [y/N]", default="N").lower() == "y"
            module = Prompt.ask("Enter Metasploit module", default="") if not suggest else ""
            cmd = f"exploit {target} {'--suggest' if suggest else f'--module {module}' if module else ''}".strip()
        elif cmd_type == "project":
            action = Prompt.ask("Project action (create/list/load/export)", choices=["create", "list", "load", "export"])
            name = Prompt.ask("Project name", default="") if action in ["create", "load", "export"] else ""
            cmd = f"project {action} {name}".strip()
        elif cmd_type == "report":
            report_type = Prompt.ask("Report type (html/pdf/json)", choices=["html", "pdf", "json"], default="html")
            cmd = f"report {report_type}"
        elif cmd_type == "auto":
            script = Prompt.ask("Enter automation script path")
            cmd = f"auto {script}"
        elif cmd_type == "sim":
            attack_type = Prompt.ask("Attack type (brute-force/priv-esc)", choices=["brute-force", "priv-esc"])
            target = Prompt.ask("Enter target (e.g., ftp://192.168.1.1 or local)")
            cmd = f"sim {attack_type} {target}"
        else:
            return
        
        self.execute_command(cmd)

    def cmd_clear(self, args):
        self.console.clear()

    def cmd_exit(self, args):
        self.console.print("\n[green][+] Goodbye! Keep hacking ethically![/green]")
        readline.write_history_file(self.history_file)
        sys.exit(0)

    def execute_command(self, command_line):
        if not command_line.strip():
            return
        
        try:
            parts = shlex.split(command_line)
            command = parts[0]
            args = parts[1:]
            
            readline.add_history(command_line)
            
            if command in self.builtin_commands:
                if asyncio.iscoroutinefunction(self.builtin_commands[command]):
                    asyncio.run(self.builtin_commands[command](args))
                else:
                    self.builtin_commands[command](args)
            else:
                result = subprocess.run(parts, capture_output=True, text=True, timeout=600)
                if result.returncode != 0:
                    self.console.print(f"[red][-] Command failed: {result.returncode} - {result.stderr}[/red]")
                else:
                    self.console.print(result.stdout)
        except KeyboardInterrupt:
            self.console.print("[red][-] Command interrupted[/red]")
        except subprocess.TimeoutExpired:
            self.console.print("[red][-] Command timed out[/red]")
        except Exception as e:
            self.console.print(f"[red][-] Execution error: {e}[/red]")
            self.logger.error(f"Execution error: {e}")

    def run(self):
        self.print_banner()
        
        while True:
            try:
                prompt = f"[bold red]KNT[/bold red]"
                if self.project_name:
                    prompt += f"([bold green]{self.project_name}[/bold green])"
                prompt += "> "
                
                command = self.console.input(prompt)
                self.execute_command(command)
                
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Use 'exit' to quit[/yellow]")
            except EOFError:
                self.cmd_exit([])
            except Exception as e:
                self.console.print(f"[red][-] Error: {e}[/red]")
                self.logger.error(f"Terminal error: {e}")

if __name__ == "__main__":
    terminal = KNTerminal()
    terminal.run()