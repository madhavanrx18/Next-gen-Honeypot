#!/usr/bin/env python3

# Import library dependencies
import argparse
import sys
import os
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
import colorama
from colorama import Fore, Style
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.live import Live
from rich.layout import Layout

# Import project dependencies
from ssh_honeypot import honeypot as ssh_honeypot
from web_honeypot import run_app as web_honeypot
from dashboard_data_parser import parse_logs
from web_app import run_app as web_app

# Initialize colorama for cross-platform color support
colorama.init()

# ASCII Art Banner
BANNER = """
██╗  ██╗ ██████╗ ███╗   ██╗███████╗██╗   ██╗██████╗ 
██║  ██║██╔═══██╗████╗  ██║██╔════╝╚██╗ ██╔╝██╔══██╗
███████║██║   ██║██╔██╗ ██║█████╗    ╚████╔╝ ██████╔╝
██╔══██║██║   ██║██║╚██╗██║██╔══╝     ╚██╔╝  ██╔═══╝ 
██║  ██║╚██████╔╝██║ ╚████║███████╗    ██║   ██║     
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝    ╚═╝   ╚═╝     
"""

class HoneypotConfig:
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
        
    def _load_config(self) -> Dict[str, Any]:
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        return self._create_default_config()
    
    def _create_default_config(self) -> Dict[str, Any]:
        default_config = {
            'ssh': {
                'default_port': 2222,
                'default_username': 'admin',
                'default_password': 'admin123',
                'tarpit_enabled': False
            },
            'web': {
                'default_port': 8080,
                'default_username': 'admin',
                'default_password': 'admin123'
            },
            'logging': {
                'level': 'INFO',
                'file': 'honeypot.log',
                'max_size': 10485760,  # 10MB
                'backup_count': 5
            }
        }
        with open(self.config_path, 'w') as f:
            yaml.dump(default_config, f, default_flow_style=False)
        return default_config

class HoneypotManager:
    def __init__(self):
        self.console = Console()
        self.config = HoneypotConfig()
        self.layout = Layout()
        self.setup_layout()
        
    def setup_layout(self):
        self.layout.split(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3)
        )
        
    def print_banner(self):
        self.console.print(Panel(
            f"{Fore.CYAN}{BANNER}{Style.RESET_ALL}",
            title="[bold blue]Honeypot Manager[/bold blue]",
            border_style="blue"
        ))
        
    def print_status(self, status: str, color: str = "green"):
        self.console.print(f"[{color}]{status}[/{color}]")
        
    def print_error(self, error: str):
        self.console.print(f"[red]Error: {error}[/red]")
        
    def create_status_table(self, stats: Dict[str, Any]) -> Table:
        table = Table(title="Honeypot Statistics")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        for key, value in stats.items():
            table.add_row(key, str(value))
            
        return table

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Advanced Honeypot Manager with SSH and Web Support",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # General arguments
    parser.add_argument('-c', '--config', type=str, help='Path to configuration file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--version', action='version', version='%(prog)s 1.0.0')
    
    # SSH Honeypot arguments
    parser.add_argument('-s', '--ssh', action='store_true', help='Run SSH Honeypot')
    parser.add_argument('-a', '--address', type=str, help='Address to bind to')
    parser.add_argument('-p', '--port', type=int, help='Port to listen on')
    parser.add_argument('-u', '--username', type=str, help='SSH username')
    parser.add_argument('-w', '--password', type=str, help='SSH password')
    parser.add_argument('-t', '--tarpit', action='store_true', help='Enable tarpit mode')
    
    # Web Honeypot arguments
    parser.add_argument('-wh', '--web', action='store_true', help='Run Web Honeypot')
    parser.add_argument('-wp', '--web-port', type=int, help='Web server port')
    parser.add_argument('-wu', '--web-username', type=str, help='Web admin username')
    parser.add_argument('-ww', '--web-password', type=str, help='Web admin password')
    
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    try:
        if args.ssh:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=Console()
            ) as progress:
                task = progress.add_task("[cyan]Starting SSH Honeypot...", total=None)
                
                manager.print_status(f"Starting SSH Honeypot on {args.address or '0.0.0.0'}:{args.port or 2222}")
                manager.print_status(f"Username: {args.username or 'admin'}, Password: {args.password or 'admin123'}")
                
                ssh_honeypot(
                    args.address or "0.0.0.0",
                    args.port or 2222,
                    args.username or "admin",
                    args.password or "admin123",
                    args.tarpit
                )
        elif args.web:
            web_port = args.web_port or 8080
            print(f"Starting Web Honeypot on port {web_port}")
            web_app(port=web_port)
        else:
            print("Please specify either SSH (-s) or Web (-wh) honeypot mode")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\nShutting down Honeypot...")
        sys.exit(0)
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    manager = HoneypotManager()
    main()
