# Import library dependencies.
import logging
from logging.handlers import RotatingFileHandler
import paramiko
import threading
import socket
import time
from pathlib import Path
import datetime
import random
import json

# Constants.
SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.3"

# Constants.
# Get base directory of where user is running honeypy from.
base_dir = Path(__file__).parent.parent
# Source creds_audits.log & cmd_audits.log file path.
server_key = base_dir / 'ssh_honeypy' / 'static' / 'server.key'

creds_audits_log_local_file_path = base_dir / 'ssh_honeypy' / 'log_files' / 'creds_audits.log'
cmd_audits_log_local_file_path = base_dir / 'ssh_honeypy' / 'log_files' / 'cmd_audits.log'
session_log_local_file_path = base_dir / 'ssh_honeypy' / 'log_files' / 'session.log'

# SSH Server Host Key.
host_key = paramiko.RSAKey(filename=server_key)

# Logging Format.
logging_format = logging.Formatter('%(asctime)s - %(message)s')

# Session Logger
session_logger = logging.getLogger('SessionLogger')
session_logger.setLevel(logging.INFO)
session_handler = RotatingFileHandler(session_log_local_file_path, maxBytes=2000, backupCount=5)
session_handler.setFormatter(logging_format)
session_logger.addHandler(session_handler)

# Funnel (catch all) Logger.
funnel_logger = logging.getLogger('FunnelLogger')
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler(cmd_audits_log_local_file_path, maxBytes=2000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

# Credentials Logger. Captures IP Address, Username, Password.
creds_logger = logging.getLogger('CredsLogger')
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler(creds_audits_log_local_file_path, maxBytes=2000, backupCount=5)
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)

# Fake system information
SYSTEM_INFO = {
    'hostname': 'prod-server-01',
    'os': 'Ubuntu 22.04.3 LTS',
    'kernel': '5.15.0-91-generic',
    'cpu': 'Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz',
    'memory': '32768MB',
    'uptime': '15 days, 3 hours, 45 minutes',
    'users': ['admin', 'system', 'backup', 'monitor'],
    'last_login': 'admin from 192.168.1.100 2 hours ago'
}

# Fake directory structure
DIRECTORY_STRUCTURE = {
    '/': ['bin', 'etc', 'home', 'var', 'usr', 'tmp'],
    '/home': ['admin', 'system', 'backup', 'monitor'],
    '/etc': ['passwd', 'shadow', 'hosts', 'network'],
    '/var': ['log', 'run', 'tmp'],
    '/var/log': ['auth.log', 'syslog', 'messages'],
    '/tmp': ['temp_file1', 'temp_file2']
}

# SSH Server Class. This establishes the options for the SSH server.
class Server(paramiko.ServerInterface):

    def __init__(self, client_ip, input_username=None, input_password=None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password
        self.start_time = datetime.datetime.now()
        session_logger.info(f"New connection from {client_ip}")

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
    
    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        funnel_logger.info(f'[{timestamp}] Client {self.client_ip} attempted connection with username: {username}, password: {password}')
        creds_logger.info(f'{timestamp},{self.client_ip},{username},{password}')
        
        if self.input_username is not None and self.input_password is not None:
            if username == self.input_username and password == self.input_password:
                session_logger.info(f"Successful login from {self.client_ip} as {username}")
                return paramiko.AUTH_SUCCESSFUL
            else:
                session_logger.warning(f"Failed login attempt from {self.client_ip} as {username}")
                return paramiko.AUTH_FAILED
        else:
            session_logger.info(f"Successful login from {self.client_ip} as {username}")
            return paramiko.AUTH_SUCCESSFUL
    
    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        command = str(command)
        return True

def get_fake_file_content(path):
    if path == '/etc/passwd':
        return """root:x:0:0:root:/root:/bin/bash
admin:x:1000:1000:System Administrator:/home/admin:/bin/bash
system:x:1001:1001:System Service Account:/home/system:/sbin/nologin
backup:x:1002:1002:Backup Service:/home/backup:/sbin/nologin
monitor:x:1003:1003:Monitoring Service:/home/monitor:/sbin/nologin"""
    elif path == '/etc/hosts':
        return """127.0.0.1 localhost
192.168.1.100 prod-server-01
192.168.1.101 prod-server-02
192.168.1.102 prod-server-03"""
    elif path == '/var/log/auth.log':
        return f"""Jan 15 10:30:15 prod-server-01 sshd[1234]: Accepted password for admin from 192.168.1.100 port 54321 ssh2
Jan 15 10:35:22 prod-server-01 sshd[1235]: Failed password for invalid user root from 192.168.1.101 port 54322 ssh2
Jan 15 10:40:45 prod-server-01 sshd[1236]: Accepted password for system from 192.168.1.102 port 54323 ssh2"""
    else:
        return "This is a fake file for demonstration purposes."

def emulated_shell(channel, client_ip):
    channel.send(b"\r\nWelcome to Ubuntu 22.04.3 LTS (Jammy Jellyfish)\r\n\r\n")
    channel.send(b"Last login: " + SYSTEM_INFO['last_login'].encode() + b"\r\n")
    channel.send(b"\r\n")
    
    prompt = f"{SYSTEM_INFO['hostname']}:~$ "
    channel.send(prompt.encode())
    
    command = b""
    current_dir = "/home/admin"
    
    while True:
        char = channel.recv(1)
        if not char:
            channel.close()
            break
            
        channel.send(char)
        command += char
        
        if char == b"\r":
            cmd = command.strip().decode()
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            if cmd == 'exit':
                response = b"\nGoodbye!\n"
                channel.close()
            elif cmd == 'pwd':
                response = f"\n{current_dir}\n".encode()
            elif cmd == 'whoami':
                response = b"\nadmin\n"
            elif cmd == 'ls':
                if current_dir in DIRECTORY_STRUCTURE:
                    response = "\n".join(DIRECTORY_STRUCTURE[current_dir]).encode() + b"\n"
                else:
                    response = b"No such directory\n"
            elif cmd.startswith('cd '):
                new_dir = cmd[3:].strip()
                if new_dir in DIRECTORY_STRUCTURE.get(current_dir, []):
                    current_dir = f"{current_dir}/{new_dir}"
                    response = b""
                else:
                    response = b"No such directory\n"
            elif cmd.startswith('cat '):
                file_path = cmd[4:].strip()
                if file_path in DIRECTORY_STRUCTURE.get(current_dir, []):
                    content = get_fake_file_content(file_path)
                    response = f"\n{content}\n".encode()
                else:
                    response = b"No such file\n"
            elif cmd == 'uname -a':
                response = f"\nLinux {SYSTEM_INFO['hostname']} {SYSTEM_INFO['kernel']} #1 SMP PREEMPT_DYNAMIC Thu Jan 11 12:00:00 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux\n".encode()
            elif cmd == 'uptime':
                response = f"\n{datetime.datetime.now().strftime('%H:%M:%S')} up {SYSTEM_INFO['uptime']},  {len(SYSTEM_INFO['users'])} users,  load average: {random.uniform(0.1, 2.0):.2f}, {random.uniform(0.1, 2.0):.2f}, {random.uniform(0.1, 2.0):.2f}\n".encode()
            else:
                response = b"\nCommand not found\n"
            
            funnel_logger.info(f'[{timestamp}] Command "{cmd}" executed by {client_ip}')
            channel.send(response)
            channel.send(prompt.encode())
            command = b""

def client_handle(client, addr, username, password, tarpit=False):
    client_ip = addr[0]
    print(f"{client_ip} connected to server.")
    try:
    
        # Initlizes a Transport object using the socket connection from client.
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER

        # Creates an instance of the SSH server, adds the host key to prove its identity, starts SSH server.
        server = Server(client_ip=client_ip, input_username=username, input_password=password)
        transport.add_server_key(host_key)
        transport.start_server(server=server)

        # Establishes an encrypted tunnel for bidirectional communication between the client and server.
        channel = transport.accept(100)

        if channel is None:
            print("No channel was opened.")

        standard_banner = "Welcome to Ubuntu 22.04 LTS (Jammy Jellyfish)!\r\n\r\n"
        
        try:
            # Endless Banner: If tarpit option is passed, then send 'endless' ssh banner.
            if tarpit:
                endless_banner = standard_banner * 100
                for char in endless_banner:
                    channel.send(char)
                    time.sleep(8)
            # Standard Banner: Send generic welcome banner to impersonate server.
            else:
                channel.send(standard_banner)
            # Send channel connection to emulated shell for interpretation.
            emulated_shell(channel, client_ip=client_ip)

        except Exception as error:
            print(error)
    # Generic catch all exception error code.
    except Exception as error:
        print(error)
        print("!!! Exception !!!")
    
    # Once session has completed, close the transport connection.
    finally:
        try:
            transport.close()
        except Exception:
            pass
        
        client.close()

def honeypot(address, port, username, password, tarpit=False):
    
    # Open a new socket using TCP, bind to port.
    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socks.bind((address, port))

    # Can handle 100 concurrent connections.
    socks.listen(100)
    print(f"SSH server is listening on port {port}.")

    while True: 
        try:
            # Accept connection from client and address.
            client, addr = socks.accept()
            # Start a new thread to handle the client connection.
            ssh_honeypot_thread = threading.Thread(target=client_handle, args=(client, addr, username, password, tarpit))
            ssh_honeypot_thread.start()

        except Exception as error:
            # Generic catch all exception error code.
            print("!!! Exception - Could not open new client connection !!!")
            print(error)