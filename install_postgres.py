
import paramiko
import subprocess
#import socket
import sys
import os
from statistics import mean
import psycopg2

SSH_USER = "admin1"
SSH_KEY = "/home/admin1/.ssh/id_rsa"

#def get_primary_ip(host):
#    ssh = paramiko.SSHClient()
#    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#    ssh.connect(host, username=SSH_USER, key_filename=os.path.expanduser(SSH_KEY))
#    stdin, stdout, stderr = ssh.exec_command("hostname -I | awk '{print $1}'")
#    ip = stdout.read().decode().strip()
#    ssh.close()
#    return ip
#
#def get_local_ip():
#    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#    try:
#        s.connect(("8.8.8.8", 80))  # фейковое подключение для определения IP
#        ip = s.getsockname()[0]
#    finally:
#        s.close()
#    return ip

def get_load_avg(host):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, username=SSH_USER, key_filename=os.path.expanduser(SSH_KEY))
    stdin, stdout, stderr = ssh.exec_command("uptime")
    output = stdout.read().decode()
    ssh.close()
    try:
        load = float(output.split("load average:")[1].split(",")[0].strip())
        return load
    except Exception as e:
        print(f"Error getting load from {host}: {e}")
        return 100.0

def generate_inventory(target, other):
    with open("ansible/inventory.ini", "w") as f:
        f.write(f"[target]\n{target}\n[other]\n{other}\n")

def run_ansible():
    subprocess.run([
        "ansible-playbook",
        "-i", "ansible/inventory.ini",
        "ansible/install_postgres.yml"
    ], check=True)

def check_postgres_connection(host):
    try:
        conn = psycopg2.connect(
            dbname='postgres',
            user='student',
            password='student',
            host=host,
            port=5432
        )
        cur = conn.cursor()
        cur.execute("SELECT 1")
        result = cur.fetchone()
        conn.close()
        return result == (1,)
    except Exception as e:
        print(f"Connection failed: {e}")
        return False

#def main():
#    if len(sys.argv) < 2:
#        print("Usage: python3 install_postgres.py <ip1,ip2>")
#        sys.exit(1)
#
#    servers_input = sys.argv[1]
#    servers = [s.strip() for s in servers_input.split(',')]
#    loads = {host: get_load_avg(host) for host in servers}
#    target_host = min(loads, key=loads.get)
#    other_host = [h for h in servers if h != target_host][0]
#
#    client_ip = get_primary_ip(other_host)
#
#    local_ip = get_local_ip()
#
#    allowed_ip = f"{client_ip},{local_ip}"
#
#    print(f"Target host (least loaded): {target_host}")
#    print(f"Allowed IP (client + local): {allowed_ip}")
#
#    run_ansible(target_host, allowed_ip)
#
#    if check_postgres_connection(target_host):
#        print("PostgreSQL is up and responding to SELECT 1")
#    else:
#        print("Failed to validate PostgreSQL installation")
#
#if __name__ == "__main__":
#    main()

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 install_postgres.py <ip1,ip2>")
        sys.exit(1)

    SERVERS = sys.argv[1].split(',')
    loads = {host: get_load_avg(host) for host in SERVERS}
    sorted_hosts = sorted(loads.items(), key=lambda x: x[1])
    target_host = sorted_hosts[0][0]
    other_host = sorted_hosts[1][0]

    print(f"Target host (least loaded): {target_host}")
    generate_inventory(target_host, other_host)
    run_ansible()

    if check_postgres_connection(target_host):
        print("PostgreSQL is up and responding to SELECT 1")
    else:
        print("Failed to validate PostgreSQL installation")

if __name__ == "__main__":
    main()
