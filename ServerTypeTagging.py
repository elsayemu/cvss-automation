import os
import sqlite3
import boto3
import re

INDICATOR_MAP = {
    'nginx': ('Production Web', 'H', 'H', 'H'),
    'apache2': ('Production Web', 'H', 'H', 'H'),
    'httpd': ('Production Web', 'H', 'H', 'H'),
    'tomcat': ('Production Web', 'H', 'H', 'H'),
    'mysqld': ('Database', 'H', 'H', 'M'),
    'postgres': ('Database', 'H', 'H', 'M'),
    'mongod': ('Database', 'H', 'H', 'M'),
    'sqlservr': ('Database', 'H', 'H', 'M'),
    's3fs': ('Storage', 'H', 'M', 'M'),
    'nfsd': ('Storage', 'H', 'M', 'M'),
    'smbd': ('Storage', 'H', 'M', 'M'),
    'rclone': ('Storage', 'H', 'M', 'M'),
    'postfix': ('Email', 'H', 'M', 'L'),
    'dovecot': ('Email', 'H', 'M', 'L'),
    'exim': ('Email', 'H', 'M', 'L'),
    'sendmail': ('Email', 'H', 'M', 'L'),
    'sshd': ('IAM/Authentication', 'H', 'H', 'H'),
    'winlogon': ('IAM/Authentication', 'H', 'H', 'H'),
    'slapd': ('IAM/Authentication', 'H', 'H', 'H'),
    'lsass': ('IAM/Authentication', 'H', 'H', 'H'),
    'veeam': ('Backup', 'H', 'H', 'M'),
    'bacula': ('Backup', 'H', 'H', 'M'),
    'restic': ('Backup', 'H', 'H', 'M'),
    'node': ('API', 'M', 'H', 'H'),
    'python': ('API', 'M', 'H', 'H'),
    'java': ('API', 'M', 'H', 'H'),
    'saprouter': ('ERP/CRM', 'H', 'H', 'M'),
    'odoo-bin': ('ERP/CRM', 'H', 'H', 'M'),
    'named': ('DNS', 'H', 'L', 'H'),
    'dnsmasq': ('DNS', 'H', 'L', 'H'),
    'systemd-resolved': ('DNS', 'H', 'L', 'H'),
    'confluence': ('Internal Wikis', 'M', 'L', 'L'),
    'mediawiki': ('Internal Wikis', 'M', 'L', 'L'),
    'php': ('Internal Wikis', 'M', 'L', 'L')
}

def get_instance_id_by_hostname(ec2, hostname):
    match = re.search(r'ip-(\d+)-(\d+)-(\d+)-(\d+)', hostname)
    if not match:
        return None
    ip = '.'.join(match.groups())

    try:
        response = ec2.describe_instances(Filters=[
            {'Name': 'private-ip-address', 'Values': [ip]}
        ])
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                return instance['InstanceId']
    except Exception as e:
        print(f"[ERROR] describe_instances failed for IP {ip}: {e}")
    return None

def read_package_names(db_path):
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sys_programs")
            return [row[0].lower() for row in cursor.fetchall()]
    except Exception:
        return []

def read_hostname(db_path):
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT hostname FROM sys_osinfo LIMIT 1")
            result = cursor.fetchone()
            return result[0] if result else None
    except Exception:
        return None

def update_instance_tags(ec2, instance_id, cr, ar, ir):
    ec2.create_tags(
        Resources=[instance_id],
        Tags=[
            {'Key': 'CR', 'Value': cr},
            {'Key': 'AR', 'Value': ar},
            {'Key': 'IR', 'Value': ir},
        ]
    )

def detect_and_apply_tags(packages):
    for package in packages:
        pkg = package.strip().lower()
        if pkg in INDICATOR_MAP:
            return INDICATOR_MAP[pkg]  # returns (ServerType, CR, AR, IR)
    return None

def main():
    ec2 = boto3.client('ec2', region_name='us-east-2')
    db_dir = '/var/ossec/queue/db/'

    for db_file in os.listdir(db_dir):
        if not db_file.endswith('.db') or db_file == '000.db':
            continue

        db_path = os.path.join(db_dir, db_file)
        hostname = read_hostname(db_path)
        if not hostname:
            print(f"[{db_file}] Could not determine agent hostname.")
            continue

        instance_id = get_instance_id_by_hostname(ec2, hostname)
        if not instance_id:
            print(f"[{db_file}] Could not match hostname '{hostname}' to an EC2 instance.")
            continue

        packages = read_package_names(db_path)
        match = detect_and_apply_tags(packages)
        if not match:
            print(f"[{db_file}] No matching server type.")
            continue

        server_type, cr, ar, ir = match
        try:
            update_instance_tags(ec2, instance_id, cr, ar, ir)
            print(f"[SUCCESS] Updated {instance_id} CR={cr}, AR={ar}, IR={ir} based on '{server_type}'")
        except Exception as e:
            print(f"[{db_file}] Failed to update tags: {e}")

if __name__ == '__main__':
    main()
