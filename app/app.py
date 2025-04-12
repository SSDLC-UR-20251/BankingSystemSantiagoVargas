from paramiko.client import SSHClient, AutoAddPolicy, RejectPolicy

def safe_connect():
    client = SSHClient()
    client.set_missing_host_key_policy(RejectPolicy)
    client.connect("example.com")

    # ... interaction with server

    client.close()
