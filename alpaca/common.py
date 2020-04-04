"""
small helper functions.
"""
import socket
import subprocess


def truncate_key(key: str) -> bytes:
    """
    truncate key to 16 bytes
    """
    assert key

    key = bytes(key, 'ascii') + bytes.fromhex('0' * 32)
    return key[:16]


def ip_pton(ip: str) -> int:
    ip_bytes = socket.inet_pton(socket.AF_INET, ip)
    return (int).from_bytes(ip_bytes, 'big')


def ip_ntop(ip: int) -> str:
    ip_bytes = (ip).to_bytes(4, 'big')
    return socket.inet_ntop(socket.AF_INET, ip_bytes)


def exec_cmd(cmd: str):
    bash_cmd = ['bash', '-c', cmd]
    child = subprocess.Popen(bash_cmd,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        universal_newlines=True, shell=False)

    stdout, _stderr = child.communicate()
    rc = child.returncode

    return (rc, stdout)
