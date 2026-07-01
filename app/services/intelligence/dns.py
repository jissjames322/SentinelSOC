import socket


def lookup(ip):
    try:
        return {
            "hostname": socket.gethostbyaddr(ip)[0]
        }
    except Exception:
        return {
            "hostname": None
        }