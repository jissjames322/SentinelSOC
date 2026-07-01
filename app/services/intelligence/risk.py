import ipaddress


def calculate(ip, data):
    score = 0

    try:
        ip_obj = ipaddress.ip_address(ip)

        if ip_obj.is_private:
            score += 0
        else:
            score += 10

        if data.get("hostname") is None:
            score += 5

        if data.get("country") is None:
            score += 5

    except Exception:
        score = 100

    return score