from ipwhois import IPWhois


def lookup(ip):
    try:
        obj = IPWhois(ip)
        rdap = obj.lookup_rdap(depth=1)

        return {
            "asn": rdap.get("asn"),
            "network": rdap.get("network", {}).get("name")
        }

    except Exception:
        return {
            "asn": None,
            "network": None
        }