from .geo import lookup as geo_lookup
from .dns import lookup as dns_lookup
from .rdap import lookup as rdap_lookup
from .risk import calculate


def lookup(ip):
    result = {}

    result.update(dns_lookup(ip))
    result.update(geo_lookup(ip))
    result.update(rdap_lookup(ip))

    result["risk_score"] = calculate(ip, result)

    result["ip"] = ip

    return result