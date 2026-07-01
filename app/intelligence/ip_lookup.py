import ipaddress
import socket

from ipwhois import IPWhois
import geoip2.database

reader = geoip2.database.Reader("database/GeoLite2-City.mmdb")


def lookup_ip(ip):

    result = {}

    try:

        ip_obj = ipaddress.ip_address(ip)

        result["ip"] = ip
        result["version"] = ip_obj.version
        result["private"] = ip_obj.is_private

        try:
            result["hostname"] = socket.gethostbyaddr(ip)[0]
        except:
            result["hostname"] = "Unknown"

        if not ip_obj.is_private:

            # WHOIS / ASN
            try:
                obj = IPWhois(ip)
                whois = obj.lookup_rdap(depth=1)

                result["asn"] = whois.get("asn")
                result["network"] = whois.get("network", {}).get("name")

            except:
                result["asn"] = "Unknown"
                result["network"] = "Unknown"

            # GEO LOCATION
            try:

                response = reader.city(ip)

                result["country"] = response.country.name
                result["state"] = response.subdivisions.most_specific.name
                result["city"] = response.city.name
                result["latitude"] = response.location.latitude
                result["longitude"] = response.location.longitude
                result["timezone"] = response.location.time_zone

            except:

                result["country"] = "Unknown"
                result["state"] = "Unknown"
                result["city"] = "Unknown"
                result["latitude"] = None
                result["longitude"] = None
                result["timezone"] = None

    except Exception as e:

        result["error"] = str(e)

    return result