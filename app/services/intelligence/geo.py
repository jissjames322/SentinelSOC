import geoip2.database

reader = geoip2.database.Reader("database/GeoLite2-City.mmdb")


def lookup(ip):
    try:
        response = reader.city(ip)

        return {
            "country": response.country.name,
            "state": response.subdivisions.most_specific.name,
            "city": response.city.name,
            "latitude": response.location.latitude,
            "longitude": response.location.longitude,
            "timezone": response.location.time_zone,
        }

    except Exception:
        return {
            "country": None,
            "state": None,
            "city": None,
            "latitude": None,
            "longitude": None,
            "timezone": None,
        }