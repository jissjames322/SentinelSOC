import ipaddress


def validate_event(event):
    required = ["ip", "event_type", "source"]

    for field in required:
        if not event.get(field):
            raise ValueError(f"Missing required field: {field}")

    ipaddress.ip_address(event["ip"])

    return True