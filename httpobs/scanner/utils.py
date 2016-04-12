import socket


def sanitize_headers(headers: dict) -> dict:
    """
    :param headers: raw headers object from a request's response
    :return: that same header, after sanitization
    """
    try:
        if len(str(headers)) <= 16384:
            return dict(headers)
        else:
            return None

    except:
        return None


def valid_hostname(hostname: str):
    """
    :param hostname: The hostname requested in the scan
    :return: Hostname if it's valid, otherwise False
    """

    # Block attempts to scan things like 'localhost'
    if '.' not in hostname or 'localhost' in hostname:
        return False

    # First, let's try to see if it's an IPv4 address
    try:
        socket.inet_aton(hostname)  # inet_aton() will throw an exception if hostname is not a valid IP address
        return False                # If we get this far, it's an IP address and therefore not a valid fqdn
    except:
        pass

    # And IPv6
    try:
        socket.inet_pton(socket.AF_INET6, hostname)  # same as inet_aton(), but for IPv6
        return False
    except:
        pass

    # Then, try to do a lookup on the hostname; this should return at least one entry and should be the first time
    # that the validator is making a network connection -- the same that requests would make.
    try:
        hostname_ips = socket.getaddrinfo(hostname, 443)

        # This shouldn't trigger, since getaddrinfo should generate saierror if there's no A records.  Nevertheless,
        # I want to be careful in case of edge cases.  This does make it hard to test.
        if len(hostname_ips) < 1:
            return False
    except:
        return False

    # If we've made it this far, then everything is good to go!  Woohoo!
    return hostname
