import socket


def valid_hostname(hostname: str):
    """
    :param hostname: The hostname requested in the scan
    :return: Hostname if it's valid, otherwise None
    """

    # First, let's try to see if it's an IPv4 address
    try:
        socket.inet_aton(hostname)  # inet_aton() will throw an exception if hostname is not a valid IP address
        return None                # If we get this far, it's an IP address and therefore not a valid fqdn
    except:
        pass

    # And IPv6
    try:
        socket.inet_pton(socket.AF_INET6, hostname)  # same as inet_aton(), but for IPv6
        return None
    except:
        pass

    # Then, try to do a lookup on the hostname; this should return at least one entry and should be the first time
    # that the validator is making a network connection -- the same that requests would make.
    try:
        hostname_ips = socket.getaddrinfo(hostname, 443)

        if len(hostname_ips) < 1:
            return None
    except:
        return None

    # If we've made it this far, then everything is good to go!  Woohoo!
    return hostname
