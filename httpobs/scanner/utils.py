import socket
import tld


def is_valid_hostname(hostname: str) -> bool:
    """
    :param hostname:
    :return: True if it's a valid hostname, False otherwise
    """

    # First, try to look it up
    try:
        sai = socket.getaddrinfo(hostname, 443)

        if len(sai) < 1:
            return False
    except:
        return False

    # Then, let's try to see if it's an IPv4 address
    try:
        socket.inet_aton(hostname)
        return False
    except:
        pass

    # And IPv6
    try:
        socket.inet_pton(socket.AF_INET6, hostname)
        return False
    except:
        pass

    # Finally, let's see if it's a TLD
    if hostname in tld.get_tld_names():
        return False

    # If we've made it this far, then everything is good to go!  Woohoo!
    return True
