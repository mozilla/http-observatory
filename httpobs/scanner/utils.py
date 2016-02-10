import socket
import tld


def is_valid_hostname(hostname: str) -> bool:
    """
    :param hostname: The hostname requested in the scan
    :return: True if it's a valid hostname (fqdn in DNS that's not an IP address), False otherwise
    """
    
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

    # Then, let's see if it's a TLD; this includes things fuel.aero or co.uk that look like fqdns but aren't
    if hostname in tld.get_tld_names():
        return False

    # Then, try to do a lookup on the hostname; this should return at least one entry and should be the first time
    # that the validator is making a network connection -- the same that requests would make.
    try:
        hostname_ips = socket.getaddrinfo(hostname, 443)

        if len(hostname_ips) < 1:
            return False
    except:
        return False

    # If we've made it this far, then everything is good to go!  Woohoo!
    return True


def sanitize(output: dict):
    SCAN_VALID_KEYS = ('end_time', 'error', 'grade', 'grade_reasons', 'result_id', 'start_time', 'state',
                       'tests_completed', 'tests_failed', 'tests_passed', 'tests_quantity')

    # Convert it to a dict (in case it's a DictRow)
    output = dict(output)

    if 'tests_quantity' in output:  # autodetect that it's a scan
        # Rename 'id' to 'result_id':
        output['result_id'] = output.pop('id')

        # Remove 'error' if it's null
        if output['error'] == None:
            del(output['error'])

        # Delete any other things that might have made their way into the results
        output = {k: output[k] for k in SCAN_VALID_KEYS if k in output}

    return output
