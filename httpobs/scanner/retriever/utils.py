def get_duplicate_header_values(response, header) -> list:
    # According to RFC 2616, when two headers with the same name are sent then user agents are technically
    # supposed to combine them with a comma. However, some things (like CSP) are not treated that way,
    # and instead treated as if the policy has been sent multiple times. This allows code to retrieve
    # a list of every header instance.
    """
    Args:
        response: the raw response object from requests
        header: the header that one is looking for (e.g. Content-Security-Policy)

    Returns:
        all instances of that header, as a list

    """
    return [v for k, v in response.raw.headers.items() if k.lower().strip() == header.lower()]
