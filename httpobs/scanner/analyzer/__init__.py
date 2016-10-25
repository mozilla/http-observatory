from .content import contribute, subresource_integrity
from .headers import (content_security_policy, cookies, public_key_pinning, referrer_policy, strict_transport_security,
                      x_content_type_options, x_xss_protection, x_frame_options)
from .misc import cross_origin_resource_sharing, redirection

__all__ = [
    'NUM_TESTS',
    'tests',
    'TEST_NAMES'
]

tests = (
    content_security_policy,
    cookies,
    contribute,
    cross_origin_resource_sharing,
    public_key_pinning,
    redirection,
    referrer_policy,
    strict_transport_security,
    subresource_integrity,
    x_content_type_options,
    x_frame_options,
    x_xss_protection,
)

NUM_TESTS = len(tests)
TEST_NAMES = [test.__name__.replace('_', '-') for test in tests]
