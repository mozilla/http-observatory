from .content import subresource_integrity
from .headers import (
    content_security_policy,
    cookies,
    referrer_policy,
    strict_transport_security,
    x_content_type_options,
    x_frame_options,
    x_xss_protection,
)
from .misc import cross_origin_resource_sharing, redirection

__all__ = ['NUM_TESTS', 'tests', 'TEST_NAMES']

tests = (
    content_security_policy,
    cookies,
    cross_origin_resource_sharing,
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
