from .content import contribute, subresource_integrity
from .headers import (content_security_policy, cookies, strict_transport_security,
                      x_content_type_options, x_xss_protection, x_frame_options)
from .misc import cross_origin_resource_sharing, redirection, tls_configuration

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
    redirection,
    strict_transport_security,
    subresource_integrity,
#    tls_configuration,  # TODO: renable this
    x_content_type_options,
    x_frame_options,
    x_xss_protection,
)

NUM_TESTS = len(tests)
TEST_NAMES = [test.__name__.replace('_', '-') for test in tests]
