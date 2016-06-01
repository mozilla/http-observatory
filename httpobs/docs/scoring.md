# HTTP Observatory Scoring Documentation

**Last Updated:** 2016-06-01 amuntner@mozilla.com
**Author:** april@mozilla.com

 Issue | Description | Modifier 
 --- | --- | --- 
 contribute-json-invalid-json | Contribute.json file cannot be parsed | -10 
 contribute-json-missing-required-keys | Contribute.json exists, but is missing some of the required keys | -5 
 contribute-json-not-implemented | Contribute.json file missing from root of website | -10 
 contribute-json-only-required-on-mozilla-properties | Contribute.json isn't required on websites that don't belong to Mozilla | 0 
 contribute-json-with-required-keys | Contribute.json implemented with the required contact information | 0 
 cookies-not-found | No cookies detected | 0 
 cookies-secure-with-httponly-sessions | All cookies use the Secure flag and all session cookies use the HttpOnly flag | 0 
 cookies-session-without-httponly-flag | Session cookie set without using the HttpOnly flag | -30 
 cookies-session-without-secure-flag-but-protected-by-hsts | Session cookie set without the Secure flag, but transmission over HTTP prevented by HSTS | -10 
 cookies-session-without-secure-flag | Session cookie set without using the Secure flag or set over http | -40 
 cookies-without-secure-flag-but-protected-by-hsts | Cookies set without using the Secure flag, but transmission over HTTP prevented by HSTS | -5 
 cookies-without-secure-flag | Cookies set without using the Secure flag or set over http | -20 
 cross-origin-resource-sharing-implemented-with-public-access | Public content is visible via cross-origin resource sharing (CORS) Access-Control-Allow-Origin header | 0 
 cross-origin-resource-sharing-implemented-with-restricted-access | Content is visible via cross-origin resource sharing (CORS) files or headers, but is restricted to specific domains | 0 
 cross-origin-resource-sharing-implemented-with-universal-access | Content is visible via cross-origin resource sharing (CORS) file or headers | -50 
 cross-origin-resource-sharing-not-implemented | Content is not visible via cross-origin resource sharing (CORS) files or headers | 0 
 csp-header-invalid | Content Security Policy (CSP) header cannot be parsed successfully | -25 
 csp-implemented-with-insecure-scheme | Content Security Policy (CSP) implemented, but allows resources to be loaded from http | -20 
 csp-implemented-with-no-unsafe | Content Security Policy (CSP) implemented without 'unsafe-inline' or 'unsafe-eval' | 5 
 csp-implemented-with-no-unsafe-default-src-none | Content Security Policy (CSP) implemented with default-src 'none' and no 'unsafe' | 10 
 csp-implemented-with-unsafe-eval | Content Security Policy (CSP) implemented, but allows 'unsafe-eval' | -10 
 csp-implemented-with-unsafe-inline | Content Security Policy (CSP) implemented, but allows 'unsafe-inline' inside script-src | -20 
 csp-implemented-with-unsafe-inline-in-style-src-only | Content Security Policy (CSP) implemented with 'unsafe-inline' inside style-src | 0 
 csp-not-implemented | Content Security Policy (CSP) header not implemented | -25 
 hpkp-header-invalid | HTTP Public Key Pinning (HPKP) header cannot be recognized | -5 
 hpkp-implemented-max-age-at-least-fifteen-days | HTTP Public Key Pinning (HPKP) header set to a minimum of 15 days (1296000) | 5 
 hpkp-implemented-max-age-less-than-fifteen-days | HTTP Public Key Pinning (HPKP) header set to less than 15 days (1296000) | 1 
 hpkp-not-implemented | HTTP Public Key Pinning (HPKP) header not implemented | 0 
 hpkp-not-implemented-no-https | HTTP Public Key Pinning (HPKP) header can't be implemented without https | 0 
 hpkp-preloaded | Preloaded via the HTTP Public Key Pinning (HPKP) preloading process | 5 
 hsts-header-invalid | HTTP Strict Transport Security (HSTS) header cannot be recognized | -20 
 hsts-implemented-max-age-at-least-six-months | HTTP Strict Transport Security (HSTS) header set to a minimum of six months (15768000) | 0 
 hsts-implemented-max-age-less-than-six-months | HTTP Strict Transport Security (HSTS) header set to less than six months (15768000) | -10 
 hsts-not-implemented | HTTP Strict Transport Security (HSTS) header not implemented | -20 
 hsts-not-implemented-no-https | HTTP Strict Transport Security (HSTS) header cannot be set for sites not available over https | -20 
 hsts-preloaded | Preloaded via the HTTP Strict Transport Security (HSTS) preloading process | 5 
 html-not-parsable | Claims to be html, but cannot be parsed | -20 
 redirection-missing | Does not redirect to an https site | -20 
 redirection-not-needed-no-http | Not able to connect via http, so no redirection necessary | 0 
 redirection-not-to-https-on-initial-redirection | Redirects to https eventually, but initial redirection is to another http URL | -10 
 redirection-not-to-https | Redirects, but final destination is not an https URL | -20 
 redirection-off-host-from-http | Initial redirection from http to https is to a different host, preventing HSTS | -5 
 redirection-to-https | Initial redirection is to https on same host, final destination is https | 0 
 request-did-not-return-status-code-200 | / did not return a status code of 200 | -5 
 sri-implemented-and-all-scripts-loaded-securely | Subresource Integrity (SRI) is implemented and all scripts are loaded from a similar origin | 5 
 sri-implemented-and-external-scripts-loaded-securely | Subresource Integrity (SRI) is implemented and all scripts are loaded securely | 5 
 sri-implemented-but-external-scripts-not-loaded-securely | Subresource Integrity (SRI) implemented, but external scripts are loaded over http | -20 
 sri-not-implemented-and-external-scripts-not-loaded-securely | Subresource Integrity (SRI) is not implemented, and external scripts are loaded over http | -50 
 sri-not-implemented-but-all-scripts-loaded-from-secure-origin | Subresource Integrity (SRI) not implemented as all scripts are loaded from a similar origin | 0 
 sri-not-implemented-but-external-scripts-loaded-securely | Subresource Integrity (SRI) not implemented, but all external scripts are loaded over https | -5 
 sri-not-implemented-but-no-scripts-loaded | Subresource Integrity (SRI) is not needed since site contains no script tags | 0 
 sri-not-implemented-response-not-html | Subresource Integrity (SRI) is only needed for html resources | 0 
 x-content-type-options-header-invalid | X-Content-Type-Options header cannot be recognized | -5 
 x-content-type-options-nosniff | X-Content-Type-Options header set to "nosniff" | 0 
 x-content-type-options-not-implemented | X-Content-Type-Options header not implemented | -5 
 x-frame-options-allow-from-origin | X-Frame-Options (XFO) header uses ALLOW-FROM uri directive | 0 
 x-frame-options-header-invalid | X-Frame-Options (XFO) header cannot be recognized | -20 
 x-frame-options-implemented-via-csp | X-Frame-Options (XFO) implemented via the CSP frame-ancestors directive | 5 
 x-frame-options-not-implemented | X-Frame-Options (XFO) header not implemented | -20 
 x-frame-options-sameorigin-or-deny | X-Frame-Options (XFO) header set to SAMEORIGIN or DENY | 0 
 xml-not-parsable | Claims to be xml, but cannot be parsed | -20 
 x-xss-protection-disabled | X-XSS-Protection header set to "0" (disabled) | -10 
 x-xss-protection-enabled-mode-block | X-XSS-Protection header set to "1; mode=block" | 0 
 x-xss-protection-enabled | X-XSS-Protection header set to "1" | 0 
 x-xss-protection-header-invalid | X-XSS-Protection header cannot be recognized | -10 
 x-xss-protection-not-implemented | X-XSS-Protection header not implemented | -10 
 x-xss-protection-not-needed-due-to-csp | X-XSS-Protection header not needed due to strong Content Security Policy (CSP) header | 0 


