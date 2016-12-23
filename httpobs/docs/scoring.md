# HTTP Observatory Scoring Methodology

**Last Updated:** 2016-06-13 april@mozilla.com<br>
**Author:** april@mozilla.com

All websites start with a baseline score of 100, and then receive penalties or bonuses from there. Although the minimum score is 0, there is no maximum score. Currently, the highest possible score in the HTTP Observatory is 135.

Note that although both the letter grade ranges and modifiers are essentially arbitrary, they are based on feedback from industry professionals on how important passing or failing a given test is likely to be.

## Grading Chart

Scoring Range | Grade
:---: | :---:
100+ | &nbsp;A+
90-99 | &nbsp;A&nbsp;
85-89 | &nbsp;A-
80-84 | &nbsp;B+
70-79 | &nbsp;B&nbsp;
65-69 | &nbsp;B-
60-64 | &nbsp;C+
50-59 | &nbsp;C&nbsp;
45-49 | &nbsp;C-
40-44 | &nbsp;D+
30-39 | &nbsp;D&nbsp;
25-29 | &nbsp;D-
0-24 | &nbsp;F&nbsp;

## Score Modifiers

[Contribute.json](https://www.contributejson.org/) | Description | Modifier
--- | --- | :---:
contribute-json-only-required-on-mozilla-properties | Contribute.json isn't required on websites that don't belong to Mozilla | 0
contribute-json-with-required-keys | Contribute.json implemented with the required contact information | 0
contribute-json-missing-required-keys | Contribute.json exists, but is missing some of the required keys | -5
contribute-json-not-implemented | Contribute.json file missing from root of website | -5
contribute-json-invalid-json | Contribute.json file cannot be parsed | -10
<br>

[Cookies](https://wiki.mozilla.org/Security/Guidelines/Web_Security#Cookies) | Description | Modifier
--- | --- | :---:
cookies-not-found | No cookies detected | 0
cookies-secure-with-httponly-sessions | All cookies use the `Secure` flag and all session cookies use the `HttpOnly` flag | 0
cookies-without-secure-flag-<br>but-protected-by-hsts | Cookies set without using the `Secure` flag, but transmission over HTTP prevented by HSTS | -5
cookies-session-without-secure-flag-<br>but-protected-by-hsts | Session cookie set without the `Secure` flag, but transmission over HTTP prevented by HSTS | -10
cookies-without-secure-flag | Cookies set without using the `Secure` flag or set over http | -20
cookies-session-without-httponly-flag | Session cookie set without using the `HttpOnly` flag | -30
cookies-session-without-secure-flag | Session cookie set without using the `Secure` flag or set over http | -40
<br>

[Cross-origin Resource Sharing (CORS)](https://wiki.mozilla.org/Security/Guidelines/Web_Security#Cross-origin_Resource_Sharing) | Description | Modifier
--- | --- | :---:
cross-origin-resource-sharing-<br>implemented-with-public-access | Public content is visible via cross-origin resource sharing (CORS) Access-Control-Allow-Origin header | 0
cross-origin-resource-sharing-<br>implemented-with-restricted-access | Content is visible via cross-origin resource sharing (CORS) files or headers, but is restricted to specific domains | 0
cross-origin-resource-sharing-not-implemented | Content is not visible via cross-origin resource sharing (CORS) files or headers | 0
xml-not-parsable | crossdomain.xml or clientaccesspolicy.xml claims to be xml, but cannot be parsed | -20
cross-origin-resource-sharing-<br>implemented-with-universal-access | Content is visible via cross-origin resource sharing (CORS) file or headers | -50
<br>

[Content Security Policy](https://wiki.mozilla.org/Security/Guidelines/Web_Security#Content_Security_Policy) | Description | Modifier
--- | --- | :---:
csp-implemented-with-no-unsafe-default-src-none | Content Security Policy (CSP) implemented with `default-src 'none'` and without `'unsafe-inline'` or `'unsafe-eval'` | 10
csp-implemented-with-no-unsafe | Content Security Policy (CSP) implemented without `'unsafe-inline'` or `'unsafe-eval'` | 5
csp-implemented-with-unsafe-inline-in-style-src-only | Content Security Policy (CSP) implemented with unsafe directives inside `style-src`. This includes `'unsafe-inline'`, `data:`, or overly broad sources such as `https:`. | 0
csp-implemented-with-unsafe-eval | Content Security Policy (CSP) implemented unsafely, with `'unsafe-eval'` | -10
csp-implemented-with-insecure-scheme | Content Security Policy (CSP) implemented, but secure site allows resources to be loaded from http | -20
csp-implemented-with-unsafe-inline | Content Security Policy (CSP) implemented unsafely. This includes `'unsafe-inline'` or `data:` inside `script-src`, overly broad sources such as `https:` inside `object-src` or `script-src`, or not restricting the sources for `object-src` or `script-src`. | -20
csp-not-implemented | Content Security Policy (CSP) header not implemented | -25
csp-header-invalid | Content Security Policy (CSP) header cannot be parsed successfully | -25
<br>

[HTTP Public Key Pinning](https://wiki.mozilla.org/Security/Guidelines/Web_Security#HTTP_Public_Key_Pinning) | Description | Modifier
--- | --- | :---:
hpkp-preloaded | Preloaded via the HTTP Public Key Pinning (HPKP) preloading process | 5
hpkp-implemented-<br>max-age-at-least-fifteen-days | HTTP Public Key Pinning (HPKP) header set to a minimum of 15 days (1296000) | 5
hpkp-implemented-<br>max-age-less-than-fifteen-days | HTTP Public Key Pinning (HPKP) header set to less than 15 days (1296000) | 1
hpkp-header-invalid | HTTP Public Key Pinning (HPKP) header cannot be recognized | -5
hpkp-not-implemented | HTTP Public Key Pinning (HPKP) header not implemented | 0
hpkp-invalid-cert | HTTP Public Key Pinning (HPKP) header cannot be set, as site contains an invalid certificate chain | 0
hpkp-not-implemented-no-https | HTTP Public Key Pinning (HPKP) header can't be implemented without https | 0
<br>

[HTTP Strict Transport Security](https://wiki.mozilla.org/Security/Guidelines/Web_Security#HTTP_Strict_Transport_Security) | Description | Modifier
--- | --- | :---:
hsts-preloaded | Preloaded via the HTTP Strict Transport Security (HSTS) preloading process | 5
hsts-implemented-<br>max-age-at-least-six-months | HTTP Strict Transport Security (HSTS) header set to a minimum of six months (15768000) | 0
hsts-implemented-<br>max-age-less-than-six-months | HTTP Strict Transport Security (HSTS) header set to less than six months (15768000) | -10
hsts-not-implemented | HTTP Strict Transport Security (HSTS) header not implemented | -20
hsts-not-implemented-no-https | HTTP Strict Transport Security (HSTS) header cannot be set for sites not available over https | -20
hsts-invalid-cert | HTTP Strict Transport Security (HSTS) header cannot be set, as site contains an invalid certificate chain | -20
hsts-header-invalid | HTTP Strict Transport Security (HSTS) header cannot be recognized | -20
<br>

[Redirections](https://wiki.mozilla.org/Security/Guidelines/Web_Security#HTTP_Redirections) | Description | Modifier
--- | --- | :---:
redirection-all-redirects-preloaded | All hosts redirected to are in the HTTP Strict Transport Security (HSTS) preload list | 0
redirection-to-https | Initial redirection is to https on same host, final destination is https | 0
redirection-not-needed-no-http | Not able to connect via http, so no redirection necessary | 0
redirection-off-host-from-http | Initial redirection from http to https is to a different host, preventing HSTS | -5
redirection-not-to-https-on-initial-redirection | Redirects to https eventually, but initial redirection is to another http URL | -10
redirection-missing | Does not redirect to an https site | -20
redirection-not-to-https | Redirects, but final destination is not an https URL | -20
redirection-invalid-cert | Invalid certificate chain encountered during redirection | -20
<br>

[Referrer Policy](https://wiki.mozilla.org/Security/Guidelines/Web_Security#Referrer_Policy) | Description | Modifier
--- | --- | :---:
referrer-policy-private | `Referrer-Policy` header set to `no-referrer` or `same-origin`, `strict-origin` or `strict-origin-when-cross-origin` | 5
referrer-policy-no-referrer-when-downgrade | `Referrer-Policy` header set to `no-referrer-when-downgrade` | 0
referrer-policy-not-implemented | `Referrer-Policy` header not implemented | 0
referrer-policy-unsafe | Referrer-Policy header unsafely set to `origin`, `origin-when-cross-origin`, or `unsafe-url` | -5
referrer-policy-header-invalid | `Referrer-Policy` header cannot be recognized | -5
<br>

[Subresource Integrity](https://wiki.mozilla.org/Security/Guidelines/Web_Security#Subresource_Integrity) | Description | Modifier
--- | --- | :---:
sri-implemented-<br>and-all-scripts-loaded-securely | Subresource Integrity (SRI) is implemented and all scripts are loaded from a similar origin | 5
sri-implemented-<br>and-external-scripts-loaded-securely | Subresource Integrity (SRI) is implemented and all scripts are loaded securely | 5
sri-not-implemented-<br>but-all-scripts-loaded-from-secure-origin | Subresource Integrity (SRI) not implemented as all scripts are loaded from a similar origin | 0
sri-not-implemented-<br>but-no-scripts-loaded | Subresource Integrity (SRI) is not needed since site contains no script tags | 0
sri-not-implemented-<br>response-not-html | Subresource Integrity (SRI) is only needed for html resources | 0
sri-not-implemented-<br>but-external-scripts-loaded-securely | Subresource Integrity (SRI) not implemented, but all external scripts are loaded over https | -5
request-did-not-return-status-code-200 | / did not return a status code of 200 | -5
sri-implemented-<br>but-external-scripts-not-loaded-securely | Subresource Integrity (SRI) implemented, but external scripts are loaded over http | -20
html-not-parsable | Claims to be html, but cannot be parsed | -20
sri-not-implemented-<br>and-external-scripts-not-loaded-securely | Subresource Integrity (SRI) is not implemented, and external scripts are loaded over http | -50
<br>

[X-Content-Type-Options](https://wiki.mozilla.org/Security/Guidelines/Web_Security#X-Content-Type-Options) | Description | Modifier
--- | --- | :---:
x-content-type-options-nosniff | `X-Content-Type-Options` header set to `nosniff` | 0
x-content-type-options-not-implemented | `X-Content-Type-Options` header not implemented | -5
x-content-type-options-header-invalid | `X-Content-Type-Options` header cannot be recognized | -5
<br>

[X-Frame-Options](https://wiki.mozilla.org/Security/Guidelines/Web_Security#X-Frame-Options) | Description | Modifier
--- | --- | :---:
x-frame-options-implemented-via-csp | `X-Frame-Options` (XFO) implemented via the CSP `frame-ancestors` directive | 5
x-frame-options-allow-from-origin | `X-Frame-Options` (XFO) header uses `ALLOW-FROM uri` directive | 0
x-frame-options-sameorigin-or-deny | `X-Frame-Options` (XFO) header set to `SAMEORIGIN` or `DENY` | 0
x-frame-options-not-implemented | `X-Frame-Options` (XFO) header not implemented | -20
x-frame-options-header-invalid | `X-Frame-Options` (XFO) header cannot be recognized | -20
<br>

[X-XSS-Protection](https://wiki.mozilla.org/Security/Guidelines/Web_Security#X-XSS-Protection) | Description | Modifier
--- | --- | :---:
x-xss-protection-not-needed-due-to-csp | `X-XSS-Protection` header not needed due to strong Content Security Policy (CSP) header | 0
x-xss-protection-enabled-mode-block | `X-XSS-Protection` header set to `1; mode=block` | 0
x-xss-protection-enabled | `X-XSS-Protection` header set to `1` | 0
x-xss-protection-disabled | `X-XSS-Protection` header set to `0` (disabled) | -10
x-xss-protection-not-implemented | `X-XSS-Protection` header not implemented | -10
x-xss-protection-header-invalid | `X-XSS-Protection` header cannot be recognized | -10
