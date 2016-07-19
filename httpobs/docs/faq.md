# HTTP Observatory FAQ

**Last Updated:** 2016-07-06<br>
**Author:** april@mozilla.com

## Frequently Asked Questions

**What is the scoring methodology based on?**

It is extremely difficult to assign an objective value to a subjective criteria such as "How bad is it that a given site doesn't implement HTTP Strict Transport Security?"  This is complicated by the fact that what may be bad for one site -- such as not implementing Content Security Policy (CSP) on a site that contains user information -- may not be as bad for another site.

The scores and grades offered by the HTTP Observatory are based on the opinions of a wide variety of information security professionals, and largely reflect the relative importance written about in the official [Mozilla web security guidelines](https://wiki.mozilla.org/Security/Guidelines/Web_Security).

**Can I use the HTTP Observatory for API endpoints?**

The HTTP Observatory is designed around scanning websites, not API endpoints. This is not to say that it *can't* be used for API endpoints, just that the results may not reflect the actual security posture of the API. Nevertheless, the various security headers expected by the HTTP Observatory shouldn't cause any negative impact for APIs that return exclusively data, such as JSON or XML. The recommended configuration for API endpoints is:

```
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
Strict-Transport-Security: max-age=31536000
X-Content-Type-Options: nosniff
```

Results returned from the TLS Observatory are accurate for both API endpoints and websites.

**What is the maximum and minimum possible score?**

The current maximum possible score is 130 out of 100.  The minimum score is always 0, regardless of how badly a site does.

For details, please see [grade.py](https://github.com/mozilla/http-observatory/blob/master/httpobs/scanner/grader/grade.py), and to see a list of the most recent "perfect" scoring websites, you can use the [getRecentScans API](https://http-observatory.security.mozilla.org/api/v1/getRecentScans?min=130&num=25).