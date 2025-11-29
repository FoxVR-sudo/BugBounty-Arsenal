# Rewardable Bug Bounty Scanning Techniques

## 1. Local File Inclusion (LFI)
- Path traversal payloads: `/etc/passwd`, `../etc/passwd`, `..%2f..%2fetc%2fpasswd`, `/home/user/.ssh/id_rsa`, etc.
- Null byte and extension tricks: `%00`, `.jpg`, `.png`
- Test for file read via API endpoints, parameters, or upload/download features.

## 2. Header Injection / Reflection
- Inject custom headers: `Host`, `User-Agent`, `X-Forwarded-Host`, etc.
- Observe for reflected values, response splitting, or cache poisoning.
- Use for bypassing access controls or triggering SSRF/redirects.

## 3. Excessive Data Exposure
- Query API endpoints for sensitive data: emails, phone numbers, API keys, tokens.
- Fuzz GraphQL and REST APIs for overbroad responses.
- Look for verbose error messages, debug info, or data leaks in JSON/XML.

## 4. XSS (Cross-Site Scripting)
- Inject payloads in parameters, JSON, or body: `<img src=x onerror=alert(1)>`, `<svg/onload=alert(1)>`, `javascript:`
- Test both reflected and stored vectors.
- Use DOM-based payloads for client-side JS sinks.

## 5. CSRF (Cross-Site Request Forgery)
- Check for missing or predictable CSRF tokens in forms and API requests.
- Attempt state-changing actions from another origin.

## 6. IDOR (Insecure Direct Object Reference)
- Manipulate IDs, user_id, doc_id, or array parameters to access other users' data.
- Fuzz with sequential, random, or out-of-range values.

## 7. SSRF (Server-Side Request Forgery)
- Supply URLs with internal IPs, gopher/file schemes, or metadata endpoints.
- Use DNS logging for OOB detection.

## 8. GraphQL Injection
- Introspection queries: `{__schema{types{name}}}`
- Deeply nested queries for DoS or data exposure.
- Fuzz for unauthorized field access.

## 9. File Upload Attacks
- Upload files with double extensions, polyglots, or dangerous content.
- Try to access uploaded files directly.

## 10. Request Smuggling
- Manipulate `Transfer-Encoding`, `Content-Length`, and chunked encoding headers.
- Look for desync or split responses.

---

> Този файл описва основните техники за сканиране и експлоатация, които са интегрирани в BugBounty-Arsenal за максимален награден потенциал (без DoS).
