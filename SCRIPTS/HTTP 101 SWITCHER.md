# HTTP 101 SWITCHING PROTOCOLS STUB SERVER

This is a minimal Python HTTP server that responds to every GET request with a bare `101 Switching Protocols` response and no body or further headers. It's commonly used as a quick-and-dirty test endpoint in HTTP smuggling/desync labs, where you need something on the other end of a connection to observe how a front-end proxy reacts to an unusual status code.
---
Usage: `python3 script.py [port]`
---
### courtesy of tryhackme:
```python
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
if len(sys.argv)-1 != 1:
    print("""
Usage: {} 
    """.format(sys.argv[0]))
    sys.exit()
class Redirect(BaseHTTPRequestHandler):
   def do_GET(self):
       self.protocol_version = "HTTP/1.1"
       self.send_response(101)
       self.end_headers()
HTTPServer(("", int(sys.argv[1])), Redirect).serve_forever()
```
