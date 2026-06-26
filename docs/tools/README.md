# bbflow Tool Reference Docs

每個工具首次使用前，在 VPS 跑 `tool --help` 並建立對應文件。

## 建立流程

1. `ssh oracle-a1` → `tool --help` / `tool subcommand --help`
2. 本地也跑一次 `tool --version`，確認版本一致
3. 建立 `docs/tools/<tool>.md`，包含：
   - **版本號**（VPS + 本地）
   - **Command tree**（子命令結構）
   - **Key flags**（常用 flag 表格）
   - **Gotchas**（踩過的坑、平台差異）
   - **bbflow usage pattern**（在 hunter 裡的標準用法）

## 平台差異注意

| 類別 | 差異來源 | 處理方式 |
|------|---------|---------|
| Go 工具 flag | **版本**差異（非平台） | 兩邊裝同版本；doc 記版本號 |
| Python 工具 flag | **版本**差異 | `uv tool install tool==X.Y.Z` 鎖版 |
| 系統工具 (grep/sed) | **平台**差異（BSD vs GNU） | hunter 裡避免 `grep -P`；用 `grep -oE` + `sed` |
| 路徑/環境 | PATH 設定不同 | VPS 的 `~/go/bin` 需確認在 PATH |

## 版本快查

```bash
# VPS
ssh oracle-a1 'export PATH=$HOME/go/bin:$PATH; \
  gowitness version; cdncheck -version; gobuster --version; \
  puredns --version; crlfuzz -V; nomore403 --version'

# 本地
gowitness version; cdncheck -version; gobuster --version; \
  puredns --version; crlfuzz -V; nomore403 --version
```

## 現有文件

| Tool | Version | Doc |
|------|---------|-----|
| gowitness | v3.1.1 | [gowitness.md](gowitness.md) |
| cdncheck | v1.2.41 | [cdncheck.md](cdncheck.md) |
| wafw00f | v2.2.0 | [wafw00f.md](wafw00f.md) |
| nomore403 | dev | [nomore403.md](nomore403.md) |
| jsluice | latest | [jsluice.md](jsluice.md) |
| puredns | v2.1.1 | [puredns.md](puredns.md) |
| crlfuzz | v1.4.0 | [crlfuzz.md](crlfuzz.md) |
| gobuster | v3.8.2 | [gobuster.md](gobuster.md) |
