# Web recon

給定一個 hostname 和 port，保存第一輪 Web、DNS 與字典掃描的原始證據及候選清單。適合對新發現的 subdomain 或 vhost 重複執行。工具使用系統解析結果；若 hostname 無法解析，該 hostname 的工作結束，批次中的其他 hostname 繼續。工具不修改 `/etc/hosts`。

## 執行

需要 Python 3.10+、`curl`、`dig` 和 `openssl`。字典階段另需 `ffuf`、`gobuster`。未提供字典時不啟動字典階段；工具缺失會在該階段標為 `unavailable`。

```bash
python3 scripts/web-recon.py --host app.example.test --port 8080
python3 scripts/web-recon.py --hosts-file hosts.txt --port 443 \
  --host-prefixes-wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --paths-wordlist /usr/share/seclists/Discovery/Web-Content/common.txt \
  --extensions-wordlist /usr/share/seclists/Discovery/Web-Content/web-extensions.txt \
  --out-dir ./runs/example
```

`hosts.txt` 每行一個 hostname，可用 `#` 註解。字典的路徑由使用者指定，工具不內建字典。`--host-prefixes-wordlist` 的每個字只接在**輸入的 hostname** 前：輸入 `app.example.test` 與 `admin` 時，測 `admin.app.example.test`。同一份字典分別交給 `gobuster dns` 與 `ffuf` vhost；後者使用 `Host` header。HTTPS vhost 的 `Host` 差異仍是候選，須另用該 hostname 的 SNI 核對。

`--paths-wordlist` 由 `ffuf` 掃根路徑，不遞迴。`--extensions-wordlist` 先測 `indexFUZZ` 等已觀察檔名；如找到與 missing baseline 不同的 `.php` response，才用 path 字典測 `FUZZ.php`。`--max-extra-requests` 限制這個第二階段的 request 數，預設 100,000。三種字典可各自省略。

`--public-sources` 才查 crt.sh 與 Wayback CDX；候選 hostname 不會在同一輪自動探測。`.htb` 等內部名稱不送到公共資料來源。當前服務的 TLS certificate SAN 始終檢查。來源、上限與輸出見 [公開資料來源](docs/public-sources.md)。

## 固定檢查

- 同一 port 分別試 HTTP 和 HTTPS；保存 root response、redirect 與 TLS certificate。初查允許 lab 的 self-signed certificate，TLS certificate 未做信任鏈驗證，SAN 只作 hostname 線索。
- 每個可用 origin 保存兩個隨機 missing path 作對照，再查 `robots.txt`、sitemap、少量 `/.well-known/`、`.git/HEAD`、`.env`、OpenAPI／Swagger 及常見資訊檔。沿 `robots.txt` 的 `Sitemap:` 查 sitemap index，最多讀 10 份 sitemap。sitemap URL 只列為候選，不逐一探測。
- 同站 crawl 預設最多 50 頁、深度 2。保存 link、form、field、HTML comment 及實際載入的 JavaScript；source map 只從已發現的 JavaScript 測。每份 body 最多 1 MiB；`--max-requests` 預設限制 Web request 總數為 200。超出頁數或 request 上限的 URL 留在候選清單。
- `dig` 查 records、PTR、SOA／NS、wildcard 對照，僅在確認輸入 hostname 本身是 zone 且 NS 回 authoritative SOA 後才試 AXFR。若系統解析靠 hosts entry 而 DNS server 沒有該 zone，DNS 階段標 `unavailable`，Web 與 vhost 階段仍照常執行。
- 固定路徑和 `ffuf` 命中都與 missing path／default vhost 對照。`baseline_match` 表示 response 與負控制相同；`candidate` 或 `different_from_missing_baseline` 需查看原始 response。scanner error 和部分結果分別保存。

## 結果

未指定 `--out-dir` 時，在目前目錄新建 `web-recon-YYYYMMDD-HHMMSS`，不覆寫舊執行。指定的輸出目錄須尚不存在。

```text
run.json                  批次完成狀態
new-hosts.txt             可作下一輪 --hosts-file 輸入的候選 hostname
new-hosts.jsonl           候選來源、起始 hostname 與起始 host 的實際連線 IP:port
hosts/<hostname>-<hash>/summary.json
hosts/<hostname>-<hash>/responses/*.headers|*.body|*.meta|*.errors|*.jsonl
hosts/<hostname>-<hash>/tls/
hosts/<hostname>-<hash>/dns/
hosts/<hostname>-<hash>/scanners/
hosts/<hostname>-<hash>/public/
```

`responses/*.jsonl` 由從 `pentest-notes` 複製的離線 `scripts/web-summary.py` 產生，抽出 headers、title、cookie 名稱相關 fingerprint、form／hidden field、link、script、comment 等線索；原始 response 仍保留在同一 prefix 的檔案。`new-hosts.txt` 是候選清單，使用前依 `new-hosts.jsonl` 的來源與目標範圍挑選。`source_ip_port` 指起始 Web host 的連線端點，並非候選 hostname 已解析的 IP；公共資料來源的候選沒有此映射。

## 驗證

在 Mac 執行：

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile webrecon/*.py scripts/*.py
```

單元測試使用假的 DNS、HTTP、公共來源和 scanner 輸出。Kali 的 `ffuf`、`gobuster`、`dig` 與受控 Web／DNS 服務整合測試須在能連到 Kali 的環境執行，並以當地安裝版本的 `--help` 和原始輸出核對。

來源：`pentest-notes` 的 `discovery/`、`web/` 與 `scripts/web-summary.py`，以及 `sec-notes` 的 `recon/`、`protocols/` 與 `cheatsheets/`。`web-summary.py` 複製自 `pentest-notes` commit `b602578fd06756ae8b3bea6020991994d3ad8976`。
