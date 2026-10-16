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

### 只重跑換過的字典

從**已完成**的 run 沿用解析、Web crawl 與其他 scanner 結果；另建一個輸出目錄，不修改原 run。只傳要換的字典；傳兩份或三份就重跑對應的所有階段。例如只換 path 字典：

```bash
python3 scripts/web-recon.py --from-run ./runs/example \
  --paths-wordlist /usr/share/seclists/Discovery/Web-Content/big.txt \
  --out-dir ./runs/example-paths-big
```

同時換 path 與 extension 字典：

```bash
python3 scripts/web-recon.py --from-run ./runs/example \
  --paths-wordlist /usr/share/seclists/Discovery/Web-Content/big.txt \
  --extensions-wordlist /usr/share/seclists/Discovery/Web-Content/web-extensions.txt
```

`--from-run` 從原 run 的 `run.json` 讀 hostname 和 port。可以省略 `--host`、`--port`；若傳入，必須與單一 hostname 的原 run 相符。字典與執行階段的對應：

| 字典參數 | 本輪執行的階段 |
| --- | --- |
| `--host-prefixes-wordlist` | Gobuster DNS 字典與 ffuf vhost；沿用舊 DNS record、PTR、zone 與 AXFR 結果 |
| `--paths-wordlist` | ffuf path；如果舊 run 已確認 extension，也用新 path 字典重跑該 extension 的檔名掃描 |
| `--extensions-wordlist` | 已觀察檔名的 extension 掃描；確認 extension 後，沿用舊 path 字典做檔名掃描 |

同時傳 path 與 extension 字典時，完整 extension 掃描使用新 path 字典，不另外跑舊 extension 的檔名重掃。舊版 `--only` 命令仍可使用；舊 path 字典已搬走而只想重跑 extension 時，可用 `--only extensions --extensions-wordlist ... --paths-wordlist ...` 指定現有 path 字典，而不重跑 path 階段。這個 override 記在 `run.json` 的 `wordlists.extension_names_wordlist`，原 path 掃描使用的字典仍記在 `wordlists.paths_wordlist`。新 run 的 `report.md` 合併舊結果和本輪結果；`report.md` 與 `summary.json` 引用的舊 raw evidence 會複製到新 run 的 `hosts/<hostname>-<hash>/reused/`，因此這些連結在單獨搬移新 run 後仍可使用。字典路徑仍指向使用者指定的檔案；要再重跑需要該字典仍存在，或重新指定字典。讀取正在執行中的 run 會因缺少 `run.json` 而停止。
重跑的 exit code 依本輪指定階段判定；報表仍保留整個 host 的狀態，所以舊 DNS 階段 `unavailable` 可能讓 host 顯示 `partial`，即使新的 path 掃描完成。

執行開始會印出輸出目錄。終端顯示各階段的開始、完成、耗時，以及 `ffuf` 當次掃描的 `已測數/總數`；`progress.jsonl` 同步保存這些事件，可在另一個 terminal 用 `tail -f <輸出目錄>/progress.jsonl` 查看。DNS 與 Web 檢查可同時進行。每個 origin 的 vhost、path、extension 掃描預設依序執行；加入 `--scanner-workers 2` 或 `3` 可同時跑最多 2 或 3 個 `ffuf` 階段。每個 `ffuf` 仍各以 20 requests/s 為上限，因此 2 個 worker 的合計上限是 40 requests/s。`--hosts-file` 的 hostname 仍逐一處理。

`--public-sources` 才查 crt.sh 與 Wayback CDX；候選 hostname 不會在同一輪自動探測。`.htb` 等內部名稱不送到公共資料來源。當前服務的 TLS certificate SAN 始終檢查。來源、上限與輸出見 [公開資料來源](docs/public-sources.md)。

## 固定檢查

- 同一 port 分別試 HTTP 和 HTTPS；保存 root response、redirect 與 TLS certificate。初查允許 lab 的 self-signed certificate，TLS certificate 未做信任鏈驗證，SAN 只作 hostname 線索。
- 每個可用 origin 保存兩個隨機 missing path 作對照，再查 `robots.txt`、sitemap、少量 `/.well-known/`、`.git/HEAD`、`.env`、OpenAPI／Swagger 及常見資訊檔。沿 `robots.txt` 的 `Sitemap:` 查 sitemap index，最多讀 10 份 sitemap。sitemap URL 只列為候選，不逐一探測。
- 同站 crawl 預設最多 50 頁、深度 2。保存 link、form、field、HTML comment 及實際載入的 JavaScript；source map 只從已發現的 JavaScript 測。每份 body 最多 1 MiB；`--max-requests` 預設限制 Web request 總數為 200。超出頁數或 request 上限的 URL 留在候選清單。
- `dig` 查 records、PTR、SOA／NS、wildcard 對照，僅在確認輸入 hostname 本身是 zone 且 NS 回 authoritative SOA 後才試 AXFR。若系統解析靠 hosts entry 而 DNS server 沒有該 zone，DNS 階段標 `unavailable`，Web 與 vhost 階段仍照常執行。
- 固定路徑和 `ffuf` 命中都與 missing path／default vhost 對照。`baseline_match` 表示 response 與負控制相同；`candidate` 或 `different_from_missing_baseline` 需查看原始 response。scanner error 和部分結果分別保存。

## 結果

未指定 `--out-dir` 時，在目前目錄新建 `web-recon-YYYYMMDD-HHMMSS`，不覆寫舊執行。指定的輸出目錄須尚不存在。

**先看 `report.md`**：它把各 hostname 的完成狀態、候選與證據連結整理在同一個檔案。候選過多時顯示前 30 筆，完整清單仍在對應的 `summary.json`。舊版已完成的 run 也能直接生成報表，無須重新送 request：

```bash
python3 -m webrecon.report ./runs/old-run
```

```text
report.md                 整輪閱讀入口：狀態、候選、原始證據連結
run.json                  批次完成狀態
progress.jsonl            執行中的階段與 ffuf 進度
new-hosts.txt             可作下一輪 --hosts-file 輸入的候選 hostname
new-hosts.jsonl           候選來源、起始 hostname 與起始 host 的實際連線 IP:port
hosts/<hostname>-<hash>/summary.json
hosts/<hostname>-<hash>/responses/*.headers|*.body|*.meta|*.errors|*.jsonl
hosts/<hostname>-<hash>/tls/
hosts/<hostname>-<hash>/dns/
hosts/<hostname>-<hash>/scanners/
hosts/<hostname>-<hash>/reused/       重跑時複製的舊證據
hosts/<hostname>-<hash>/public/
```

`responses/*.jsonl` 由從 `pentest-notes` 複製的離線 `scripts/web-summary.py` 產生，抽出 headers、title、cookie 名稱相關 fingerprint、form／hidden field、link、script、comment 等線索；原始 response 仍保留在同一 prefix 的檔案。`new-hosts.txt` 是候選清單，使用前依 `new-hosts.jsonl` 的來源與目標範圍挑選。`source_ip_port` 指起始 Web host 的連線端點，並非候選 hostname 已解析的 IP；公共資料來源的候選沒有此映射。

原始檔數量多，是因為每次 Web request 分別保存 headers、body、curl 狀態、錯誤及離線摘要；每次 `dig`／`ffuf`／`gobuster` 也保存原始 output 與執行狀態。判讀候選時可從 `report.md` 的連結回查 response 和 missing-path／default-vhost 控制組；平常閱讀不需要逐一打開原始檔。

## 驗證

在 Mac 執行：

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile webrecon/*.py scripts/*.py
python3 verification/local_web.py
```

單元測試使用假的 DNS、HTTP、公共來源和 scanner 輸出。`local_web.py` 以受控 Web 服務執行完整 CLI。在 Kali 執行實際安裝的 `ffuf`、`gobuster` 和 `dig`：

```bash
python3 -m unittest discover -s tests -v
python3 verification/local_web.py
python3 verification/kali_scanners.py
python3 verification/kali_dns.py
```

後兩個腳本在 loopback 啟動受控 Web／DNS 服務並保存 scanner 原始 output；`kali_dns.py` 僅在測試過程為 `dig` 和 `gobuster` 指定受控 DNS server，平常執行 CLI 仍使用系統設定的 resolver。腳本會印出原始 output 的暫存目錄。

來源：`pentest-notes` 的 `discovery/`、`web/` 與 `scripts/web-summary.py`，以及 `sec-notes` 的 `recon/`、`protocols/` 與 `cheatsheets/`。`web-summary.py` 複製自 `pentest-notes` commit `b602578fd06756ae8b3bea6020991994d3ad8976`。
