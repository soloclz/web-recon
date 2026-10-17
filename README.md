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

### 自動接續前次結果

在同一個 engagement 目錄執行 `--host` 或 `--hosts-file` 加 `--port` 即可。第一次做完整初查；以後會自動沿用該 port 的前次結果，新的 hostname 才做完整初查，失敗的階段重試，字典路徑或內容改變時只更新對應階段。每輪仍建立新的 run 目錄與一份彙總 `report.md`。

```bash
python3 scripts/web-recon.py --hosts-file hosts.txt --port 443
```

未指定 `--out-dir` 時，以目前目錄作為 engagement 目錄；指定 `--out-dir` 時，以輸出目錄的 parent 為範圍。工具在該目錄的 `.web-recon/port-<port>.json` 記錄目前 run，並用 `Continuing:` 顯示本輪沿用的來源。舊版結果若只有一條可辨識的 run 歷史，第一次也可自動接續。若同一 port 有多條獨立歷史，用 `--extend-run SOURCE` 選一次來源；若要重新做完整初查，用 `--fresh`。

### 只重跑換過的字典

一般執行帶原本的 hostname／hosts file、port 和新字典即可自動更新對應階段。若要明確指定來源，`--from-run` 可只重跑指定的字典階段；它從**已完成**的 run 沿用解析、Web crawl 與其他 scanner 結果，另建一個輸出目錄。例如只換 path 字典：

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

### 把新 hostname 加入下一輪

如果 `hosts.txt` 同時有已掃過和新找到的 hostname，直接執行：

```bash
python3 scripts/web-recon.py --hosts-file hosts.txt --port 443
```

工具沿用來源 run 的 port、未指定的字典與掃描上限。新 hostname 做完整初查；舊 hostname 已完成的階段沿用，先前失敗的字典階段重試。達到相同 crawl／request 上限所造成的 Web `partial` 可沿用；response body 不完整則重試。解析、scheme、TLS 或 DNS 固定檢查未完成時，該 hostname 重新做完整初查。指定 `--public-sources` 時，舊 hostname 只補查尚未完成的公開資料來源。來源 run 裡即使有不在新 hosts file 的 hostname，仍保留在新報表，先前失敗的階段也會重試。新 run 的 `report.md` 在 `This run` 欄標示 `reused`、`updated`、`scanned` 或 `retry_failed`。重試失敗時，舊結果仍在報表，失敗嘗試另存並於下一輪再試；沿用結果引用的原始證據會複製進新 run，搬走來源 run 後連結仍可用。

若字典檔路徑或內容改變，自動接續只替舊 hostname 更新對應的 prefix、path 或 extension 階段，新 hostname 使用目前的字典。例如在加入新 host 時換 path 字典：

```bash
python3 scripts/web-recon.py --hosts-file hosts.txt --port 443 \
  --paths-wordlist /usr/share/seclists/Discovery/Web-Content/big.txt
```

完整新 run 會在 `run.json` 保存字典內容的 SHA-256，所以下一輪能辨識同一路徑的內容變更；自動接續也會保存本輪更新階段的 hash。舊版 run 沒有這個紀錄，沿用它的階段仍是未知 hash；若在原路徑改過字典，明確傳入該字典參數就會更新對應階段。沿用階段的字典檔即使已移走，仍可沿用結果；新 hostname 或需要更新的階段必須有對應字典檔。port 必須與來源 run 相同。`--extend-run` 需要來源 run 的 `run.json`，不能接正在執行中的 run。

新 run 會保存每個 hostname 使用的 Web 與 extension request 上限。下一輪明確改 `--max-pages`、`--max-depth`、`--max-body-bytes` 或 `--max-requests` 時，受影響的舊 hostname 重新做 Web 初查；只改 `--max-extra-requests` 時更新 extension 階段。舊版 run 沒有上限紀錄，已完成的 Web 結果可沿用，Web `partial` 會重新初查。工具不會在沒有連線的情況下得知遠端網站內容是否改變；要重新讀取已完成的網站，使用 `--fresh`。

根目錄的 `new-hosts.txt` 只列本輪結果中尚未作為輸入掃描的候選 hostname，可直接作下一輪的 `--hosts-file`；若使用自己累積的 hosts file，自動接續仍會排除已完成的 hostname。

執行開始會印出輸出目錄。終端顯示各階段的開始、完成與耗時。`HTTP vhost scan 9,222/114,438 tried (8%), elapsed 7m43s` 表示 ffuf 在 HTTP vhost 階段已測 9,222 個字典項，共 114,438 個；8% 只代表這個階段的進度，7m43s 是已耗時間。`progress.jsonl` 同步保存事件與原始 stage 名稱，可在另一個 terminal 用 `tail -f <輸出目錄>/progress.jsonl` 查看。DNS 與 Web 檢查可同時進行。每個 origin 的 vhost、path、extension 掃描預設依序執行；加入 `--scanner-workers 2` 或 `3` 可同時跑最多 2 或 3 個 `ffuf` 階段。`--ffuf-rate 10` 將每個 `ffuf` 程序限制為最多 10 requests/s；預設為 20。若有 2 個 worker，合計上限可達 20 requests/s。這個參數控制 vhost、path、extension 字典掃描，不控制 `gobuster dns` 或固定 Web 檢查。續跑會沿用前次 rate；指定新 rate 只影響新掃描或重試的階段，已完成的階段繼續沿用原始證據。ffuf 每個工作的 timeout 至少為 1 小時；大型字典會依項數與 rate 延長，實際值記在對應的 `*.status.json`。`--hosts-file` 的 hostname 仍逐一處理。

`--public-sources` 才查 crt.sh 與 Wayback CDX；候選 hostname 不會在同一輪自動探測。`.htb` 等內部名稱不送到公共資料來源。當前服務的 TLS certificate SAN 始終檢查。來源、上限與輸出見 [公開資料來源](docs/public-sources.md)。

## 固定檢查

- 同一 port 分別試 HTTP 和 HTTPS；保存 root response、redirect 與 TLS certificate。初查允許 lab 的 self-signed certificate，TLS certificate 未做信任鏈驗證，SAN 只作 hostname 線索。
- 每個可用 origin 保存兩個隨機 missing path 作對照，再查 `robots.txt`、sitemap、少量 `/.well-known/`、`.git/HEAD`、`.env`、OpenAPI／Swagger 及常見資訊檔。沿 `robots.txt` 的 `Sitemap:` 查 sitemap index，最多讀 10 份 sitemap。sitemap URL 只列為候選，不逐一探測。
- 同站 crawl 預設最多 50 頁、深度 2。保存 link、form、field、HTML comment 及實際載入的 JavaScript；source map 只從已發現的 JavaScript 測。每份 body 最多 1 MiB；`--max-requests` 預設限制 Web request 總數為 200。超出頁數或 request 上限的 URL 留在候選清單。
- `dig` 查 records、PTR、SOA／NS、wildcard 對照，僅在確認輸入 hostname 本身是 zone 且 NS 回 authoritative SOA 後才試 AXFR。若系統解析靠 hosts entry 而 DNS server 沒有該 zone，DNS 階段標 `unavailable`，Web 與 vhost 階段仍照常執行。
- 固定路徑和 `ffuf` 命中都與 missing path／default vhost 對照。`baseline_match` 表示 response 與負控制相同；`candidate` 或 `different_from_missing_baseline` 需查看原始 response。scanner error 和部分結果分別保存。

## 結果

未指定 `--out-dir` 時，在目前目錄新建 `web-recon-YYYYMMDD-HHMMSS`，不覆寫舊執行。指定的輸出目錄須尚不存在。自動接續的狀態保存在 engagement 目錄的 `.web-recon/`；移動或刪除目前 run 後，可用 `--extend-run SOURCE` 指向仍存在的來源，或用 `--fresh` 開始新歷史。

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
