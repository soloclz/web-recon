### 公開資料來源

`--public-sources` 會查 [crt.sh 的 JSON 查詢](https://groups.google.com/g/crtsh/c/sCpRljHP4dw) 與 [Wayback CDX API](https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server)。前者收集 `name_value` 中屬於輸入 hostname 之下的名稱；後者收集同一 hostname 與其 subdomain 的歷史 URL。查詢結果只是候選，程式不會對其中的 hostname 或 URL 發出 request。

每個來源最多保留 500 筆，response 最多讀取 4 MiB，單次查詢 timeout 為 15 秒。原始 JSON 分別保存在 `crtsh.json`、`wayback-cdx.json`。結果含各來源的 `status`、查詢 URL、候選數與 artifact 路徑；單一來源失敗時仍保留另一來源的候選。`.htb`、`.local`、IP 等不適合公開索引的名稱標為 `unavailable`。

整合時以 `from webrecon.public import run_public_sources` 呼叫 `run_public_sources(host, output_directory)`。回傳的 `candidates` 分為 `hostname`、`hostname_pattern` 與 `url`，每筆皆有 `source`。只將 `hostname` 寫入下一輪 hostname 候選清單；`hostname_pattern` 保留 wildcard 模式，`url` 留作歷史路徑線索。
