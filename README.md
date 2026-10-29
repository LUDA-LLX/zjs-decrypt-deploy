# zjs-decrypt-deploy

ljzd 工具站 —— **Streamlit Community Cloud 部署副本**(临时)。

仅含部署必需文件;访问码通过 Streamlit Secrets(`ACCESS_CODE`)配置,不入仓库。
主源码(含 CLI/自托管等)在私有仓库 `1Charizard/zjs-decrypt`。

- `streamlit_app.py` — Streamlit 应用(上传 .zjs + 登录态 → 解密 → 下载)
- `decrypt_zjs.py` — 解密核心
- `requirements.txt` — 依赖

> 仅供部署;请仅解密你有权使用的脚本。
