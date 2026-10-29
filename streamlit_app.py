#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ljzd 工具站 —— Streamlit Community Cloud 版(免费纯云)
部署: https://streamlit.io/cloud (GitHub 登录 -> New app -> 本仓库 -> streamlit_app.py)
访问码: 在 Streamlit 的 App Settings -> Secrets 中配置 ACCESS_CODE(本文件自动读取)

本地运行:
  pip install -r requirements-streamlit.txt
  streamlit run streamlit_app.py
"""
import json
import os
import shutil
import tempfile
import traceback

import streamlit as st

import decrypt_zjs as dz

try:
    ACCESS_CODE = st.secrets.get('ACCESS_CODE', '')
except Exception:
    ACCESS_CODE = os.environ.get('ACCESS_CODE', '')

st.set_page_config(page_title='ljzd 工具站', page_icon='🔓', layout='centered')

st.title('🔓 ljzd 工具站')
st.caption('免费纯云(Streamlit) · HTTPS 自动 · 上传文件与登录态仅本次请求处理, 不留存')


def do_decrypt(code, file_bytes, filename, token, userid, deviceid):
    if ACCESS_CODE and code != ACCESS_CODE:
        return None, '❌ 访问码错误'
    if not filename.lower().endswith('.zjs'):
        return None, '❌ 仅支持 .zjs 文件'
    token = (token or '').strip()
    userid = (userid or '').strip()
    deviceid = (deviceid or '').strip()
    if not token or not userid:
        return None, '❌ 请填写 token 与 userId'

    cfg = {
        'token': token,
        'user_id': userid,
        'device_id': deviceid,
        'apk_sign': dz.DEFAULT_APK_SIGN,
        'channel': dz.DEFAULT_CHANNEL,
        'api_base': dz.API_BASE,
    }
    workdir = tempfile.mkdtemp(prefix='zjs_dec_')
    try:
        src = os.path.join(workdir, filename)
        with open(src, 'wb') as f:
            f.write(file_bytes)
        out_lines, hdr, stats = dz.decrypt_zjs_file(src, cfg, verbose=False)
        base = filename[:-4] if filename.lower().endswith('.zjs') else filename
        plain = ('\r\n'.join(out_lines) + '\r\n').encode('utf-8')
        blocks = len(stats)
        cnt = hdr.get('count') if isinstance(hdr, dict) else None
        msg = f'✅ 解密成功: 加密块 {blocks} 个'
        if cnt is not None:
            msg += f', 头部动作数 {cnt}'
        return (base + '_解密.zjs', plain), msg
    except Exception as e:
        traceback.print_exc()
        return None, '❌ 解密失败: %s' % e
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


with st.form('decrypt_form', clear_on_submit=False):
    code = st.text_input('访问码(站长发放)', type='password')
    fup = st.file_uploader('① 上传加密 .zjs 脚本', type=['zjs'])
    col1, col2 = st.columns(2)
    token = col1.text_input('② token', placeholder='logged_user.json 的 token')
    userid = col2.text_input('② userId', placeholder='如 qq_1FE0…')
    deviceid = st.text_input('③ android_id(可留空)', placeholder='settings get secure android_id')
    submitted = st.form_submit_button('🚀 开始解密', use_container_width=True)

if submitted:
    if fup is None:
        st.warning('请先上传 .zjs 文件')
    else:
        with st.spinner('正在解密(首次含联网换取密钥, 请稍候)…'):
            res, msg = do_decrypt(code, fup.getvalue(), fup.name,
                                  token, userid, deviceid)
        if res:
            st.success(msg)
            st.download_button('⬇ 下载明文 .zjs', data=res[1],
                               file_name=res[0],
                               mime='application/octet-stream',
                               use_container_width=True)
        else:
            st.error(msg)

st.divider()
with st.expander('登录态怎么获取 / 说明'):
    st.markdown(
        '1. 手机安装并登录 **App**;\n'
        '2. 读取 App 数据目录 `files/logged_user.json`(需 root 或备份), 复制其中 `token` 与 `userId` 填入;\n'
        '3. 也可在手机 `settings get secure android_id` 查 android_id(可留空尝试)。\n\n'
        '每个加密脚本由作者按账号授权, 密钥由服务端按你登录态下发; 他人账号解不开你的付费脚本属正常。\n'
        '本站在内存处理文件与登录态, 不落盘; 请仅解密你有权使用的脚本。'
    )
