#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ljzd 工具(com.zdanjian.zdanjian) .zjs 加密脚本 一键解密工具
支持 App 加密动作格式 encryptVersion 1 / 2 / 3:
  v1: AES-CBC(PKCS5) key=callK, iv=ek16, 明文为 JSON 字符串
  v2: AES-CBC(PKCS5) key=ek16, iv=callK, 明文为 SJSON + Key1 混淆(encryptKey)
  v3: 双层 AES-CBC(PKCS5): 外层 key=callK iv=AES_IV, 内层 key=ek16 iv=AES_IV,
      明文为 SJSON + Key1 混淆(encryptKey)

密钥通过官方接口获取:
  GET {api}/runScript/checkEncryptInfo?id=<encryptId>
  需带签名头(登录 token、userId、deviceId、apk 签名、timestamp、sign)

用法:
  python3 decrypt_zjs.py <文件.zjs> [文件2.zjs ...]
        [--out DIR] [--json] [--login-json FILE] [--token T] [--user-id U]
        [--device-id D] [--apk-sign S] [--channel C] [--api URL]
        [--keep-ct] [--verbose]
"""
import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import time
import urllib.request

APP_PKG = 'com.zdanjian.zdanjian'
LOGIN_JSON_PATH = '/data/data/%s/files/logged_user.json' % APP_PKG
CALLK = '联系Q673636904'                     # EncryptUtil.commonK (16 UTF-8 bytes)
AES_IV = b'f815de617ed77f83'                # EncryptUtil.AES_IV (16 ASCII bytes)
API_BASE = 'http://120.77.173.114:8080/zdjl/'
DEFAULT_CHANNEL = 'zdjl_arm64'
DEFAULT_APK_SIGN = '764c9b0797078754d9d6ec86f23e691b'  # v26.5.0 签名;App 升级后可能变化
APP_VERSION = '26.5.0'
APP_VERSION_CODE = '26000050'
UA = 'okhttp/4.9.0'


# ---------------- 基础算法(与 Java 端逐字节一致) ----------------

def java_md5_hex(s):
    """EncryptUtil.MD5(String): 每 char 取低 8 位再 md5"""
    b = bytes(ord(c) & 0xFF for c in s)
    return hashlib.md5(b).hexdigest()


def md5_bytes_hex(b):
    return hashlib.md5(b).hexdigest()


def java_hash(s):
    """Java String.hashCode() (signed 32-bit) —— 按 UTF-16 code unit 迭代"""
    h = 0
    for u in _utf16_units(s):
        h = (31 * h + u) & 0xFFFFFFFF
    if h >= 0x80000000:
        h -= 0x100000000
    return h


def key1_digits(encrypt_key):
    """Key.Key1(encryptKey) 生成的数字串(用于 XOR 混淆还原)"""
    k = str(java_hash(encrypt_key))
    n = len(encrypt_key)
    for i in range(2, n):
        k += str(java_hash(encrypt_key[i - 2:i]))
    return k


def _utf16_units(s):
    """按 UTF-16 code unit 切分(与 Java char / JS charCodeAt 一致, emoji 占2单元)"""
    raw = s.encode('utf-16-le', errors='surrogatepass')
    return [raw[i] | (raw[i + 1] << 8) for i in range(0, len(raw), 2)]


def _units_to_str(units):
    raw = bytearray()
    for u in units:
        raw.append(u & 0xFF)
        raw.append((u >> 8) & 0xFF)
    return bytes(raw).decode('utf-16-le', errors='surrogatepass')


def key_xor(s, digits):
    """Key1 XOR: 按 UTF-16 code unit 逐位异或(与 Java char 一致)"""
    su = _utf16_units(s)
    du = _utf16_units(digits)
    L = len(du)
    out = [(u ^ du[i % L]) & 0xFFFF for i, u in enumerate(su)]
    return _units_to_str(out)


def ek16(encrypt_key):
    """encryptKey 循环截断到 16 字节(Java byte[16] 逐位取模)"""
    b = encrypt_key.encode('utf-8')
    return bytes(b[i % len(b)] for i in range(16))


# ---------------- AES-CBC/PKCS5 后端(优先 pycryptodome,退回 openssl) ----------------

try:
    from Crypto.Cipher import AES as _PyAES
    _HAS_CRYPTO = True
except Exception:
    _HAS_CRYPTO = False


def _aes_crypto(data, key, iv, decrypt=True):
    c = _PyAES.new(key, _PyAES.MODE_CBC, iv)
    return c.decrypt(data) if decrypt else c.encrypt(data)


_OPENSSL = shutil.which('openssl')


def _aes_openssl(data, key, iv, decrypt=True):
    if not _OPENSSL:
        raise RuntimeError('no AES backend: install pycryptodome or openssl')
    k = key.hex()
    v = iv.hex()
    cmd = [_OPENSSL, 'enc', '-aes-128-cbc', '-K', k, '-iv', v]
    cmd.append('-d' if decrypt else '-e')
    p = subprocess.run(cmd, input=data, stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL)
    if p.returncode != 0:
        raise RuntimeError('openssl aes failed')
    return p.stdout


def aes_decrypt_raw(data, key, iv):
    """解出整块(不去 PKCS7 padding)"""
    if len(data) == 0 or len(data) % 16 != 0:
        raise ValueError('ciphertext length not block aligned: %d' % len(data))
    if _HAS_CRYPTO:
        return _aes_crypto(data, key, iv)
    if not _OPENSSL:
        raise RuntimeError('no AES backend: install pycryptodome or openssl')
    cmd = [_OPENSSL, 'enc', '-d', '-aes-128-cbc', '-K', key.hex(), '-iv', iv.hex(), '-nopad']
    p = subprocess.run(cmd, input=data, stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL)
    if p.returncode != 0:
        raise RuntimeError('openssl aes failed')
    return p.stdout


def unpad_pkcs7(b):
    """校验并去掉 PKCS7/PKCS5 padding(Java Cipher.doFinal 行为)"""
    if len(b) == 0:
        return b
    pad = b[-1]
    if pad < 1 or pad > 16 or len(b) < pad or b[-pad:] != bytes([pad]) * pad:
        raise ValueError('PKCS7 padding 校验失败, 密钥可能不正确 (last=%d)' % pad)
    return b[:-pad]


def aes_decrypt_pkcs5(data, key, iv):
    return unpad_pkcs7(aes_decrypt_raw(data, key, iv))


# ---------------- SJSON 二进制解析 ----------------

class SJSONReader:
    def __init__(self, data):
        self.d = data
        self.p = 0

    def read(self, n=1):
        r = self.d[self.p:self.p + n]
        if len(r) != n:
            raise ValueError('eof @%d need %d' % (self.p, n))
        self.p += n
        return r

    def u8(self):
        b = self.d[self.p]
        self.p += 1
        return b

    def peek8(self):
        return self.d[self.p]

    def int_le(self):
        r = struct.unpack_from('<i', self.d, self.p)[0]
        self.p += 4
        return r

    def long_le(self):
        r = struct.unpack_from('<q', self.d, self.p)[0]
        self.p += 8
        return r

    def double_le(self):
        r = struct.unpack_from('<d', self.d, self.p)[0]
        self.p += 8
        return r

    def cstr(self):
        start = self.p
        while self.d[self.p] != 0:
            self.p += 1
        raw = self.d[start:self.p]
        self.p += 1
        return raw.decode('utf-8', errors='replace')

    def utf8str(self):
        n = self.int_le()
        if n <= 0 or n > 0x2000000:
            raise ValueError('bad string size %d @%d' % (n, self.p))
        if n == 1:
            self.p += 1
            return ''
        raw = self.read(n)
        return raw[:n - 1].decode('utf-8', errors='replace')


def _sjson_value(r):
    t = r.u8()
    if t == 0:
        raise ValueError('unexpected terminator')
    name = r.cstr()
    return name, _sjson_type(r, t)


def _sjson_type(r, t):
    if t == 1:
        return r.double_le()
    if t == 2:
        return r.utf8str()
    if t == 3:                       # object
        r.int_le()
        obj = {}
        while True:
            if r.peek8() == 0:
                r.p += 1
                break
            k, v = _sjson_value(r)
            obj[k] = v
        return obj
    if t == 4:                       # array
        r.int_le()
        arr = []
        while True:
            if r.peek8() == 0:
                r.p += 1
                break
            _, v = _sjson_value(r)
            arr.append(v)
        return arr
    if t == 5:                       # binary
        ln = r.int_le()
        sub = r.u8()
        raw = r.read(ln - 1)
        return {'$binary': base64.b64encode(raw).decode('ascii'), '$sub': sub}
    if t == 6:
        return '<undefined>'
    if t == 8:
        return r.u8() > 0
    if t == 9:
        return r.long_le()
    if t == 10:
        return None
    if t == 11:
        a = r.cstr()
        b = r.cstr()
        return {'$regex': a, '$flags': b}
    if t == 13:                      # code
        return {'$code': r.utf8str()}
    if t == 14:                      # symbol -> 引擎当字符串
        return {'$symbol': r.utf8str()}
    if t == 15:                      # codeWScope
        r.int_le()
        code = r.utf8str()
        scope = _sjson_doc(r)
        return {'$codeWScope': code, '$scope': scope}
    if t == 16:
        return r.int_le()
    if t == 17:
        a = r.int_le()
        b = r.int_le()
        return {'$timestamp': [a, b]}
    if t == 18:
        return r.long_le()
    raise ValueError('unsupported sjson type %d @%d' % (t, r.p))


def _sjson_doc(r):
    r.int_le()
    obj = {}
    while True:
        if r.p >= len(r.d):
            break
        if r.peek8() == 0:
            r.p += 1
            break
        k, v = _sjson_value(r)
        obj[k] = v
    return obj


def parse_sjson(data):
    r = SJSONReader(data)
    obj = _sjson_doc(r)
    return obj, r.p


def deobfuscate(node, digits, obfuscated=True):
    """Key1 XOR 还原: 所有字符串 key 与字符串值都被混淆(服务端 en() 处理过)"""
    if not obfuscated:
        return node
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            dk = key_xor(k, digits)
            if isinstance(v, str):
                out[dk] = key_xor(v, digits)
            else:
                out[dk] = deobfuscate(v, digits)
        return out
    if isinstance(node, list):
        return [deobfuscate(x, digits) for x in node]
    return node


# ---------------- 网络: 获取 encryptKey ----------------

def _http_get(url, headers, timeout=20):
    req = urllib.request.Request(url, headers=headers)
    r = urllib.request.urlopen(req, timeout=timeout)
    return r.status, dict(r.headers), r.read()


def fetch_encrypt_key(encrypt_id, token, user_id, device_id,
                      apk_sign=DEFAULT_APK_SIGN, channel=DEFAULT_CHANNEL,
                      api_base=API_BASE, verbose=False):
    path = '/zdjl/runScript/checkEncryptInfo'
    url = '%srunScript/checkEncryptInfo?id=%s' % (api_base.rstrip('/') + '/', encrypt_id)
    ts = str(int(time.time() * 1000))
    sign = java_md5_hex(ts + CALLK + path)
    hdr = {
        'ZDJL-TOKEN': token or '',
        'ZDJL-USER-ID': user_id or '',
        'ZDJL-APP-VERSION': APP_VERSION,
        'ZDJL-APP-VERSION-CODE': APP_VERSION_CODE,
        'ZDJL-DEVICE-ID': device_id or '',
        'ZDJL-TIMESTAMP': ts,
        'ZDJL-CLIENT-TYPE': 'APP',
        'ZDJL-SIGN': sign,
        'ZDJL-A-S': apk_sign,
        'ZDJL-CHANNEL': channel,
        'User-Agent': UA,
    }
    st, rh, raw = _http_get(url, hdr)
    if verbose:
        print('  [api] HTTP %d id=%s' % (st, encrypt_id))
    sig = rh.get('ZDJL-SIGN')
    if sig:
        key_md5 = java_md5_hex(sig + CALLK)
        s = raw.decode('utf-8')
        out = ''.join(chr(ord(ch) ^ ord(key_md5[i % len(key_md5)]))
                      for i, ch in enumerate(s))
    else:
        out = raw.decode('utf-8', errors='replace')
    try:
        j = json.loads(out)
    except Exception:
        raise RuntimeError('API 响应解析失败: %r' % out[:300])
    if not j.get('suc'):
        raise RuntimeError('API 返回失败: %s' % (j.get('msg') or j))
    obj = j.get('obj') or {}
    ek = obj.get('encryptKey')
    ver = obj.get('encryptVersion')
    if not ek:
        raise RuntimeError('API 未返回 encryptKey: %s' % (json.dumps(obj, ensure_ascii=False)))
    if verbose:
        print('  [api] encryptVersion=%r encryptKey=%r' % (ver, ek))
    return str(ver) if ver is not None else '', ek


def load_login_from_device(verbose=False):
    """尝试直接读 App logged_user.json(需要权限/root)"""
    if os.path.exists(LOGIN_JSON_PATH):
        try:
            with open(LOGIN_JSON_PATH, encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    # 尝试 su
    for su in ('/system/bin/su', '/sbin/su', '/su/bin/su'):
        if os.path.exists(su):
            try:
                p = subprocess.run([su, '-c', 'cat ' + LOGIN_JSON_PATH],
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15)
                if p.returncode == 0 and p.stdout.strip():
                    return json.loads(p.stdout.decode('utf-8'))
            except Exception:
                pass
    return None


def read_device_id(verbose=False):
    """android_id(与 App DeviceUtil fallback 一致)"""
    for cmd in (['settings', 'get', 'secure', 'android_id'],):
        try:
            p = subprocess.run(cmd, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, timeout=15)
            if p.returncode == 0:
                v = p.stdout.decode().strip()
                if v and v != 'null':
                    return v
        except Exception:
            pass
    # root 方式
    for su in ('/system/bin/su', '/sbin/su', '/su/bin/su'):
        if os.path.exists(su):
            try:
                p = subprocess.run([su, '-c', 'settings get secure android_id'],
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15)
                if p.returncode == 0:
                    v = p.stdout.decode().strip()
                    if v and v != 'null':
                        return v
            except Exception:
                pass
    return None


# ---------------- 解密主流程 ----------------

def decrypt_block_v3(b64content, encrypt_key):
    ct = base64.b64decode(b64content)
    k_callk = CALLK.encode('utf-8')
    k_ek = ek16(encrypt_key)
    # 外层: key=callK; 内层: key=ek16 (Java 两层均自动 PKCS5)
    mid = aes_decrypt_pkcs5(ct, k_callk, AES_IV)
    pt = aes_decrypt_pkcs5(mid, k_ek, AES_IV)
    return pt


def decrypt_block_v2(b64content, encrypt_key):
    ct = base64.b64decode(b64content)
    return aes_decrypt_pkcs5(ct, ek16(encrypt_key), CALLK.encode('utf-8'))


def decrypt_block_v1(b64content, encrypt_key):
    ct = base64.b64decode(b64content)
    return aes_decrypt_pkcs5(ct, CALLK.encode('utf-8'), ek16(encrypt_key))


def decrypt_one_content(b64content, encrypt_key, version):
    if version == '3':
        return decrypt_block_v3(b64content, encrypt_key)
    if version == '2':
        return decrypt_block_v2(b64content, encrypt_key)
    # v1 / 空 -> 明文 JSON 字符串(无混淆)
    return decrypt_block_v1(b64content, encrypt_key)


def decrypt_zjs_file(path, cfg, verbose=False):
    with open(path, 'rb') as f:
        data = f.read()
    try:
        text = data.decode('utf-8')
    except Exception:
        raise RuntimeError('不是 UTF-8 文本, 不是 zjs 脚本')
    lines = text.split('\r\n')
    hdr_line = lines[0]
    hdr = json.loads(hdr_line)
    if not hdr.get('encrypt') and 'encryptId' not in hdr_line:
        # 未加密文件
        if verbose:
            print('  未加密, 直接复制')
        return lines, hdr, []
    newhdr = {k: v for k, v in hdr.items() if k not in ('encrypt', 'encryptUserId')}
    key_cache = {}

    def get_key(encrypt_id):
        if encrypt_id not in key_cache:
            key_cache[encrypt_id] = fetch_encrypt_key(encrypt_id, **cfg, verbose=verbose)
        return key_cache[encrypt_id]

    out_lines = [json.dumps(newhdr, ensure_ascii=False)]
    stats = []
    for ln in lines[1:]:
        if not ln.strip():
            continue
        try:
            o = json.loads(ln)
        except Exception:
            raise RuntimeError('动作行解析失败(可能不是完整行)')
        if not isinstance(o, dict) or o.get('type') not in ('加密动作',) or 'content' not in o:
            # 普通动作或未知行: 原样保留
            out_lines.append(ln)
            continue
        eid = o.get('encryptId', '')
        if not eid:
            raise RuntimeError('加密动作缺少 encryptId')
        version, ek = get_key(eid)
        pt = decrypt_one_content(o['content'], ek, version)
        digits = key1_digits(ek) if version in ('2', '3') else None
        if version in ('2', '3'):
            tree, consumed = parse_sjson(pt)
            if consumed != len(pt) and verbose:
                print('   [warn] block consumed %d/%d' % (consumed, len(pt)))
            action = deobfuscate(tree, digits)
        else:
            # v1 明文是 JSON 字符串
            action = json.loads(pt.decode('utf-8', errors='replace'))
        out_lines.append(json.dumps(action, ensure_ascii=False, separators=(',', ':')))
        stats.append((eid, version, len(pt)))
    return out_lines, hdr, stats


def resolve_login(args, verbose=False):
    token = args.token
    user_id = args.user_id
    if args.login_json:
        with open(args.login_json, encoding='utf-8') as f:
            j = json.load(f)
        token = token or j.get('token')
        user_id = user_id or j.get('userId')
    elif not token:
        j = load_login_from_device(verbose)
        if j:
            token = j.get('token')
            user_id = j.get('userId')
            if verbose:
                print('  登录态: 从设备 App 读取 userId=%s' % (j.get('userId') or ''))
    if not token or not user_id:
        raise RuntimeError('缺少登录态: 请用 --login-json / --token / --user-id, 或确保设备 App 已登录(root 自动读取)')
    device_id = args.device_id or read_device_id(verbose)
    return {
        'token': token,
        'user_id': user_id,
        'device_id': device_id,
        'apk_sign': args.apk_sign or DEFAULT_APK_SIGN,
        'channel': args.channel or DEFAULT_CHANNEL,
        'api_base': args.api or API_BASE,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description='ljzd .zjs 加密脚本一键解密')
    ap.add_argument('files', nargs='+', help='输入 .zjs 文件(可多个)')
    ap.add_argument('-o', '--out', default=None, help='输出目录(默认与输入同目录)')
    ap.add_argument('--json', dest='want_json', action='store_true', help='额外输出完整可读 .json')
    ap.add_argument('--login-json', help='App logged_user.json 路径(离线提供登录态)')
    ap.add_argument('--token'); ap.add_argument('--user-id')
    ap.add_argument('--device-id'); ap.add_argument('--apk-sign')
    ap.add_argument('--channel'); ap.add_argument('--api')
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args(argv)

    cfg = resolve_login(args, verbose=args.verbose)
    if args.verbose:
        print('认证信息: userId=%s deviceId=%s' % (cfg['user_id'], cfg['device_id']))
    for f in args.files:
        if not os.path.exists(f):
            print('!! 文件不存在: %s' % f)
            continue
        base = os.path.splitext(os.path.basename(f))[0]
        outdir = args.out or os.path.dirname(os.path.abspath(f)) or '.'
        os.makedirs(outdir, exist_ok=True)
        print('== 解密: %s' % os.path.basename(f))
        t0 = time.time()
        out_lines, hdr, stats = decrypt_zjs_file(f, cfg, verbose=args.verbose)
        zjs_path = os.path.join(outdir, base + '_解密.zjs')
        with open(zjs_path, 'w', encoding='utf-8') as w:
            w.write('\r\n'.join(out_lines) + '\r\n')
        if args.verbose or not args.want_json:
            pass
        if args.want_json:
            json_path = os.path.join(outdir, base + '_解密.json')
            full = {'header': hdr, 'note': 'ljzd 解密结果',
                    'decrypted_actions': [json.loads(l) for l in out_lines[1:]]}
            with open(json_path, 'w', encoding='utf-8') as w:
                json.dump(full, w, ensure_ascii=False, indent=1)
            print('  完整可读: %s' % json_path)
        print('  明文脚本: %s' % zjs_path)
        print('  (%d 个加密块, 耗时 %.1fs)' % (len(stats), time.time() - t0))
    return 0


if __name__ == '__main__':
    sys.exit(main())
