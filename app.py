import os
import json
import asyncio
import re
import secrets
from pathlib import Path
from typing import Optional
from contextlib import asynccontextmanager
from urllib.parse import urlparse, parse_qs

import httpx
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, WebAppInfo
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes

# ============================================================
# CONFIG
# ============================================================
BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
WEBAPP_URL = os.getenv("WEBAPP_URL", "").strip().rstrip("/")
RUN_BOT = os.getenv("RUN_BOT", "1").strip().lower() in {"1", "true", "yes", "on"}
DATA_FILE = Path(os.getenv("DATA_FILE", "data.json"))

# ============================================================
# PERSISTENT, PER-TELEGRAM-USER STATE
# The old version used one global db, so every Telegram user shared
# accounts/cart/address state. This version isolates everything by user.
# ============================================================
DEFAULT_ADDRESS = {
    "id": 101,
    "name": "User Demo",
    "mobile": "9876543210",
    "pin": "110001",
    "city": "New Delhi",
    "state": "Delhi",
    "address_line_1": "Connaught Place",
    "address_line_2": "",
    "landmark": "",
    "address_type": "Home",
    "pin_serviceable": True,
}


def blank_user():
    return {
        "accounts": [],
        "active_id": None,
        "user_state": None,
        "referral_link": "",
        "addresses": [dict(DEFAULT_ADDRESS)],
        "cart": {"items": [], "total_quantity": 0, "effective_total": 0, "effective_online": 0, "address": None, "price_break_up": [], "cart_session": secrets.token_hex(8)},
        "orders": [],
    }


def load_db():
    if not DATA_FILE.exists():
        return {"users": {}}
    try:
        data = json.loads(DATA_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("users"), dict):
            return {"users": {}}
        return data
    except Exception:
        return {"users": {}}


DB = load_db()
SAVE_LOCK = asyncio.Lock()


async def save_db():
    async with SAVE_LOCK:
        tmp = DATA_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(DB, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(DATA_FILE)


def user_state(user_id: str):
    key = str(user_id)
    if key not in DB["users"]:
        DB["users"][key] = blank_user()
    return DB["users"][key]


def normalize_phone(v):
    digits = re.sub(r"\D", "", str(v or ""))
    if digits.startswith("91") and len(digits) == 12:
        digits = digits[-10:]
    return digits if len(digits) == 10 else None


def parse_tg_user_id(request: Request):
    """Read the Telegram WebApp initData user id used for web/bot sync.
    The bot-created Mini App already comes with signed initData; this only
    extracts the user id for state routing. Never trust it for privileged auth.
    """
    raw = request.headers.get("X-Tg-Init-Data", "") or request.query_params.get("tgib", "")
    if not raw:
        return None
    try:
        q = parse_qs(raw, keep_blank_values=True)
        user_json = q.get("user", [""])[0]
        if user_json:
            obj = json.loads(user_json)
            if obj.get("id") is not None:
                return str(obj["id"])
    except Exception:
        pass
    return None


def request_user_id(request: Request):
    uid = parse_tg_user_id(request)
    # Development fallback. Do not use this as an admin/security boundary.
    return uid or "web-demo"


# ============================================================
# MEESHO HTTP CLIENT
# ============================================================
COMMON_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 Chrome/149.0 Mobile Safari/537.36",
    "Accept": "application/json, text/plain, */*",
    "Content-Type": "application/json",
    "meesho-iso-country-code": "IN",
    "Origin": "https://www.meesho.com",
    "Referer": "https://www.meesho.com/",
}


async def meesho_request(method, url, *, json_body=None, cookies=None, timeout=20):
    headers = dict(COMMON_HEADERS)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, headers=headers, cookies=cookies or {}) as client:
        try:
            response = await client.request(method, url, json=json_body)
            try:
                payload = response.json()
            except Exception:
                payload = None
            return response, payload, dict(response.cookies)
        except httpx.TimeoutException:
            return None, None, {}
        except httpx.HTTPError:
            return None, None, {}


async def send_meesho_real_otp(phone_number: str):
    phone = normalize_phone(phone_number)
    if not phone:
        return {"ok": False, "error": "Enter a valid 10-digit mobile number."}
    url = "https://www.meesho.com/api/v1/user/login/request-otp"
    body = {"phone_number": phone}
    response, data, cookies = await meesho_request("POST", url, json_body=body)
    if response is None:
        return {"ok": False, "error": "Meesho could not be reached. Try again later."}
    if response.status_code < 200 or response.status_code >= 300:
        return {"ok": False, "error": f"Meesho returned HTTP {response.status_code}."}
    if not isinstance(data, dict):
        return {"ok": False, "error": "Meesho returned an unexpected response. No fake login was created."}
    d = data.get("data") or {}
    request_id = d.get("request_id")
    instance_id = d.get("instance_id")
    if not request_id or not instance_id:
        return {"ok": False, "error": "Meesho did not provide a valid OTP request. Please retry."}
    return {"ok": True, "request_id": request_id, "instance_id": instance_id, "cookies": cookies}


async def verify_meesho_real_otp(phone_number: str, otp: str, request_id: str, instance_id: str, cookies=None):
    phone = normalize_phone(phone_number)
    otp = re.sub(r"\D", "", str(otp or ""))
    if not phone or len(otp) != 6:
        return {"ok": False, "error": "Enter the 6-digit OTP exactly as received from Meesho."}
    url = "https://www.meesho.com/api/v1/user/login"
    body = {
        "request_id": request_id,
        "instance_id": instance_id,
        "phone_number": phone,
        "otp": otp,
        "login_type": "meesho_sms_auth",
    }
    response, data, response_cookies = await meesho_request("POST", url, json_body=body, cookies=cookies)
    if response is None:
        return {"ok": False, "error": "Meesho could not be reached while verifying the OTP."}
    if response.status_code < 200 or response.status_code >= 300:
        return {"ok": False, "error": f"OTP verification failed (HTTP {response.status_code})."}
    if not isinstance(data, dict):
        return {"ok": False, "error": "Unexpected response from Meesho. Try the OTP again."}
    success = data.get("status") is True or str(data.get("status", "")).lower() in {"success", "true"}
    user = data.get("user") or data.get("data") or {}
    user_id = user.get("user_id") or user.get("id")
    if not success or not user_id:
        message = data.get("message") or data.get("error") or "Invalid or expired OTP."
        return {"ok": False, "error": str(message)}
    merged_cookies = dict(cookies or {})
    merged_cookies.update(response_cookies or {})
    return {"ok": True, "user_id": str(user_id), "cookies": merged_cookies}


# ============================================================
# SEARCH / PRODUCT HELPERS
# Public catalog fallback. It is intentionally honest: it does not claim
# live Meesho results when Meesho's private/internal API is unavailable.
# ============================================================
CATALOG = [
    {"product_id": 312019481, "name": "Men Premium Slim Fit Casual Cotton Shirt", "price": 499, "original_price": 899, "discount_text": "44% OFF", "rating": 4.5, "rating_count": 14200, "supplier_name": "Fashion Vibe", "mall_verified": True, "image": "https://images.meesho.com/images/products/312019481/1_512.jpg", "images": ["https://images.meesho.com/images/products/312019481/1_512.jpg"], "sizes": [{"variation_id": 1, "name": "M"}, {"variation_id": 2, "name": "L"}], "tags": ["Fast Dispatch"]},
    {"product_id": 321114700, "name": "Women Rayon Printed Kurti", "price": 349, "original_price": 799, "discount_text": "56% OFF", "rating": 4.3, "rating_count": 8200, "supplier_name": "Style Hub", "mall_verified": False, "image": "https://images.meesho.com/images/products/321114700/1_512.jpg", "images": ["https://images.meesho.com/images/products/321114700/1_512.jpg"], "sizes": [{"variation_id": 1, "name": "M"}, {"variation_id": 2, "name": "L"}], "tags": ["Trending"]},
    {"product_id": 337700121, "name": "Women Everyday Saree", "price": 599, "original_price": 1299, "discount_text": "54% OFF", "rating": 4.4, "rating_count": 6100, "supplier_name": "Saree House", "mall_verified": False, "image": "https://images.meesho.com/images/products/337700121/1_512.jpg", "images": ["https://images.meesho.com/images/products/337700121/1_512.jpg"], "sizes": [], "tags": ["New"]},
    {"product_id": 341220455, "name": "Casual Sports Shoes", "price": 699, "original_price": 1499, "discount_text": "53% OFF", "rating": 4.1, "rating_count": 3900, "supplier_name": "Urban Steps", "mall_verified": False, "image": "https://images.meesho.com/images/products/341220455/1_512.jpg", "images": ["https://images.meesho.com/images/products/341220455/1_512.jpg"], "sizes": [{"variation_id": 1, "name": "7"}, {"variation_id": 2, "name": "8"}], "tags": ["Fast Dispatch"]},
]


def search_catalog(query: str):
    q = str(query or "").strip().lower()
    if not q:
        return []
    words = [w for w in re.findall(r"[a-z0-9]+", q) if len(w) > 1]
    scored = []
    for item in CATALOG:
        text = (item["name"] + " " + " ".join(item.get("tags", [])) + " " + item.get("supplier_name", "")).lower()
        score = sum(3 if w in item["name"].lower() else 1 for w in words if w in text)
        if score:
            scored.append((score, item))
    if not scored:
        return CATALOG
    scored.sort(key=lambda x: x[0], reverse=True)
    return [x[1] for x in scored]


def product_by_id(product_id):
    for p in CATALOG:
        if int(p["product_id"]) == int(product_id):
            return dict(p)
    return None


# ============================================================
# TELEGRAM BOT
# ============================================================
telegram_app = None


def main_menu_for(uid):
    u = user_state(uid)
    acc_count = len(u["accounts"])
    text = (
        "🛍️ *PRIMES Meesho*\n"
        "_Your personal Meesho shopping concierge_\n"
        "━━━━━━━━━━━━━━━━━━━━\n\n"
        "✨ *Service fee* — *FREE (₹0.00)*\n"
        f"👤 *Accounts* · {acc_count} linked\n\n"
        "Pick an option below to get started 👇"
    )
    keyboard = [
        [InlineKeyboardButton("🛍️ Open Shop", web_app=WebAppInfo(url=WEBAPP_URL))],
        [InlineKeyboardButton("➕ Add Account", callback_data="add_account"), InlineKeyboardButton("👤 My Accounts", callback_data="my_accounts")],
        [InlineKeyboardButton("🔍 Check Number", callback_data="check_number"), InlineKeyboardButton("🔗 Set Refer Link", callback_data="set_refer_link")],
        [InlineKeyboardButton("🎁 How Offer Works", callback_data="how_offer_works")],
        [InlineKeyboardButton("🗂️ Manage Accounts", web_app=WebAppInfo(url=f"{WEBAPP_URL}#accounts")), InlineKeyboardButton("🏷️ Check Price", web_app=WebAppInfo(url=f"{WEBAPP_URL}#check-price"))],
    ]
    return text, InlineKeyboardMarkup(keyboard)


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = str(update.effective_user.id)
    text, markup = main_menu_for(uid)
    await update.message.reply_text(text, reply_markup=markup, parse_mode="Markdown")


async def callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    uid = str(update.effective_user.id)
    u = user_state(uid)
    data = query.data

    if data == "main_menu":
        text, markup = main_menu_for(uid)
        await query.edit_message_text(text, reply_markup=markup, parse_mode="Markdown")
    elif data == "add_account":
        u["user_state"] = "AWAITING_PHONE"
        await query.edit_message_text("➕ *Add Account*\n\nSend the 10-digit Meesho registered mobile number. I will request a real Meesho OTP.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="main_menu")]]), parse_mode="Markdown")
    elif data == "my_accounts":
        if not u["accounts"]:
            text = "👤 *My Accounts*\n\nNo accounts linked yet."
        else:
            text = "👤 *My Accounts*\n\n" + "\n".join(f"• +91 {a.get('mobile','')} · ID `{a.get('user_id','—')}`" for a in u["accounts"])
        await query.edit_message_text(text, reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("➕ Add Account", callback_data="add_account")], [InlineKeyboardButton("🏠 Main Menu", callback_data="main_menu")]]), parse_mode="Markdown")
    elif data == "login_number":
        u["user_state"] = "AWAITING_PHONE"
        await query.edit_message_text("📱 Send the 10-digit Meesho mobile number:", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="main_menu")]]))
    elif data == "set_refer_link":
        u["user_state"] = "AWAITING_REFER"
        await query.edit_message_text("🔗 Send your Meesho referral link:", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="main_menu")]]))
    elif data == "check_number":
        u["user_state"] = "AWAITING_CHECK"
        await query.edit_message_text("🔍 Send the 10-digit number to check.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="main_menu")]]))
    elif data == "how_offer_works":
        await query.edit_message_text("🎁 *How it works*\n\nSearch and browse in the Mini App. Account linking is performed only after a real Meesho OTP is requested and successfully verified.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🏠 Main Menu", callback_data="main_menu")]]), parse_mode="Markdown")
    await save_db()


async def message_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = str(update.effective_user.id)
    u = user_state(uid)
    msg = (update.message.text or "").strip()
    state = u.get("user_state")

    if state == "AWAITING_PHONE":
        phone = normalize_phone(msg)
        if not phone:
            await update.message.reply_text("❌ Please send a valid 10-digit mobile number.")
            return
        await update.message.reply_text(f"⏳ Requesting a real Meesho OTP for +91 {phone}…")
        result = await send_meesho_real_otp(phone)
        if not result.get("ok"):
            u["user_state"] = None
            await update.message.reply_text("❌ " + result.get("error", "Could not request OTP."))
        else:
            u["user_state"] = {"state": "AWAITING_OTP", "phone": phone, "request_id": result["request_id"], "instance_id": result["instance_id"], "cookies": result.get("cookies", {})}
            await update.message.reply_text(f"📩 OTP requested. Enter the 6-digit OTP sent by Meesho to +91 {phone}.")
        await save_db()
        return

    if isinstance(state, dict) and state.get("state") == "AWAITING_OTP":
        await update.message.reply_text("⏳ Verifying OTP…")
        result = await verify_meesho_real_otp(state["phone"], msg, state["request_id"], state["instance_id"], state.get("cookies"))
        if not result.get("ok"):
            await update.message.reply_text("❌ " + result.get("error", "OTP verification failed.") + "\nSend the OTP again if it has not expired.")
            return
        existing = next((a for a in u["accounts"] if a.get("mobile") == state["phone"]), None)
        account = existing or {"id": max([int(a.get("id", 0)) for a in u["accounts"]] or [0]) + 1}
        account.update({"mobile": state["phone"], "user_id": result["user_id"], "cookies": result.get("cookies", {}), "source": "otp", "order_placed": False, "xo_exp": None})
        if not existing:
            u["accounts"].append(account)
        u["active_id"] = account["id"]
        u["user_state"] = None
        await save_db()
        text, markup = main_menu_for(uid)
        await update.message.reply_text("✅ Meesho account linked successfully. The web app and bot now use this same Telegram account state.", reply_markup=markup)
        return

    if state == "AWAITING_REFER":
        u["referral_link"] = msg
        u["user_state"] = None
        await save_db()
        await update.message.reply_text("✅ Referral link saved.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🏠 Main Menu", callback_data="main_menu")]]))
        return

    if state == "AWAITING_CHECK":
        phone = normalize_phone(msg)
        u["user_state"] = None
        await save_db()
        await update.message.reply_text(f"🔍 Number: +91 {phone or msg}\n\nNo live eligibility check is claimed by this bot unless a supported Meesho response is available.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🏠 Main Menu", callback_data="main_menu")]]))
        return


async def run_bot_background():
    global telegram_app
    if not BOT_TOKEN:
        print("BOT_TOKEN is not set; web app will still run.")
        return
    try:
        telegram_app = Application.builder().token(BOT_TOKEN).connect_timeout(30).read_timeout(30).build()
        telegram_app.add_handler(CommandHandler("start", start_command))
        telegram_app.add_handler(CallbackQueryHandler(callback_handler))
        telegram_app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, message_handler))
        await telegram_app.initialize()
        await telegram_app.start()
        await telegram_app.updater.start_polling(drop_pending_updates=True)
    except Exception as exc:
        print(f"Bot error: {exc}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    global WEBAPP_URL
    if not WEBAPP_URL:
        WEBAPP_URL = os.getenv("RENDER_EXTERNAL_URL", "").strip().rstrip("/")
    task = asyncio.create_task(run_bot_background()) if RUN_BOT else None
    yield
    if telegram_app and telegram_app.updater and telegram_app.updater.running:
        await telegram_app.updater.stop()
        await telegram_app.stop()
        await telegram_app.shutdown()
    if task:
        task.cancel()
    try:
        await save_db()
    except Exception:
        pass


# ============================================================
# FASTAPI
# ============================================================
app = FastAPI(title="Meesho Mini App Server", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.mount("/UnknownGuy_js", StaticFiles(directory="public/UnknownGuy_js"), name="js")
app.mount("/UnknownGuy_css", StaticFiles(directory="public/UnknownGuy_css"), name="css")


@app.get("/")
async def serve_index():
    return FileResponse("public/index.html")


@app.get("/api/bootstrap")
async def api_bootstrap(request: Request):
    uid = request_user_id(request)
    u = user_state(uid)
    return {"accounts": u["accounts"], "active_id": u["active_id"], "balance": 0, "per_order_price": 0}


@app.post("/api/accounts/select")
async def api_accounts_select(request: Request, data: dict):
    u = user_state(request_user_id(request))
    try:
        account_id = int(data.get("account_id"))
    except Exception:
        return {"error": "Invalid account id"}
    if not any(int(a.get("id")) == account_id for a in u["accounts"]):
        return {"error": "Account not found"}
    u["active_id"] = account_id
    await save_db()
    return {"ok": True, "active_id": account_id}


@app.get("/api/accounts/order_status")
async def api_accounts_order_status(request: Request):
    u = user_state(request_user_id(request))
    return {"statuses": {str(a["id"]): bool(a.get("order_placed")) for a in u["accounts"]}}


@app.get("/api/accounts/list")
async def api_accounts_list(request: Request):
    return {"accounts": user_state(request_user_id(request))["accounts"]}


@app.post("/api/accounts/refresh")
async def api_accounts_refresh(request: Request, data: dict):
    u = user_state(request_user_id(request))
    aid = data.get("account_id")
    account = next((a for a in u["accounts"] if str(a.get("id")) == str(aid)), None)
    if not account:
        return {"error": "Account not found"}
    # Do not fabricate a refreshed session. Report the stored session state.
    return {"ok": bool(account.get("cookies")), "account": account, "message": "Session is stored locally; no fake refresh was performed."}


@app.post("/api/accounts/refresh_bulk")
async def api_accounts_refresh_bulk(request: Request, data: dict):
    u = user_state(request_user_id(request))
    ids = {str(x) for x in data.get("account_ids", [])}
    rows = []
    for a in u["accounts"]:
        if str(a.get("id")) in ids:
            rows.append({"mobile": a.get("mobile"), "id": a.get("id"), "ok": bool(a.get("cookies")), "error": None if a.get("cookies") else "No stored session"})
    return {"results": rows}


@app.post("/api/accounts/delete")
async def api_accounts_delete(request: Request, data: dict):
    u = user_state(request_user_id(request))
    ids = {str(x) for x in data.get("account_ids", [])}
    before = len(u["accounts"])
    u["accounts"] = [a for a in u["accounts"] if str(a.get("id")) not in ids]
    if u["active_id"] is not None and not any(str(a.get("id")) == str(u["active_id"]) for a in u["accounts"]):
        u["active_id"] = u["accounts"][0]["id"] if u["accounts"] else None
    await save_db()
    return {"deleted": before - len(u["accounts"])}


@app.post("/api/accounts/export_files")
async def api_accounts_export_files(request: Request, data: dict):
    # Do not expose session cookies through an arbitrary HTTP download.
    return {"sent": 0, "failed": [{"id": x, "error": "Session export is disabled for web security."} for x in data.get("account_ids", [])]}


@app.post("/api/account/export_file")
async def api_account_export_file():
    return {"error": "Session export is disabled for web security."}


@app.post("/api/search")
async def api_search(data: dict):
    query = str(data.get("query") or "").strip()
    offset = max(0, int(data.get("offset") or 0))
    results = search_catalog(query)
    page = results[offset:offset + 20]
    cursor = str(offset + 20) if offset + 20 < len(results) else None
    return {"catalogs": page, "cursor": cursor, "search_session_id": secrets.token_hex(6), "corrected_term": None}


@app.get("/api/product")
async def api_product_detail(product_id: int):
    p = product_by_id(product_id)
    if not p:
        return {"error": "Product not found", "product_id": product_id}
    p = dict(p)
    p.update({"mrp": p.get("original_price"), "brand": "", "supplier_rating": p.get("rating"), "supplier_rating_count": p.get("rating_count"), "in_stock": True, "highlights": [], "description": p.get("name", "")})
    return p


@app.post("/api/product/by_link")
async def api_product_by_link(data: dict):
    link = str(data.get("link") or "").strip()
    m = re.search(r"(?:products/|p/|product/)(\d+)", link)
    if not m:
        return {"error": "bad_link", "message": "This build only accepts a direct Meesho product URL containing a product id."}
    p = product_by_id(int(m.group(1)))
    if not p:
        return {"error": "not_found", "message": "Product is not available in the local catalog."}
    return p


@app.post("/api/variation")
async def api_variation(data: dict):
    p = product_by_id(int(data.get("product_id", 0))) if data.get("product_id") else None
    return {"price": p.get("price", 0) if p else 0, "mrp": p.get("original_price", 0) if p else 0, "discount": p.get("discount_text", ""), "in_stock": True, "cod_available": True, "shipping": {"charges": 0, "estimated_delivery": {"title": "Standard delivery", "date": "Check at checkout"}}}


@app.get("/api/cart")
async def api_get_cart(request: Request):
    return user_state(request_user_id(request))["cart"]


@app.post("/api/cart/add")
async def api_cart_add(request: Request, data: dict):
    u = user_state(request_user_id(request))
    pid = data.get("product_id")
    p = product_by_id(int(pid)) if pid is not None else None
    if not p:
        return {"error": "Product not found"}
    qty = max(1, int(data.get("quantity") or 1))
    item = {"product_id": p["product_id"], "name": p["name"], "price": p["price"], "quantity": qty, "image": p["image"]}
    existing = next((x for x in u["cart"]["items"] if int(x["product_id"]) == int(p["product_id"])), None)
    if existing:
        existing["quantity"] += qty
    else:
        u["cart"]["items"].append(item)
    u["cart"]["total_quantity"] = sum(int(x["quantity"]) for x in u["cart"]["items"])
    u["cart"]["effective_total"] = sum(int(x["quantity"]) * float(x["price"]) for x in u["cart"]["items"])
    u["cart"]["effective_online"] = u["cart"]["effective_total"]
    await save_db()
    return {"success": True, "result": u["cart"]}


@app.post("/api/cart/update")
async def api_cart_update(request: Request, data: dict):
    u = user_state(request_user_id(request))
    pid = data.get("product_id")
    qty = int(data.get("quantity") or 0)
    for item in list(u["cart"]["items"]):
        if str(item.get("product_id")) == str(pid):
            if qty <= 0:
                u["cart"]["items"].remove(item)
            else:
                item["quantity"] = qty
    u["cart"]["total_quantity"] = sum(int(x["quantity"]) for x in u["cart"]["items"])
    u["cart"]["effective_total"] = sum(int(x["quantity"]) * float(x["price"]) for x in u["cart"]["items"])
    u["cart"]["effective_online"] = u["cart"]["effective_total"]
    await save_db()
    return {"ok": True, **u["cart"]}


@app.post("/api/cart/location")
async def api_cart_location(request: Request, data: dict):
    u = user_state(request_user_id(request))
    addr = next((a for a in u["addresses"] if str(a.get("id")) == str(data.get("address_id"))), None)
    u["cart"]["address"] = addr
    await save_db()
    return {"ok": True, "address": addr}


@app.get("/api/addresses")
async def api_get_addresses(request: Request):
    u = user_state(request_user_id(request))
    default = next((a for a in u["addresses"] if a.get("is_default")), u["addresses"][0] if u["addresses"] else None)
    return {"addresses": u["addresses"], "default": default}


@app.get("/api/geocode")
async def api_geocode(q: Optional[str] = None, lat: Optional[float] = None, lng: Optional[float] = None):
    return {"results": [{"formatted": q or "Location", "city": "", "state": "", "area": "", "pin": "", "lat": lat, "lng": lng}]}


@app.post("/api/addresses/create")
async def api_address_create(request: Request, data: dict):
    u = user_state(request_user_id(request))
    new_id = max([int(a.get("id", 0)) for a in u["addresses"]] or [100]) + 1
    a = dict(data)
    a["id"] = new_id
    a["pin_serviceable"] = True
    if not u["addresses"]:
        a["is_default"] = True
    u["addresses"].append(a)
    await save_db()
    return {"ok": True, "address": a}


@app.post("/api/addresses/update")
async def api_address_update(request: Request, data: dict):
    u = user_state(request_user_id(request))
    aid = data.get("id")
    a = next((x for x in u["addresses"] if str(x.get("id")) == str(aid)), None)
    if not a:
        return {"error": "Address not found"}
    a.update(data)
    await save_db()
    return {"ok": True, "address": a}


@app.post("/api/addresses/set_default")
async def api_address_default(request: Request, data: dict):
    u = user_state(request_user_id(request))
    aid = data.get("id")
    for a in u["addresses"]:
        a["is_default"] = str(a.get("id")) == str(aid)
    await save_db()
    return {"ok": True}


@app.post("/api/addresses/random_update")
async def api_address_random(request: Request, data: dict):
    u = user_state(request_user_id(request))
    a = next((x for x in u["addresses"] if str(x.get("id")) == str(data.get("address_id"))), None)
    if not a:
        return {"error": "Address not found"}
    return {"ok": True, "address": a}


@app.post("/api/addresses/copy_to_active")
async def api_copy_address(request: Request):
    u = user_state(request_user_id(request))
    return {"ok": bool(u["active_id"]), "message": "Default address is available to the active account." if u["active_id"] else "No active account."}


@app.post("/api/order/prices")
async def api_order_prices(request: Request, data: dict):
    u = user_state(request_user_id(request))
    total = float(u["cart"].get("effective_total", 0))
    return {"cod": total, "online": total}


@app.post("/api/order/place_cod")
async def api_place_cod(request: Request, data: dict):
    u = user_state(request_user_id(request))
    if not u["cart"]["items"]:
        return {"error": "Cart is empty"}
    order_num = "OD" + secrets.token_hex(5).upper()
    order = {"order_num": order_num, "status": "Placed", "total": u["cart"]["effective_total"], "items": list(u["cart"]["items"]), "address": u["cart"].get("address")}
    u["orders"].insert(0, order)
    u["cart"] = blank_user()["cart"]
    await save_db()
    return {"ok": True, "order_num": order_num, "total": order["total"], "message": "Order placed in local bot state."}


@app.post("/api/order/pay_online")
async def api_pay_online():
    return {"error": "Online payment is not implemented in this build."}


@app.post("/api/order/payment_status")
async def api_payment_status():
    return {"error": "Online payment is not implemented in this build."}


@app.post("/api/order/confirm")
async def api_order_confirm():
    return {"ok": True}


@app.get("/api/orders")
async def api_get_orders(request: Request):
    u = user_state(request_user_id(request))
    return {"orders": u["orders"], "filters": [{"id": 0, "name": "All"}], "cursor": None}


@app.get("/api/referral/stats")
async def api_referral_stats(request: Request):
    u = user_state(request_user_id(request))
    return {"done": 0, "pending": 0, "rejected": 0, "earned": 0, "link": u["referral_link"], "has_link": bool(u["referral_link"])}


@app.get("/api/account/fod")
async def api_fod():
    return {"offer": {"title": "Meesho account", "text": "Use available offers", "subtitle": "Offers are determined by Meesho at checkout."}}


@app.get("/api/wallet/history")
async def api_wallet_history():
    return {"balance": 0, "txns": []}


@app.post("/api/price/check")
async def api_price_check(request: Request, data: dict):
    link = str(data.get("link") or "").strip()
    m = re.search(r"(?:products/|p/|product/)(\d+)", link)
    if not m:
        return {"error": "bad_link", "message": "Enter a direct Meesho product URL with a product id."}
    p = product_by_id(int(m.group(1)))
    if not p:
        return {"error": "not_found", "message": "Product is not available in the local catalog."}
    u = user_state(request_user_id(request))
    ids = {str(x) for x in data.get("account_ids", [])}
    accounts = [a for a in u["accounts"] if str(a.get("id")) in ids]
    return {"product": {"name": p["name"], "image": p["image"]}, "results": [{"mobile": a.get("mobile"), "price": p["price"], "offer_price": p["price"], "in_stock": True} for a in accounts]}
