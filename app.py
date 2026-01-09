from flask import (
    Flask, render_template, request, redirect, url_for,
    make_response, session, flash
)
from datetime import datetime, date
import sqlite3
from contextlib import closing
import os
from collections import defaultdict
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import re
import json
import urllib.request
import csv
import io

# ==========================================================
# CONFIG
# ==========================================================
app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Em produção (Render) use disco persistente:
# Configure DB_DIR=/var/data no Render.
DB_DIR = os.environ.get("DB_DIR", BASE_DIR)
DB_PATH = os.path.join(DB_DIR, "controle_gastos.db")
os.makedirs(DB_DIR, exist_ok=True)

app.secret_key = os.environ.get("SECRET_KEY", "mude-esta-chave-em-producao")

BILLING_DAY_DEFAULT = 10

DEFAULT_CATEGORIES = [
    "Supermercado",
    "Ensino",
    "Farmácia",
    "Parcelas Cartão",
    "Contas de Casa",
    "Outros",
]

PAYMENT_METHODS = ["credito", "debito", "pix", "dinheiro"]


# ==========================================================
# DB HELPERS
# ==========================================================
def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def table_exists(cur, table_name: str) -> bool:
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
    return cur.fetchone() is not None


def column_exists(cur, table_name: str, col_name: str) -> bool:
    cur.execute(f"PRAGMA table_info({table_name})")
    cols = [r[1] for r in cur.fetchall()]
    return col_name in cols


def migrate_db():
    """
    Migração idempotente (não apaga dados).
    """
    with closing(get_connection()) as conn:
        cur = conn.cursor()

        # USERS
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cpf TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            must_change_password INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
        """)

        # ACCOUNTS
        cur.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            owner_user_id INTEGER
        )
        """)

        # ACCOUNT MEMBERS
        cur.execute("""
        CREATE TABLE IF NOT EXISTS account_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            role TEXT NOT NULL DEFAULT 'member'
        )
        """)

        # ENTRIES
        cur.execute("""
        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,                 -- income|expense
            category TEXT,
            source TEXT,
            value REAL NOT NULL,
            date TEXT NOT NULL,                 -- YYYY-MM-DD
            installments_total INTEGER,
            account_id INTEGER,

            payment_method TEXT,                -- credito|debito|pix|dinheiro
            card_brand TEXT,
            points_earned REAL
        )
        """)

        # SETTINGS
        cur.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
        """)
        cur.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES ('billing_day', ?)",
            (str(BILLING_DAY_DEFAULT),)
        )

        # CATEGORIES
        cur.execute("""
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(account_id, name)
        )
        """)

        # REWARD RATES
        cur.execute("""
        CREATE TABLE IF NOT EXISTS reward_rates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER NOT NULL,
            brand TEXT NOT NULL,
            points_per_currency REAL NOT NULL,
            currency_unit TEXT NOT NULL DEFAULT 'BRL', -- BRL|USD
            created_at TEXT NOT NULL,
            UNIQUE(account_id, brand)
        )
        """)

        # BUDGETS (Orçamento por categoria/mês de fatura)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS budgets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER NOT NULL,
            month_key TEXT NOT NULL,           -- YYYY-MM
            category TEXT NOT NULL,
            limit_value REAL NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(account_id, month_key, category)
        )
        """)

        # Garantir colunas em DBs antigos
        if table_exists(cur, "entries"):
            if not column_exists(cur, "entries", "payment_method"):
                cur.execute("ALTER TABLE entries ADD COLUMN payment_method TEXT")
            if not column_exists(cur, "entries", "card_brand"):
                cur.execute("ALTER TABLE entries ADD COLUMN card_brand TEXT")
            if not column_exists(cur, "entries", "points_earned"):
                cur.execute("ALTER TABLE entries ADD COLUMN points_earned REAL")

        if table_exists(cur, "reward_rates"):
            if not column_exists(cur, "reward_rates", "currency_unit"):
                cur.execute("ALTER TABLE reward_rates ADD COLUMN currency_unit TEXT NOT NULL DEFAULT 'BRL'")

        conn.commit()


# ==========================================================
# AUTH / UTIL
# ==========================================================
def normalize_cpf(cpf: str) -> str:
    if not cpf:
        return ""
    return "".join(ch for ch in cpf if ch.isdigit())


def get_current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    with closing(get_connection()) as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE id = ?", (uid,))
        return cur.fetchone()


def get_current_account_id():
    acc_id = session.get("account_id")
    if acc_id:
        return acc_id

    user = get_current_user()
    if not user:
        return None

    with closing(get_connection()) as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT account_id FROM account_members WHERE user_id = ? ORDER BY id LIMIT 1",
            (user["id"],),
        )
        row = cur.fetchone()
        if row:
            session["account_id"] = row["account_id"]
            return row["account_id"]
    return None


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return wrapper


def validate_password_strength(password: str):
    if len(password) < 8:
        return False, "A senha deve ter pelo menos 8 caracteres."
    if not re.search(r"[A-Z]", password):
        return False, "A senha deve conter pelo menos uma letra maiúscula."
    if not re.search(r"[a-z]", password):
        return False, "A senha deve conter pelo menos uma letra minúscula."
    if not re.search(r"\d", password):
        return False, "A senha deve conter pelo menos um número."
    if not re.search(r"[^\w\s]", password):
        return False, "A senha deve conter pelo menos um caractere especial."
    return True, None


# ==========================================================
# BILLING DAY / MONTH KEY
# ==========================================================
def get_billing_day() -> int:
    with closing(get_connection()) as conn:
        cur = conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key='billing_day'")
        row = cur.fetchone()
        if row and row["value"]:
            try:
                return int(row["value"])
            except ValueError:
                return BILLING_DAY_DEFAULT
    return BILLING_DAY_DEFAULT


def billing_month_key_for_date(d: date, billing_day: int) -> str:
    """
    Se o lançamento for após o dia de fechamento, ele vai para o mês seguinte.
    """
    year, month = d.year, d.month
    if d.day > billing_day:
        month += 1
        if month > 12:
            month = 1
            year += 1
    return f"{year}-{month:02d}"


def get_current_billing_month_key(billing_day: int) -> str:
    return billing_month_key_for_date(date.today(), billing_day)


def prev_month_key(month_key: str) -> str:
    y, m = map(int, month_key.split("-"))
    m -= 1
    if m <= 0:
        m = 12
        y -= 1
    return f"{y}-{m:02d}"


def last_n_prev_months(month_key: str, n: int):
    out = []
    cur = month_key
    for _ in range(n):
        cur = prev_month_key(cur)
        out.append(cur)
    return out


# ==========================================================
# USD/BRL exchangerate.host + CACHE
# ==========================================================
def fetch_usd_brl_rate_exchangerate_host() -> float:
    url = "https://api.exchangerate.host/latest?base=USD&symbols=BRL"
    with urllib.request.urlopen(url, timeout=10) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    rate = (data.get("rates") or {}).get("BRL")
    if rate is None:
        raise RuntimeError("Resposta sem rates.BRL")
    return float(rate)


def get_usd_brl_rate_cached(max_age_seconds: int = 3600) -> float:
    migrate_db()
    now = datetime.utcnow()

    with closing(get_connection()) as conn:
        cur = conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key='usd_brl_rate'")
        row_rate = cur.fetchone()
        cur.execute("SELECT value FROM settings WHERE key='usd_brl_rate_at'")
        row_at = cur.fetchone()

    last_rate = None
    last_at = None

    if row_rate and row_rate["value"]:
        try:
            last_rate = float(row_rate["value"])
        except Exception:
            last_rate = None

    if row_at and row_at["value"]:
        try:
            last_at = datetime.fromisoformat(row_at["value"])
        except Exception:
            last_at = None

    if last_rate is not None and last_at is not None:
        if (now - last_at).total_seconds() < max_age_seconds:
            return last_rate

    rate = fetch_usd_brl_rate_exchangerate_host()

    with closing(get_connection()) as conn:
        cur = conn.cursor()
        cur.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('usd_brl_rate', ?)", (str(rate),))
        cur.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('usd_brl_rate_at', ?)", (now.isoformat(),))
        conn.commit()

    return rate


# ==========================================================
# CATEGORIES / REWARDS / ENTRIES DATA ACCESS
# ==========================================================
def ensure_default_categories(account_id: int):
    if not account_id:
        return
    now = datetime.utcnow().isoformat()
    with closing(get_connection()) as conn:
        cur = conn.cursor()
        for name in DEFAULT_CATEGORIES:
            cur.execute(
                "INSERT OR IGNORE INTO categories (account_id, name, created_at) VALUES (?, ?, ?)",
                (account_id, name, now),
            )
        conn.commit()


def get_categories_for_account(account_id: int):
    with closing(get_connection()) as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM categories WHERE account_id = ? ORDER BY name COLLATE NOCASE",
            (account_id,),
        )
        return cur.fetchall()


def get_reward_rates(account_id: int):
    with closing(get_connection()) as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM reward_rates WHERE account_id = ? ORDER BY brand COLLATE NOCASE",
            (account_id,),
        )
        return cur.fetchall()


def get_reward_rate_by_brand(account_id: int, brand: str):
    with closing(get_connection()) as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM reward_rates WHERE account_id = ? AND lower(brand) = lower(?)",
            (account_id, brand),
        )
        return cur.fetchone()


def get_all_entries_for_account(account_id: int):
    with closing(get_connection()) as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM entries WHERE account_id = ? ORDER BY date DESC, id DESC",
            (account_id,),
        )
        return cur.fetchall()


def get_entry_for_account(entry_id: int, account_id: int):
    with closing(get_connection()) as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM entries WHERE id = ? AND account_id = ?", (entry_id, account_id))
        return cur.fetchone()


# ==========================================================
# BUDGETS
# ==========================================================
def get_budgets_for_month(account_id: int, month_key: str):
    with closing(get_connection()) as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT category, limit_value FROM budgets WHERE account_id=? AND month_key=?",
            (account_id, month_key),
        )
        rows = cur.fetchall()
    return {r["category"]: float(r["limit_value"]) for r in rows}


def upsert_budget(account_id: int, month_key: str, category: str, limit_value: float):
    now = datetime.utcnow().isoformat()
    with closing(get_connection()) as conn:
        cur = conn.cursor()
        try:
            cur.execute(
                """
                INSERT INTO budgets (account_id, month_key, category, limit_value, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (account_id, month_key, category, limit_value, now),
            )
        except sqlite3.IntegrityError:
            cur.execute(
                """
                UPDATE budgets
                SET limit_value = ?
                WHERE account_id = ? AND month_key = ? AND category = ?
                """,
                (limit_value, account_id, month_key, category),
            )
        conn.commit()


# ==========================================================
# INSTALLMENTS REMAINING
# ==========================================================
def compute_installments_remaining(entry_dict: dict, billing_day: int):
    total = entry_dict.get("installments_total")
    if not total:
        return None
    try:
        total = int(total)
    except (TypeError, ValueError):
        return None

    try:
        d_entry = datetime.strptime(entry_dict["date"], "%Y-%m-%d").date()
    except Exception:
        return total

    first_key = billing_month_key_for_date(d_entry, billing_day)
    current_key = get_current_billing_month_key(billing_day)
    y1, m1 = map(int, first_key.split("-"))
    y2, m2 = map(int, current_key.split("-"))
    months_diff = (y2 - y1) * 12 + (m2 - m1)
    remaining = total - months_diff
    return max(0, remaining)


# ==========================================================
# SUMMARY
# ==========================================================
def compute_summary(entries_rows, month_key, billing_day, categories):
    total_income = 0.0
    total_expenses = 0.0
    total_points = 0.0

    category_totals = {c: 0.0 for c in categories}
    if "Outros" not in category_totals:
        category_totals["Outros"] = 0.0

    for e in entries_rows:
        if not e["date"]:
            continue
        d = datetime.strptime(e["date"], "%Y-%m-%d").date()
        key = billing_month_key_for_date(d, billing_day)
        if key != month_key:
            continue

        val = float(e["value"])
        if e["type"] == "income":
            total_income += val
        else:
            total_expenses += val
            cat = e["category"] or "Outros"
            if cat not in category_totals:
                category_totals[cat] = 0.0
            category_totals[cat] += val

        if e["points_earned"] is not None:
            try:
                total_points += float(e["points_earned"])
            except Exception:
                pass

    balance = total_income - total_expenses
    saving_rate = (balance / total_income * 100) if total_income > 0 else 0.0

    return {
        "month_key": month_key,
        "total_income": total_income,
        "total_expenses": total_expenses,
        "balance": balance,
        "saving_rate": saving_rate,
        "category_totals": category_totals,
        "total_points": round(total_points, 2),
    }


def compute_monthly_stats(entries_rows, billing_day):
    agg = defaultdict(lambda: {"income": 0.0, "expense": 0.0, "points": 0.0})
    for e in entries_rows:
        if not e["date"]:
            continue
        d = datetime.strptime(e["date"], "%Y-%m-%d").date()
        key = billing_month_key_for_date(d, billing_day)
        val = float(e["value"])
        if e["type"] == "income":
            agg[key]["income"] += val
        else:
            agg[key]["expense"] += val
        if e["points_earned"] is not None:
            try:
                agg[key]["points"] += float(e["points_earned"])
            except Exception:
                pass

    months_sorted = sorted(agg.keys())
    labels, income, expense, balance, points = [], [], [], [], []
    for k in months_sorted:
        inc = agg[k]["income"]
        exp = agg[k]["expense"]
        labels.append(k)
        income.append(inc)
        expense.append(exp)
        balance.append(inc - exp)
        points.append(round(agg[k]["points"], 2))

    return {"labels": labels, "income": income, "expense": expense, "balance": balance, "points": points}


def safe_pct_change(current: float, previous: float):
    if previous == 0:
        if current == 0:
            return 0.0
        return None  # "infinito"
    return ((current - previous) / previous) * 100.0


# ==========================================================
# ROUTES: AUTH
# ==========================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    migrate_db()

    if request.method == "POST":
        cpf = normalize_cpf(request.form.get("cpf") or "")
        password = request.form.get("password") or ""

        if not cpf:
            flash("Informe um CPF válido.", "danger")
            return redirect(url_for("login"))

        with closing(get_connection()) as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE cpf = ?", (cpf,))
            user = cur.fetchone()

            # Primeiro acesso: cria usuário e conta
            if not user:
                now = datetime.utcnow().isoformat()
                pwd_hash = generate_password_hash(cpf)  # senha inicial = cpf
                cur.execute(
                    "INSERT INTO users (cpf, password_hash, must_change_password, created_at) VALUES (?, ?, 1, ?)",
                    (cpf, pwd_hash, now),
                )
                user_id = cur.lastrowid

                cur.execute("INSERT INTO accounts (name, owner_user_id) VALUES (?, ?)", ("Conta Principal", user_id))
                account_id = cur.lastrowid

                cur.execute(
                    "INSERT INTO account_members (account_id, user_id, role) VALUES (?, ?, 'owner')",
                    (account_id, user_id),
                )
                conn.commit()

                ensure_default_categories(account_id)

                session["user_id"] = user_id
                session["account_id"] = account_id

                flash("Primeiro acesso detectado. Defina uma nova senha.", "info")
                return redirect(url_for("change_password"))

            if not check_password_hash(user["password_hash"], password):
                flash("Senha incorreta.", "danger")
                return redirect(url_for("login"))

            session["user_id"] = user["id"]
            cur.execute(
                "SELECT account_id FROM account_members WHERE user_id = ? ORDER BY id LIMIT 1",
                (user["id"],),
            )
            row_acc = cur.fetchone()
            if row_acc:
                session["account_id"] = row_acc["account_id"]

        if user["must_change_password"]:
            flash("Defina uma nova senha para continuar.", "info")
            return redirect(url_for("change_password"))

        return redirect(url_for("index"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))

    if request.method == "POST":
        new_pwd = request.form.get("new_password") or ""
        confirm = request.form.get("confirm_password") or ""

        ok, msg = validate_password_strength(new_pwd)
        if not ok:
            flash(msg, "danger")
            return redirect(url_for("change_password"))

        if new_pwd != confirm:
            flash("A confirmação não confere.", "danger")
            return redirect(url_for("change_password"))

        pwd_hash = generate_password_hash(new_pwd)

        with closing(get_connection()) as conn:
            cur = conn.cursor()
            cur.execute(
                "UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?",
                (pwd_hash, user["id"]),
            )
            conn.commit()

        flash("Senha alterada com sucesso.", "success")
        return redirect(url_for("index"))

    must_change = bool(user["must_change_password"])
    return render_template("change_password.html", must_change=must_change, user=user)


# ==========================================================
# ROUTES: DASHBOARD
# ==========================================================
@app.route("/", methods=["GET"])
@login_required
def index():
    migrate_db()

    billing_day = get_billing_day()
    account_id = get_current_account_id()
    user = get_current_user()

    if not account_id:
        flash("Nenhuma conta vinculada ao usuário.", "danger")
        return redirect(url_for("logout"))

    ensure_default_categories(account_id)
    categories = [r["name"] for r in get_categories_for_account(account_id)]
    reward_rates = get_reward_rates(account_id)

    try:
        usd_brl_rate = get_usd_brl_rate_cached()
    except Exception:
        usd_brl_rate = None

    entries_raw = get_all_entries_for_account(account_id)

    month_key = request.args.get("month") or get_current_billing_month_key(billing_day)
    summary = compute_summary(entries_raw, month_key, billing_day, categories)

    # --------- ORÇAMENTOS (já existente) ----------
    budgets = get_budgets_for_month(account_id, month_key)
    budget_progress = []
    for cat, spent in summary["category_totals"].items():
        limit_val = budgets.get(cat)
        if limit_val is None or limit_val <= 0:
            pct = None
            status = "no_budget"
        else:
            pct = (spent / limit_val) * 100
            if pct >= 100:
                status = "over"
            elif pct >= 80:
                status = "warn"
            else:
                status = "ok"

        budget_progress.append({
            "category": cat,
            "spent": float(spent),
            "limit": float(limit_val) if limit_val is not None else None,
            "pct": float(pct) if pct is not None else None,
            "status": status,
        })

    # --------- NOVO: COMPARATIVO MÊS A MÊS ----------
    prev_key = prev_month_key(month_key)
    prev_summary = compute_summary(entries_raw, prev_key, billing_day, categories)

    last3_keys = last_n_prev_months(month_key, 3)  # 3 anteriores
    last3_summaries = [compute_summary(entries_raw, k, billing_day, categories) for k in last3_keys]
    avg3_expenses = sum(s["total_expenses"] for s in last3_summaries) / 3.0
    avg3_income = sum(s["total_income"] for s in last3_summaries) / 3.0

    exp_vs_prev = summary["total_expenses"] - prev_summary["total_expenses"]
    inc_vs_prev = summary["total_income"] - prev_summary["total_income"]

    exp_vs_prev_pct = safe_pct_change(summary["total_expenses"], prev_summary["total_expenses"])
    inc_vs_prev_pct = safe_pct_change(summary["total_income"], prev_summary["total_income"])

    exp_vs_avg3 = summary["total_expenses"] - avg3_expenses
    inc_vs_avg3 = summary["total_income"] - avg3_income

    exp_vs_avg3_pct = safe_pct_change(summary["total_expenses"], avg3_expenses)
    inc_vs_avg3_pct = safe_pct_change(summary["total_income"], avg3_income)

    compare = {
        "current_key": month_key,
        "prev_key": prev_key,
        "avg3_keys": last3_keys,
        "prev": {
            "income": prev_summary["total_income"],
            "expenses": prev_summary["total_expenses"],
        },
        "avg3": {
            "income": avg3_income,
            "expenses": avg3_expenses,
        },
        "delta": {
            "exp_vs_prev": exp_vs_prev,
            "inc_vs_prev": inc_vs_prev,
            "exp_vs_avg3": exp_vs_avg3,
            "inc_vs_avg3": inc_vs_avg3,
        },
        "pct": {
            "exp_vs_prev": exp_vs_prev_pct,
            "inc_vs_prev": inc_vs_prev_pct,
            "exp_vs_avg3": exp_vs_avg3_pct,
            "inc_vs_avg3": inc_vs_avg3_pct,
        }
    }

    # --------- NOVO: “ONDE VOCÊ GASTOU MAIS” ----------
    current_cat = summary["category_totals"]
    prev_cat = prev_summary["category_totals"]

    max_spent = max(current_cat.values()) if current_cat else 0.0

    cat_rank = []
    for cat, spent in current_cat.items():
        prev_spent = float(prev_cat.get(cat, 0.0))
        delta = float(spent) - prev_spent
        pct = safe_pct_change(float(spent), prev_spent)
        bar_pct = (float(spent) / max_spent * 100.0) if max_spent > 0 else 0.0
        cat_rank.append({
            "category": cat,
            "spent": float(spent),
            "prev_spent": prev_spent,
            "delta": delta,
            "pct": pct,
            "bar_pct": bar_pct,
        })

    cat_rank.sort(key=lambda x: x["spent"], reverse=True)

    # Entries com parcelas restantes
    entries = []
    for row in entries_raw:
        d_row = dict(row)
        if d_row.get("category") == "Parcelas Cartão" and d_row.get("installments_total") is not None:
            d_row["installments_remaining_view"] = compute_installments_remaining(d_row, billing_day)
        else:
            d_row["installments_remaining_view"] = None
        entries.append(d_row)

    months = sorted(
        {
            billing_month_key_for_date(
                datetime.strptime(r["date"], "%Y-%m-%d").date(), billing_day
            )
            for r in entries_raw
            if r["date"]
        },
        reverse=True,
    )

    monthly_stats = compute_monthly_stats(entries_raw, billing_day)
    today_str = date.today().isoformat()

    return render_template(
        "index.html",
        entries=entries,
        summary=summary,
        categories=categories,
        months=months,
        monthly_stats=monthly_stats,
        billing_day=billing_day,
        user=user,
        reward_rates=reward_rates,
        usd_brl_rate=usd_brl_rate,
        payment_methods=PAYMENT_METHODS,
        today_str=today_str,
        budgets=budgets,
        budget_progress=budget_progress,
        compare=compare,
        cat_rank=cat_rank,
    )


# ==========================================================
# ROUTES: BILLING DAY
# ==========================================================
@app.route("/set-billing-day", methods=["POST"])
@login_required
def set_billing_day_route():
    migrate_db()

    day_str = request.form.get("billing_day") or str(BILLING_DAY_DEFAULT)
    try:
        day = int(day_str)
    except ValueError:
        day = BILLING_DAY_DEFAULT

    day = max(1, min(day, 28))

    with closing(get_connection()) as conn:
        cur = conn.cursor()
        cur.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('billing_day', ?)", (str(day),))
        conn.commit()

    flash(
        f"Fechamento atualizado para dia {day}. "
        f"Lançamentos após o dia {day} entram no mês seguinte.",
        "success",
    )
    return redirect(url_for("index"))


# ==========================================================
# ROUTES: BUDGETS PAGE
# ==========================================================
@app.route("/budgets", methods=["GET", "POST"])
@login_required
def budgets_page():
    migrate_db()
    account_id = get_current_account_id()
    if not account_id:
        return redirect(url_for("logout"))

    billing_day = get_billing_day()
    ensure_default_categories(account_id)
    categories = [r["name"] for r in get_categories_for_account(account_id)]
    month_key = request.args.get("month") or get_current_billing_month_key(billing_day)

    if request.method == "POST":
        for cat in categories:
            field = f"budget_{cat}"
            raw = (request.form.get(field) or "").strip().replace(",", ".")
            if raw == "":
                continue
            try:
                val = float(raw)
                if val < 0:
                    val = 0.0
            except ValueError:
                continue
            upsert_budget(account_id, month_key, cat, val)

        flash("Orçamentos salvos com sucesso.", "success")
        return redirect(url_for("budgets_page", month=month_key))

    budgets = get_budgets_for_month(account_id, month_key)
    return render_template(
        "budgets.html",
        categories=categories,
        budgets=budgets,
        month_key=month_key,
        billing_day=billing_day,
    )


# ==========================================================
# ROUTES: ENTRIES (ADD/EDIT/DELETE/EXPORT)
# ==========================================================
@app.route("/add", methods=["POST"])
@login_required
def add_entry():
    migrate_db()
    account_id = get_current_account_id()
    if not account_id:
        return redirect(url_for("logout"))

    entry_type = (request.form.get("type") or "").strip()
    raw_value = (request.form.get("value") or "").replace(",", ".").strip()
    description = (request.form.get("description") or "").strip()
    category = (request.form.get("category") or "").strip() or None
    date_str = (request.form.get("date") or "").strip() or date.today().isoformat()

    payment_method = (request.form.get("payment_method") or "").strip().lower()
    if payment_method not in PAYMENT_METHODS:
        payment_method = None

    card_brand = (request.form.get("card_brand") or "").strip()
    installments_total = (request.form.get("installments_total") or "").strip() or None
    if installments_total is not None:
        try:
            installments_total = int(installments_total)
        except ValueError:
            installments_total = None

    try:
        value = float(raw_value)
    except ValueError:
        flash("Valor inválido.", "danger")
        return redirect(url_for("index"))

    if entry_type not in ("income", "expense"):
        entry_type = "income"

    if entry_type == "expense" and not category:
        category = "Outros"

    # Pontos
    points_earned = None
    if entry_type == "expense" and payment_method == "credito":
        if card_brand:
            rate_row = get_reward_rate_by_brand(account_id, card_brand)
            if rate_row:
                ppc = float(rate_row["points_per_currency"])
                unit = (rate_row["currency_unit"] or "BRL").upper()
                if unit == "USD":
                    try:
                        usd_brl = get_usd_brl_rate_cached()
                        value_in_usd = float(value) / float(usd_brl)
                        points_earned = round(value_in_usd * ppc, 2)
                    except Exception:
                        points_earned = 0.0
                        flash("Falha ao buscar cotação USD/BRL. Pontos em USD ficaram 0 neste lançamento.", "warning")
                else:
                    points_earned = round(float(value) * ppc, 2)
            else:
                points_earned = 0.0
                flash("Bandeira sem pontuação cadastrada (Pontos = 0). Cadastre em Pontuação.", "warning")
        else:
            points_earned = 0.0

    with closing(get_connection()) as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO entries (
                type, category, source, value, date,
                installments_total, account_id,
                payment_method, card_brand, points_earned
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry_type, category, description, value, date_str,
                installments_total, account_id,
                payment_method, card_brand if payment_method == "credito" else None, points_earned
            ),
        )
        conn.commit()

    return redirect(url_for("index"))


@app.route("/edit/<int:entry_id>", methods=["GET", "POST"])
@login_required
def edit_entry(entry_id):
    migrate_db()
    account_id = get_current_account_id()
    if not account_id:
        return redirect(url_for("logout"))

    ensure_default_categories(account_id)
    categories = [r["name"] for r in get_categories_for_account(account_id)]
    reward_rates = get_reward_rates(account_id)

    entry = get_entry_for_account(entry_id, account_id)
    if not entry:
        flash("Lançamento não encontrado.", "danger")
        return redirect(url_for("index"))

    if request.method == "POST":
        entry_type = (request.form.get("type") or "").strip()
        raw_value = (request.form.get("value") or "").replace(",", ".").strip()
        description = (request.form.get("description") or "").strip()
        category = (request.form.get("category") or "").strip() or None
        date_str = (request.form.get("date") or "").strip() or entry["date"]

        payment_method = (request.form.get("payment_method") or "").strip().lower()
        if payment_method not in PAYMENT_METHODS:
            payment_method = None

        card_brand = (request.form.get("card_brand") or "").strip()
        installments_total = (request.form.get("installments_total") or "").strip() or None
        if installments_total is not None:
            try:
                installments_total = int(installments_total)
            except ValueError:
                installments_total = None

        try:
            value = float(raw_value)
        except ValueError:
            flash("Valor inválido.", "danger")
            return redirect(url_for("edit_entry", entry_id=entry_id))

        if entry_type not in ("income", "expense"):
            entry_type = entry["type"]

        if entry_type == "expense" and not category:
            category = "Outros"

        points_earned = None
        if entry_type == "expense" and payment_method == "credito":
            if card_brand:
                rate_row = get_reward_rate_by_brand(account_id, card_brand)
                if rate_row:
                    ppc = float(rate_row["points_per_currency"])
                    unit = (rate_row["currency_unit"] or "BRL").upper()
                    if unit == "USD":
                        try:
                            usd_brl = get_usd_brl_rate_cached()
                            value_in_usd = float(value) / float(usd_brl)
                            points_earned = round(value_in_usd * ppc, 2)
                        except Exception:
                            points_earned = 0.0
                            flash("Falha ao buscar cotação USD/BRL. Pontos em USD ficaram 0.", "warning")
                    else:
                        points_earned = round(float(value) * ppc, 2)
                else:
                    points_earned = 0.0
            else:
                points_earned = 0.0

        with closing(get_connection()) as conn:
            cur = conn.cursor()
            cur.execute(
                """
                UPDATE entries
                SET
                    type=?,
                    category=?,
                    source=?,
                    value=?,
                    date=?,
                    installments_total=?,
                    payment_method=?,
                    card_brand=?,
                    points_earned=?
                WHERE id=? AND account_id=?
                """,
                (
                    entry_type,
                    category,
                    description,
                    value,
                    date_str,
                    installments_total,
                    payment_method,
                    card_brand if payment_method == "credito" else None,
                    points_earned,
                    entry_id,
                    account_id,
                ),
            )
            conn.commit()

        flash("Lançamento atualizado com sucesso.", "success")
        return redirect(url_for("index"))

    return render_template(
        "edit_entry.html",
        entry=entry,
        categories=categories,
        reward_rates=reward_rates,
        payment_methods=PAYMENT_METHODS,
    )


@app.route("/delete/<int:entry_id>", methods=["POST"])
@login_required
def delete_entry(entry_id):
    migrate_db()
    account_id = get_current_account_id()
    if not account_id:
        return redirect(url_for("logout"))

    with closing(get_connection()) as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM entries WHERE id=? AND account_id=?", (entry_id, account_id))
        conn.commit()

    return redirect(url_for("index"))


@app.route("/export")
@login_required
def export_csv():
    migrate_db()
    account_id = get_current_account_id()
    if not account_id:
        return redirect(url_for("logout"))

    entries = get_all_entries_for_account(account_id)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "id", "type", "category", "source", "value", "date",
        "installments_total", "payment_method", "card_brand", "points_earned"
    ])
    for e in entries:
        writer.writerow([
            e["id"], e["type"], e["category"], e["source"], e["value"], e["date"],
            e["installments_total"], e["payment_method"], e["card_brand"], e["points_earned"]
        ])

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=controle_gastos.csv"
    response.headers["Content-Type"] = "text/csv"
    return response


# ==========================================================
# ROUTES: SHARE ACCOUNT
# ==========================================================
@app.route("/share-account", methods=["GET", "POST"])
@login_required
def share_account():
    migrate_db()
    account_id = get_current_account_id()
    if not account_id:
        return redirect(url_for("logout"))

    if request.method == "POST":
        cpf_raw = request.form.get("cpf") or ""
        cpf = normalize_cpf(cpf_raw)
        if not cpf:
            flash("Informe um CPF válido.", "danger")
            return redirect(url_for("share_account"))

        with closing(get_connection()) as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE cpf = ?", (cpf,))
            target_user = cur.fetchone()

            if not target_user:
                now = datetime.utcnow().isoformat()
                pwd_hash = generate_password_hash(cpf)
                cur.execute(
                    "INSERT INTO users (cpf, password_hash, must_change_password, created_at) VALUES (?, ?, 1, ?)",
                    (cpf, pwd_hash, now),
                )
                target_user_id = cur.lastrowid
            else:
                target_user_id = target_user["id"]

            cur.execute(
                "SELECT 1 FROM account_members WHERE account_id=? AND user_id=?",
                (account_id, target_user_id),
            )
            exists = cur.fetchone()

            if not exists:
                cur.execute(
                    "INSERT INTO account_members (account_id, user_id, role) VALUES (?, ?, 'member')",
                    (account_id, target_user_id),
                )

            conn.commit()

        flash(
            "Conta compartilhada com sucesso. A pessoa faz login com CPF e senha = CPF no primeiro acesso e troca a senha.",
            "success",
        )
        return redirect(url_for("share_account"))

    user = get_current_user()
    return render_template("share_account.html", user=user)


# ==========================================================
# MAIN
# ==========================================================
if __name__ == "__main__":
    migrate_db()
    app.run(debug=True)
