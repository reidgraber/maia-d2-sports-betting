# app.py
import streamlit as st
import sqlite3
from datetime import datetime, date, timedelta
import math
import hashlib

DB_PATH = "bets.db"
HOUSE_MARGIN = 0.04  # 4% house edge
K_ELO = 20

# ---------- DB helpers ----------
def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    c = conn.cursor()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password_hash TEXT,
        coins INTEGER DEFAULT 0,
        last_daily_grant TEXT
    );
    CREATE TABLE IF NOT EXISTS teams (
        id INTEGER PRIMARY KEY,
        name TEXT,
        gender TEXT,
        elo REAL DEFAULT 1500
    );
    CREATE TABLE IF NOT EXISTS games (
        id INTEGER PRIMARY KEY,
        api_game_id TEXT UNIQUE,
        home_team_id INTEGER,
        away_team_id INTEGER,
        start_time TEXT,
        status TEXT,
        home_score INTEGER,
        away_score INTEGER
    );
    CREATE TABLE IF NOT EXISTS bets (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        game_id INTEGER,
        team_id INTEGER,
        stake_coins INTEGER,
        odds_at_placement REAL,
        status TEXT,
        payout_coins INTEGER,
        placed_at TEXT
    );
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        type TEXT,
        amount_coins INTEGER,
        balance_after INTEGER,
        timestamp TEXT
    );
    """)
    conn.commit()
    return conn

# ---------- Auth ----------
def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def create_user(username, password):
    conn = get_conn()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password_hash, coins) VALUES (?, ?, ?)",
                  (username, hash_pw(password), 0))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def check_user(username, password):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    if row and row["password_hash"] == hash_pw(password):
        return dict(row)
    return None

# ---------- Elo & odds ----------
def win_prob(ra, rb):
    return 1.0 / (1.0 + 10 ** ((rb - ra) / 400.0))

def adjusted_odds(p, margin=HOUSE_MARGIN):
    adjusted_p = p * (1 - margin)
    if adjusted_p <= 0:
        adjusted_p = 0.0001
    return 1.0 / adjusted_p

def update_elo(ra, rb, score_a, k=K_ELO):
    # score_a = 1 if A wins, 0 if loses
    pa = win_prob(ra, rb)
    new_ra = ra + k * (score_a - pa)
    new_rb = rb + k * ((1 - score_a) - (1 - pa))
    return new_ra, new_rb

# ---------- Placeholder Live Data ----------
def get_live_games():
    # Placeholder: returns a list of dicts for upcoming games.
    # Replace with a real API integration (Sportradar, TheSportsDB, etc.)
    now = datetime.utcnow()
    return [
        {
            "api_game_id": "game1",
            "home_team": "MAIA State Men",
            "away_team": "Central MAIA Men",
            "start_time": (now + timedelta(minutes=30)).isoformat(),
            "status": "scheduled",
            "home_score": None,
            "away_score": None,
            "gender": "men"
        },
        {
            "api_game_id": "game2",
            "home_team": "MAIA Women",
            "away_team": "Rival College Women",
            "start_time": (now + timedelta(hours=2)).isoformat(),
            "status": "scheduled",
            "home_score": None,
            "away_score": None,
            "gender": "women"
        }
    ]

# ---------- App logic ----------
def grant_daily_coins(user):
    conn = get_conn()
    c = conn.cursor()
    today_str = date.today().isoformat()
    if user["last_daily_grant"] != today_str:
        new_balance = user["coins"] + 5000
        c.execute("UPDATE users SET coins = ?, last_daily_grant = ? WHERE id = ?",
                  (new_balance, today_str, user["id"]))
        c.execute("INSERT INTO transactions (user_id, type, amount_coins, balance_after, timestamp) VALUES (?, ?, ?, ?, ?)",
                  (user["id"], "daily_grant", 5000, new_balance, datetime.utcnow().isoformat()))
        conn.commit()
        user["coins"] = new_balance
        user["last_daily_grant"] = today_str
    return user

def place_bet(user_id, game_id, team_id, stake, odds):
    conn = get_conn()
    c = conn.cursor()
    # deduct stake
    c.execute("SELECT coins FROM users WHERE id = ?", (user_id,))
    coins = c.fetchone()["coins"]
    if coins < stake:
        raise Exception("Insufficient coins")
    new_balance = coins - stake
    c.execute("UPDATE users SET coins = ? WHERE id = ?", (new_balance, user_id))
    c.execute("INSERT INTO bets (user_id, game_id, team_id, stake_coins, odds_at_placement, status, payout_coins, placed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
              (user_id, game_id, team_id, stake, odds, "open", 0, datetime.utcnow().isoformat()))
    c.execute("INSERT INTO transactions (user_id, type, amount_coins, balance_after, timestamp) VALUES (?, ?, ?, ?, ?)",
              (user_id, "bet", -stake, new_balance, datetime.utcnow().isoformat()))
    conn.commit()

def settle_game_and_bets(api_game_id, home_score, away_score):
    conn = get_conn()
    c = conn.cursor()
    # find game
    c.execute("SELECT * FROM games WHERE api_game_id = ?", (api_game_id,))
    g = c.fetchone()
    if not g:
        return
    # update game score
    c.execute("UPDATE games SET home_score = ?, away_score = ?, status = ? WHERE api_game_id = ?",
              (home_score, away_score, "finished", api_game_id))
    # determine winner team id
    winners = []
    if home_score > away_score:
        winners = [g["home_team_id"]]
    elif away_score > home_score:
        winners = [g["away_team_id"]]
    else:
        winners = []  # tie case - refund
    # settle bets
    c.execute("SELECT * FROM bets WHERE game_id = ? AND status = 'open'", (g["id"],))
    open_bets = c.fetchall()
    for b in open_bets:
        if b["team_id"] in winners:
            payout = int(round(b["stake_coins"] * b["odds_at_placement"]))
            # pay user
            c.execute("SELECT coins FROM users WHERE id = ?", (b["user_id"],))
            coins = c.fetchone()["coins"]
            new_balance = coins + payout
            c.execute("UPDATE users SET coins = ? WHERE id = ?", (new_balance, b["user_id"]))
            c.execute("UPDATE bets SET status = ?, payout_coins = ? WHERE id = ?", ("won", payout, b["id"]))
            c.execute("INSERT INTO transactions (user_id, type, amount_coins, balance_after, timestamp) VALUES (?, ?, ?, ?, ?)",
                      (b["user_id"], "payout", payout, new_balance, datetime.utcnow().isoformat()))
        else:
            # lost
            c.execute("UPDATE bets SET status = ? WHERE id = ?", ("lost", b["id"]))
    conn.commit()

# ---------- Streamlit UI ----------
def main():
    st.title("MAIA D2 Fake Betting - Prototype")
    init_db()

    menu = ["Login", "Sign up", "Public games"]
    choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Sign up":
        st.header("Create an account")
        username = st.text_input("username")
        password = st.text_input("password", type="password")
        if st.button("Create"):
            ok = create_user(username, password)
            if ok:
                st.success("User created. Please log in.")
            else:
                st.error("Username taken")

    elif choice == "Login":
        st.header("Login")
        username = st.text_input("username_login")
        password = st.text_input("password_login", type="password")
        if st.button("Login"):
            user = check_user(username, password)
            if user:
                st.session_state["user"] = user
                st.success("Logged in!")
            else:
                st.error("Invalid credentials")

    elif choice == "Public games":
        st.header("Public games (demo)")
        games = get_live_games()
        for g in games:
            st.subheader(f'{g["away_team"]} @ {g["home_team"]} — {g["gender"]}')
            # show computed odds using or creating teams in DB
            conn = get_conn()
            c = conn.cursor()
            # ensure teams exist
            for tname in (g["home_team"], g["away_team"]):
                c.execute("SELECT * FROM teams WHERE name = ?", (tname,))
                if not c.fetchone():
                    c.execute("INSERT INTO teams (name, gender, elo) VALUES (?, ?, ?)", (tname, g["gender"], 1500))
                    conn.commit()
            c.execute("SELECT * FROM teams WHERE name = ?", (g["home_team"],))
            home = c.fetchone()
            c.execute("SELECT * FROM teams WHERE name = ?", (g["away_team"],))
            away = c.fetchone()
            p_home = win_prob(home["elo"], away["elo"])
            p_away = 1 - p_home
            odds_home = adjusted_odds(p_home)
            odds_away = adjusted_odds(p_away)
            st.write(f'Probabilities — Home: {p_home:.3f}, Away: {p_away:.3f}')
            st.write(f'Odds — Home: {odds_home:.2f}, Away: {odds_away:.2f}')
            st.write("----")

    # logged-in UX
    if "user" in st.session_state:
        user = st.session_state["user"]
        # refresh user from DB
        conn = get_conn()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE id = ?", (user["id"],))
        user = dict(c.fetchone())
        user = grant_daily_coins(user)
        st.session_state["user"] = user

        st.sidebar.markdown(f'**{user["username"]}**')
        st.sidebar.markdown(f'Coins: {user["coins"]}')
        if st.sidebar.button("Log out"):
            del st.session_state["user"]
            st.experimental_rerun()

        st.header("Place a bet")
        # list scheduled games from placeholder
        games = get_live_games()
        choices = [f'{g["away_team"]} @ {g["home_team"]} | {g["api_game_id"]}' for g in games]
        sel = st.selectbox("Select game", choices)
        sel_game = games[choices.index(sel)]
        # load teams from DB
        c.execute("SELECT * FROM teams WHERE name = ?", (sel_game["home_team"],))
        home = c.fetchone()
        c.execute("SELECT * FROM teams WHERE name = ?", (sel_game["away_team"],))
        away = c.fetchone()
        p_home = win_prob(home["elo"], away["elo"])
        p_away = 1 - p_home
        odds_home = adjusted_odds(p_home)
        odds_away = adjusted_odds(p_away)
        st.write(f'Odds — Home: {odds_home:.2f}, Away: {odds_away:.2f}')
        team_choice = st.radio("Pick team", [home["name"], away["name"]])
        stake = st.number_input("Stake (coins)", min_value=1, max_value=user["coins"], value=100)
        if st.button("Place bet"):
            chosen_team = home if team_choice == home["name"] else away
            odds_to_use = odds_home if chosen_team["id"] == home["id"] else odds_away
            try:
                place_bet(user["id"], sel_game["api_game_id"], chosen_team["id"], int(stake), float(round(odds_to_use,2)))
                st.success("Bet placed!")
                # refresh display
                st.experimental_rerun()
            except Exception as e:
                st.error(str(e))

        st.header("My bets")
        c.execute("SELECT b.*, g.api_game_id, t.name as team_name FROM bets b JOIN games g ON b.game_id=g.id LEFT JOIN teams t ON b.team_id=t.id WHERE b.user_id = ? ORDER BY b.placed_at DESC", (user["id"],))
        bets = c.fetchall()
        if bets:
            for b in bets:
                st.write(dict(b))
        else:
            st.write("No bets yet.")

if __name__ == "__main__":
    main()
