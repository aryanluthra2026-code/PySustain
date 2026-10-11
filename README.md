# FADE Pay — Fraud Analysis & Detection Engine

A payment-gateway web app (Python / Streamlit) with fully automatic
brute-force login protection and payment-fraud detection.

## Features

- **Brute-force shield** — 5 failed logins auto-lock the account for 15 min;
  8 failures from one IP inside 5 min block that network for 10 min.
  Threats are raised automatically; admin can unlock in Threat Center.
- **Payment fraud shield** — every payment is z-scored against the user's own
  average: >= 2.0 sigma or >= 1.75x avg  -> HELD (flagged, threat raised)
  >= 3.0 sigma or >= 3x avg               -> DECLINED (blocked, CRITICAL threat)
- **Pre-existing data** — `historical_transactions.json` seeds each user with
  transaction history so average-payment baselines exist on first run.
- **Roles** — users transact and see only their own Security Alerts page;
  admins handle attacks only (Overview, Threat Center, Auth Logs, Fraud Activity).
- **Pure-Python frontend** — no HTML/CSS in code; theming via
  `.streamlit/config.toml`.

## Run

    pip install -r requirements.txt
    streamlit run app.py

## Demo accounts

    user1 / user123   user2 / user456   user3 / user789   (users)
    admin1 / admin123   admin2 / admin456                (security ops)

## Files

    app.py                     frontend + all pages (pure Python)
    auth.py                    login page + brute-force gate
    data.py                    SQLite layer (users, logs, transactions, threats)
    detection.py               automatic brute-force / network-attack engine
    fraud_detector.py          payment deviation engine (z-score)
    seed.py                    idempotent seeding of accounts + history
    historical_transactions.json  pre-existing transaction data
    .streamlit/config.toml     theme / runtime config
