"""Payment deviation fraud detection.

Every payment submitted through the gateway is evaluated against the
user's own historical spending baseline (mean / std of their SUCCESS
transactions) before it is executed:

    ALLOW   -> payment approved and executed (status SUCCESS)
    REVIEW  -> payment HELD for manual verification (status FLAGGED)
    BLOCK   -> payment DECLINED outright (status BLOCKED)

Deviations are measured two ways:
    * z-score against the user's own distribution, and
    * multiple of the user's regular average payment.

Both a REVIEW and a BLOCK record an automatic threat so the admin sees
it in the Threat Center without anyone pressing a button.
"""
from dataclasses import dataclass

import numpy as np
import pandas as pd

import data

ALLOW = "ALLOW"
REVIEW = "REVIEW"
BLOCK = "BLOCK"

SEVERITY_BY_DECISION = {
    ALLOW: None,
    REVIEW: "MEDIUM",
    BLOCK: "CRITICAL",
}


@dataclass
class PaymentDecision:
    decision: str          # ALLOW / REVIEW / BLOCK
    reason: str
    mean: float            # user's regular average payment
    std: float
    z_score: float         # deviation of this payment (in std deviations)
    deviation_pct: float   # signed % deviation from the average
    history_count: int
    severity: str | None = None

    @property
    def approved(self):
        return self.decision == ALLOW

    @property
    def blocked(self):
        return self.decision == BLOCK


class FraudDetector:
    def __init__(self,
                 review_z=2.0,
                 block_z=3.0,
                 block_avg_multiple=3.0,
                 review_avg_multiple=1.75,
                 min_history=5,
                 absolute_cap=1_000_000.0):
        self.review_z = review_z
        self.block_z = block_z
        self.block_avg_multiple = block_avg_multiple
        self.review_avg_multiple = review_avg_multiple
        self.min_history = min_history
        self.absolute_cap = absolute_cap

    # ---------- baseline ----------
    def _history(self, user_id):
        """SUCCESS transactions only — held/declined payments must never
        be able to poison the baseline."""
        raw = data.get_transactions(user_id)
        if not raw:
            return pd.DataFrame(columns=["amount"])
        columns = ["transaction_id", "user_id", "amount",
                   "timestamp", "recipient", "status"]
        df = pd.DataFrame(raw, columns=columns)
        df = df[df["status"] == "SUCCESS"]
        return df

    def baseline(self, user_id):
        """Return dict(count, mean, std) of the user's regular payments."""
        df = self._history(user_id)
        if df.empty:
            return {"count": 0, "mean": 0.0, "std": 0.0}

        amounts = df["amount"].astype(float)
        std = float(np.std(amounts))
        return {
            "count": int(len(amounts)),
            "mean": float(np.mean(amounts)),
            "std": float(std),
        }

    # ---------- live payment evaluation ----------
    def evaluate(self, user_id, amount):
        """Decide what to do with a proposed payment."""
        amount = float(amount)
        base = self.baseline(user_id)
        count, mean, std = base["count"], base["mean"], base["std"]

        # Absolute sanity cap (protects even brand-new accounts).
        if amount <= 0:
            return PaymentDecision(
                BLOCK, "Payment amount must be positive.",
                mean, std, 0.0, 0.0, count, "LOW")
        if amount > self.absolute_cap:
            return PaymentDecision(
                BLOCK,
                f"₹{amount:,.2f} exceeds the absolute per-payment limit "
                f"of ₹{self.absolute_cap:,.0f}.",
                mean, std, self.block_z + 1,
                self._pct(amount, mean), count, "CRITICAL")

        # Not enough history yet -> accept but keep monitoring.
        if count < self.min_history:
            return PaymentDecision(
                ALLOW,
                f"Only {count} previous payments — baseline still being "
                f"established, payment accepted for monitoring.",
                mean, std, 0.0, self._pct(amount, mean), count, None)

        # Failsafe: identical historical amounts -> avoid divide-by-zero.
        safe_std = std if std > 0 else 1.0
        z = (amount - mean) / safe_std
        pct = self._pct(amount, mean)

        # --- BLOCK: strong deviation, prevents the fraud -------------
        if z >= self.block_z or amount >= mean * self.block_avg_multiple:
            return PaymentDecision(
                BLOCK,
                (f"₹{amount:,.2f} is {z:.1f}σ above your regular average "
                 f"of ₹{mean:,.2f} ({pct:+.0f}%) and "
                 f"{amount / mean:.1f}x your average payment — "
                 f"declined to prevent fraud."),
                mean, std, z, pct, count, "CRITICAL")

        # --- REVIEW: suspicious deviation, payment held ---------------
        if z >= self.review_z or amount >= mean * self.review_avg_multiple:
            return PaymentDecision(
                REVIEW,
                (f"₹{amount:,.2f} deviates from your regular average of "
                 f"₹{mean:,.2f} ({z:.1f}σ, {pct:+.0f}%) — payment held "
                 f"for verification."),
                mean, std, z, pct, count, "HIGH")

        # Unusually *small* payment (e.g. token/exfiltration pattern).
        if z <= -self.review_z:
            return PaymentDecision(
                REVIEW,
                (f"₹{amount:,.2f} is {abs(z):.1f}σ below your regular "
                 f"average of ₹{mean:,.2f} ({pct:+.0f}%) — payment held "
                 f"for verification."),
                mean, std, z, pct, count, "MEDIUM")

        return PaymentDecision(
            ALLOW,
            (f"₹{amount:,.2f} is within your normal range "
             f"(avg ₹{mean:,.2f}, {z:+.1f}σ, {pct:+.0f}%)."),
            mean, std, z, pct, count, None)

    @staticmethod
    def _pct(amount, mean):
        if not mean:
            return 0.0
        return (amount - mean) / mean * 100.0

    # ---------- what the app does with a decision ----------
    @staticmethod
    def record_payment(user_id, decision, amount, recipient):
        """Persist the payment with the status implied by the decision and
        raise an automatic threat for held/declined payments."""
        status = {ALLOW: "SUCCESS", REVIEW: "FLAGGED", BLOCK: "BLOCKED"}[decision.decision]
        data.add_transaction(user_id, amount, recipient, status=status)

        if decision.decision in (REVIEW, BLOCK):
            threat_type = ("SUSPICIOUS PAYMENT" if decision.decision == REVIEW
                           else "BLOCKED FRAUDULENT PAYMENT")
            data.add_threat(
                user_id,
                threat_type,
                decision.severity or "MEDIUM",
                (f"{status}: ₹{float(amount):,.2f} to '{recipient}'. "
                 f"{decision.reason}"),
            )
        return status

    # ---------- historical scan (admin tool) ----------
    def analyze_user(self, user_id, z_score_threshold=None):
        """Re-scan a user's past transactions and flag anomalies."""
        threshold = z_score_threshold or self.block_z
        base = self.baseline(user_id)
        if base["count"] < self.min_history:
            return 0

        df = self._history(user_id)
        mean, std = base["mean"], base["std"] or 1.0
        df = df.copy()
        df["z_score"] = (df["amount"].astype(float) - mean) / std
        fraudulent = df[df["z_score"].abs() > threshold]

        flagged = 0
        for _, row in fraudulent.iterrows():
            description = (
                f"Financial Anomaly: spend of ₹{row['amount']:.2f}. "
                f"User baseline is ₹{mean:.2f} "
                f"(z-score {row['z_score']:.2f})"
            )
            data.add_threat(
                user_id, "FINANCIAL_FRAUD", "CRITICAL", description)
            flagged += 1
        return flagged


# --- Execution block (for testing purposes) ---
if __name__ == "__main__":
    detector = FraudDetector()
    print("F.A.D.E. (Fraud and Anomaly Detection Engine) initialized.")
