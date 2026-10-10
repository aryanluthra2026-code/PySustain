import pandas as pd
import numpy as np
import data  

class FraudDetector:
    def __init__(self, z_score_threshold=3.0):
        # 3.0 means a 99.7% statistical confidence that the transaction is an anomaly.
        self.threshold = z_score_threshold

    def analyze_user(self, user_id):
        # 1. Fetch raw data using your teammate's exact function
        raw_data = data.get_transactions(user_id)
        
        if not raw_data or len(raw_data) < 5:
            print(f"[INFO] User {user_id}: Insufficient transaction history to build a baseline.")
            return

        # 2. Structure the data using Pandas
        # We must map this exactly to the schema in data.py
        columns = ['transaction_id', 'user_id', 'amount', 'timestamp', 'recipient', 'status']
        df = pd.DataFrame(raw_data, columns=columns)

        # 3. The Math: Calculate Mean and Standard Deviation (Baseline)
        mean_spend = np.mean(df['amount'])
        std_spend = np.std(df['amount'])

        # Failsafe: If all transactions are identical, std_spend is 0. This prevents division by zero.
        if std_spend == 0:
            std_spend = 1.0 

        # 4. The Algorithm: Calculate the Z-Score for every transaction
        df['z_score'] = (df['amount'] - mean_spend) / std_spend
        
        # 5. Flag transactions that breach the mathematical threshold
        df['is_fraud'] = abs(df['z_score']) > self.threshold

        # Filter the DataFrame to only show the fraudulent transactions
        fraudulent_txs = df[df['is_fraud'] == True]

        if fraudulent_txs.empty:
            print(f"[SAFE] User {user_id}: All transactions fall within normal baseline limits.")
            return

        # 6. Database Handoff: Push anomalies to the Database using teammate's function
        for index, row in fraudulent_txs.iterrows():
            description = (
                f"Financial Anomaly: Spend of ₹{row['amount']:.2f}. "
                f"User Baseline is ₹{mean_spend:.2f} (Severity Z-Score: {row['z_score']:.2f})"
            )
            
            # This is where your code seamlessly integrates with your teammate's architecture
            data.add_threat(
                user_id=int(user_id),
                threat_type="FINANCIAL_FRAUD",
                severity="CRITICAL",
                description=description
            )
            print(f"🚨 [THREAT LOGGED] User {user_id} | Amount: ₹{row['amount']} | {description}")

# --- Execution Block (For testing purposes) ---
if __name__ == "__main__":
    detector = FraudDetector()
    print("F.A.D.E. (Fraud and Anomaly Detection Engine) Initialized.")