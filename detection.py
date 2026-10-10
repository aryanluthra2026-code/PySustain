from data import get_login_logs, add_threat, get_threats


def detect_repeated_failed_logins(threshold=3):
    logs = get_login_logs()

    # Count failed login events for each user.
    failed_counts = {}

    for log in logs:
        user_id = log[1]
        status = str(log[3]).upper()

        if user_id is not None and status == "FAILED":
            failed_counts[user_id] = (
                failed_counts.get(user_id, 0) + 1
            )

    # Find existing open alerts to avoid duplicates.
    existing_threats = get_threats()

    existing_alerts = {
        (threat[1], threat[2])
        for threat in existing_threats
        if str(threat[6]).upper() == "OPEN"
    }

    alerts_created = 0

    for user_id, count in failed_counts.items():

        alert_key = (user_id, "Multiple Failed Logins")

        if count >= threshold and alert_key not in existing_alerts:
            add_threat(
                user_id,
                "Multiple Failed Logins",
                "HIGH",
                (
                    f"{count} failed login events recorded "
                    f"for user {user_id}."
                ),
            )

            alerts_created += 1

    return alerts_created
