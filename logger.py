import datetime

def log_alert(message):
    with open("alerts.log", "a") as file:
        timestamp = datetime.datetime.now()
        file.write(f"[{timestamp}] {message}\n")