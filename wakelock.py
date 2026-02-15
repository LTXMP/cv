import time
import requests

# REPLACE WITH YOUR RENDER URL
URL = "https://exclusive-aim-backend.onrender.com"

def wake_loop():
    print(f"Starting WakeLock for {URL}")
    while True:
        try:
            response = requests.get(URL)
            print(f"[{time.strftime('%H:%M:%S')}] Ping Status: {response.status_code}")
        except Exception as e:
            print(f"Ping Failed: {e}")
        
        # Render sleeps after 15 mins of inactivity. Ping every 14 mins.
        time.sleep(14 * 60) 

if __name__ == "__main__":
    wake_loop()
