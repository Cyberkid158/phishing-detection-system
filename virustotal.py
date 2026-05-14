import requests
import base64

API_KEY = "d21700094ec84d7443cf7e054692917d87013715a840cd6959dca8ce94d6cadf"

def check_virustotal(url):

    try:

        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        headers = {
            "x-apikey": API_KEY
        }

        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        response = requests.get(vt_url, headers=headers)

        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]

        malicious = stats["malicious"]
        suspicious = stats["suspicious"]

        return malicious, suspicious

    except Exception as e:

        return 0, 0
