import requests
from concurrent.futures import ThreadPoolExecutor

def check_xss(url):
    with open('payloads/xss_payload.txt', 'r') as file:
        payloads = [line.strip() for line in file.readlines()]
    
    vulnerable = []

    def test_payload(payload):
        test_url = f"{url}{payload}"
        try:
            response = requests.get(test_url)
            if payload in response.text:
                return test_url
        except requests.exceptions.RequestException:
            return None

    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(test_payload, payload) for payload in payloads]
        for future in futures:
            result = future.result()
            if result:
                vulnerable.append(result)
    
    if vulnerable:
        return vulnerable
    else:
        return "No XSS vulnerabilities found."
