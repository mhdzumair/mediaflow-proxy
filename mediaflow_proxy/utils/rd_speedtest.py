import requests
import time
import random
import logging

logging.basicConfig(level=logging.INFO)

results={}

def run_speedtest(taskid :str):
    results[taskid] = perform_speed_test() # Run the speedtest and store the results

def prune_task(taskid :str):
    time.sleep(3600)
    if taskid in results:
        del results[taskid] # Remove task from the results set


def perform_speed_test():
    test_urls = {
        "AMS": "https://45.download.real-debrid.com/speedtest/testDefault.rar/",
        "RBX": "https://rbx.download.real-debrid.com/speedtest/test.rar/",
        "LON1": "https://lon1.download.real-debrid.com/speedtest/test.rar/",
        "HKG1": "https://hkg1.download.real-debrid.com/speedtest/test.rar/",
        "SGP1": "https://sgp1.download.real-debrid.com/speedtest/test.rar/",
        "SGPO1": "https://sgpo1.download.real-debrid.com/speedtest/test.rar/",
        "TYO1": "https://tyo1.download.real-debrid.com/speedtest/test.rar/",
        "LAX1": "https://lax1.download.real-debrid.com/speedtest/test.rar/",
        "TLV1": "https://tlv1.download.real-debrid.com/speedtest/test.rar/",
        "MUM1": "https://mum1.download.real-debrid.com/speedtest/test.rar/",
        "JKT1": "https://jkt1.download.real-debrid.com/speedtest/test.rar/",
        "Cloudflare": "https://45.download.real-debrid.cloud/speedtest/testCloudflare.rar/"
    }
    
    speed = {}
    test_duration = 10  # Duration for each test in seconds

    for location, base_url in test_urls.items():
        # Generate a random float with 16 decimal places
        random_number = f"{random.uniform(0, 1):.16f}"
        url = f"{base_url}{random_number}"

        logging.info(f"Testing URL: {url}")

        start_time = time.time()
        total_bytes = 0
        
        try:
            # Stream the response
            with requests.get(url, stream=True, timeout=10) as response:
                response.raise_for_status()
                while time.time() - start_time < test_duration:
                    chunk = response.raw.read(8192)  # Read in chunks
                    if not chunk:  # Stop if no more data
                        break
                    total_bytes += len(chunk)

            duration = time.time() - start_time
            speed_mbps = (total_bytes * 8) / (duration * 1_000_000)
            speed[location] = {
                "speed_mbps": round(speed_mbps, 2),
                "duration": round(duration, 2)
            }
            logging.info(f"Speed for {location}: {speed_mbps} Mbps in {duration} seconds")
        except requests.RequestException as e:
            speed[location] = {"error": str(e)}
            logging.error(f"Error for {location}: {e}")

    return speed