import random
import logging
import time
import asyncio
from httpx import AsyncClient
from mediaflow_proxy.utils.http_utils import Streamer

results = {}

def run_speedtest(taskid: str):
    results[taskid] = asyncio.run(perform_speed_test()) # Run the speedtest and store the results

def prune_task(taskid: str):
    time.sleep(3600)
    if taskid in results:
        del results[taskid] # Remove task from the results set

async def perform_speed_test():
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
    test_duration = 10 # Duration for each test in seconds

    async with AsyncClient() as client:
        streamer = Streamer(client)

        async def test_single_url(location: str, url: str) -> Dict[str, Any]:
            try:
                start_time = time.time()
                total_bytes = 0
                
                async for chunk in streamer.stream_content(url, headers={}):
                    if time.time() - start_time >= test_duration:
                        break
                    total_bytes += len(chunk)

                duration = time.time() - start_time
                speed_mbps = (total_bytes * 8) / (duration * 1_000_000)
                return {
                    "speed_mbps": round(speed_mbps, 2),
                    "duration": round(duration, 2)
                }
            except Exception as e:
                logging.error(f"Error testing {location}: {e}")
                return {"error": str(e)}

        for location, base_url in test_urls.items():
            random_number = f"{random.uniform(0, 1):.16f}"
            url = f"{base_url}{random_number}"
            logging.info(f"Testing URL: {url}")
            
            speed[location] = await test_single_url(location, url)
            
            # Add rate limiting between tests
            await asyncio.sleep(1)
    return speed