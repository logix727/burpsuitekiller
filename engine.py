import asyncio
import httpx
from typing import List, Dict, Any
from dataclasses import dataclass
import time

@dataclass
class TestResult:
    url: str
    status_code: int
    duration_ms: float
    reason: str = ""
    error: str = ""
    response_body: str = ""
    response_headers: dict = None
    method: str = "GET"
    request_headers: dict = None
    request_body: str = ""

class AsyncTester:
    def __init__(self, concurrency: int = 10):
        self.concurrency = concurrency
        limits = httpx.Limits(max_keepalive_connections=20, max_connections=concurrency + 5)
        self.client = httpx.AsyncClient(limits=limits, timeout=10.0, follow_redirects=True)

    async def _test_single_url(self, url: str) -> TestResult:
        start = time.perf_counter()
        try:
            response = await self.client.get(url)
            duration = (time.perf_counter() - start) * 1000
            return TestResult(
                url=url,
                status_code=response.status_code,
                reason=response.reason_phrase,
                duration_ms=round(duration, 2),
                response_body=response.text,
                response_headers=dict(response.headers),
                method=response.request.method,
                request_headers=dict(response.request.headers),
                request_body=response.request.content.decode('utf-8', errors='ignore') if response.request.content else ""
            )
        except httpx.RequestError as e:
            duration = (time.perf_counter() - start) * 1000
            return TestResult(
                url=url,
                status_code=0,
                duration_ms=round(duration, 2),
                error=str(e),
                method="GET" # Default/Assumption on error
            )

    async def scan(self, urls: List[str], callback=None) -> List[TestResult]:
        """
        Scans URLs using a fixed-size worker pool (Queue pattern).
        This avoids creating thousands of coroutine objects upfront, reducing memory usage.
        """
        queue = asyncio.Queue()
        for u in urls:
            queue.put_nowait(u)
            
        results = []
        
        async def worker():
            while True:
                try:
                    url = queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                
                try:
                    res = await self._test_single_url(url)
                    results.append(res)
                    if callback:
                        try:
                            callback(res)
                        except Exception:
                            pass # User callback shouldn't kill worker
                except Exception as e:
                    print(f"Worker Error: {e}")
                finally:
                    queue.task_done()
                    # Yield to allow UI updates / event loop breathing
                    await asyncio.sleep(0)

        # Create fixed number of workers
        workers = []
        # Clamp concurrency to avoid excessive overhead if list is small
        num_workers = min(self.concurrency, len(urls))
        for _ in range(num_workers):
            workers.append(asyncio.create_task(worker()))
            
        # Wait for all tasks to be processed
        if workers:
            await asyncio.gather(*workers)
            
        return results

    async def close(self):
        await self.client.aclose()

    async def scan_bola(self, target_url: str, victim_persona: 'Persona', attacker_persona: 'Persona') -> dict:
        """
        Tests BOLA by attempting to access Victim's resource using Attacker's token.
        Assumes target_url contains victim's ID.
        """
        # 1. Baseline: Attacker accessing Attacker's own resource (Authorized) - skipped for speed if not strictly needed, 
        # but could be useful for comparison.
        
        # 2. Attack: Attacker accessing Victim's resource
        # We assume target_url is ALREADY pointing to the victim's resource (e.g. /users/101)
        # We simply swap the Authorization header to be the Attacker's token.
        
        start = time.perf_counter()
        try:
            # Send request with Attacker's credentials but Victim's URL
            response = await self.client.get(target_url, headers=attacker_persona.headers)
            duration = (time.perf_counter() - start) * 1000
            
            # Heuristic for vulnerability:
            # If 200 OK, it MIGHT be vulnerable (unless it's public data)
            # If 403/401, it's likely secure.
            # We should compare with a baseline unauthenticated request to be sure it's not just public.
            
            is_suspicious = response.status_code >= 200 and response.status_code < 300
            
            return {
                "type": "BOLA",
                "url": target_url,
                "attacker": attacker_persona.name,
                "victim_resource_owner": victim_persona.name,
                "status_code": response.status_code,
                "vulnerable": is_suspicious,
                "duration_ms": round(duration, 2),
                "response_len": len(response.content)
            }
        except Exception as e:
            return {"type": "BOLA", "error": str(e)}
