"""Detection Engine CPU Latency Benchmark.

Measures p50, p95, and worst-case (pathological input) latency across typical message lengths.
"""

from pathlib import Path
import statistics
import sys
import time
from typing import List
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.detection.engine import ThreatDetectionEngine
from app.detection.taxonomy_loader import load_taxonomy_from_directory


def percentile(data: List[float], p: float) -> float:
    k = (len(data) - 1) * p
    f = int(k)
    c = f + 1 if f + 1 < len(data) else f
    d0 = data[f] * (c - k)
    d1 = data[c] * (k - f)
    return d0 + d1


def run_benchmark():
    tax_dir = Path("backend/rules/taxonomy")
    if not tax_dir.exists():
        tax_dir = Path("rules/taxonomy")

    _, rules = load_taxonomy_from_directory(tax_dir)
    engine = ThreatDetectionEngine(rules)
    tenant_id = uuid.uuid4()

    short_msg = "Sir aapka KYC expire ho gaya, link par click karke update karo"
    medium_msg = (
        "Dear Customer, your electricity power supply will be disconnected tonight at 10 PM "
        "due to previous unpaid bill. Please call our officer at 9876543210 immediately or "
        "download our support app from hxxps://electricity-portal[.]xyz/pay to avoid blackout."
    )
    long_msg = (
        "Special Investment Announcement: Join our VIP crypto futures trading group today! "
        "Guaranteed 300% weekly return on USDT deposits. Transfer 500 USDT to our verified wallet "
        "or send via UPI to trading.vip@okhdfcbank. After transfer send screenshot and your 6-digit OTP "
        "to @crypto_admin on Telegram. Beware of fake accounts. All transactions are protected by "
        "police FIR insurance. Contact national cybercrime helpline 1930 for any inquiries. "
    ) * 3
    pathological_msg = "a" * 4090 + "!"

    cases = [
        ("Short (~50 chars)", short_msg, 1000),
        ("Medium (~250 chars)", medium_msg, 1000),
        ("Long (~1,000 chars)", long_msg, 500),
        ("Pathological Worst-Case (4,091 chars)", pathological_msg, 200),
    ]

    print("=================================================================")
    print("DETECTION ENGINE CPU LATENCY BENCHMARK")
    print("=================================================================")

    results = {}
    for label, payload, iters in cases:
        latencies_ms: List[float] = []
        for i in range(iters):
            t0 = time.perf_counter()
            engine.analyze_message(payload, tenant_id=tenant_id, message_id=f"bench_{i}")
            t1 = time.perf_counter()
            latencies_ms.append((t1 - t0) * 1000.0)

        latencies_ms.sort()
        p50 = percentile(latencies_ms, 0.50)
        p95 = percentile(latencies_ms, 0.95)
        p99 = percentile(latencies_ms, 0.99)
        max_lat = max(latencies_ms)
        mean_lat = statistics.mean(latencies_ms)
        throughput = 1000.0 / mean_lat if mean_lat > 0 else 0.0

        results[label] = {
            "p50": round(p50, 3),
            "p95": round(p95, 3),
            "p99": round(p99, 3),
            "max": round(max_lat, 3),
            "throughput_msg_per_sec": round(throughput, 1),
        }
        print(f"Profile: {label:<38} | p50: {p50:6.3f} ms | p95: {p95:6.3f} ms | max: {max_lat:6.3f} ms | {throughput:6.1f} msg/sec")

    return results


if __name__ == "__main__":
    run_benchmark()
