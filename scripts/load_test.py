"""Pre-release load test: 20 concurrent workers, 500 POST requests."""
import argparse
import os
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

DEFAULT_URL = 'http://127.0.0.1:5000/'
TEST_SITE = 'https://example.com'


def run_one(session, base_url, site_url, timeout):
    started = time.perf_counter()
    try:
        response = session.post(
            base_url,
            data={'url': site_url},
            timeout=timeout,
            allow_redirects=True,
        )
        elapsed_ms = (time.perf_counter() - started) * 1000
        return {
            'status': response.status_code,
            'elapsed_ms': elapsed_ms,
            'ok': response.status_code == 200,
            'error': None,
        }
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - started) * 1000
        return {
            'status': 0,
            'elapsed_ms': elapsed_ms,
            'ok': False,
            'error': str(exc),
        }


def fetch_cache_stats(base_url, admin_token=None):
    headers = {}
    if admin_token:
        headers['X-Admin-Token'] = admin_token
    try:
        response = requests.get(
            base_url.rstrip('/') + '/api/stats',
            headers=headers,
            timeout=15,
        )
        if response.status_code == 200:
            cache = response.json().get('cache')
            if cache:
                return cache
    except requests.RequestException:
        pass
    return None


def main():
    parser = argparse.ArgumentParser(description='Sonic Boom load test')
    parser.add_argument('--base-url', default=DEFAULT_URL)
    parser.add_argument('--site', default=TEST_SITE)
    parser.add_argument('--requests', type=int, default=500)
    parser.add_argument('--workers', type=int, default=20)
    parser.add_argument('--timeout', type=int, default=120)
    parser.add_argument('--admin-token', default=os.environ.get('STATS_ADMIN_TOKEN', ''))
    args = parser.parse_args()

    print(f"Target: {args.base_url} | site: {args.site}")
    print(f"Requests: {args.requests} | workers: {args.workers}")

    cache_before = fetch_cache_stats(args.base_url, args.admin_token or None)

    results = []
    started = time.perf_counter()

    with requests.Session() as session:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = [
                pool.submit(run_one, session, args.base_url, args.site, args.timeout)
                for _ in range(args.requests)
            ]
            for future in as_completed(futures):
                results.append(future.result())

    total_s = time.perf_counter() - started
    cache_after = fetch_cache_stats(args.base_url, args.admin_token or None)

    ok = [r for r in results if r['ok']]
    errors = [r for r in results if not r['ok']]
    status_500 = sum(1 for r in results if r['status'] == 500)
    latencies = [r['elapsed_ms'] for r in ok]

    print('\n--- Results ---')
    print(f"Total time: {total_s:.1f}s")
    print(f"Success: {len(ok)}/{len(results)} ({len(ok)/len(results)*100:.1f}%)")
    print(f"HTTP 500: {status_500}")
    print(f"Other failures: {len(errors) - status_500}")
    if latencies:
        print(f"Latency p50: {statistics.median(latencies):.0f} ms")
        print(f"Latency p95: {sorted(latencies)[int(len(latencies)*0.95)-1]:.0f} ms")
        print(f"Latency max: {max(latencies):.0f} ms")
    if errors[:3]:
        print('Sample errors:', errors[:3])

    print('\n--- Cache ---')
    if cache_after:
        print(f"Hit rate: {cache_after.get('hit_rate', 0)}%")
        print(f"Hits: {cache_after.get('hits', 0)} | Misses: {cache_after.get('misses', 0)}")
        print(f"Evictions: {cache_after.get('evictions', 0)} | Entries: {cache_after.get('entries', 0)}")
        if cache_before:
            print(f"Hit rate before: {cache_before.get('hit_rate', 0)}%")
    else:
        print('Cache stats unavailable (use localhost or set STATS_ADMIN_TOKEN)')


if __name__ == '__main__':
    main()
