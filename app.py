import argparse
import json
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from common import serve

HEADERS = {
    'strict-transport-security': 'HSTS',
    'content-security-policy': 'CSP',
    'x-content-type-options': 'X-Content-Type-Options',
    'x-frame-options': 'X-Frame-Options',
    'referrer-policy': 'Referrer-Policy',
    'permissions-policy': 'Permissions-Policy',
    'cross-origin-opener-policy': 'Cross-Origin-Opener-Policy',
}

def analyze(values):
    url = values.get('url', '').strip()
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https') or not parsed.netloc:
        return {'error': 'Enter one absolute http:// or https:// URL.'}
    req = Request(url, headers={'User-Agent': 'defensive-header-checker/1.0'})
    with urlopen(req, timeout=8) as response:
        raw = {k.lower(): v for k, v in response.headers.items()}
        present = {label: raw[name] for name, label in HEADERS.items() if name in raw}
        missing = [label for name, label in HEADERS.items() if name not in raw]
        score = round(100 * len(present) / len(HEADERS))
        return {'url': url, 'status': response.status, 'score': score, 'present': present, 'missing': missing, 'note': 'A missing header is a review signal, not proof of a vulnerability.'}

def main():
    parser = argparse.ArgumentParser(description='Inspect common HTTP security headers for one authorized URL.')
    parser.add_argument('url', nargs='?'); parser.add_argument('--web', action='store_true'); parser.add_argument('--port', type=int, default=8080)
    args = parser.parse_args()
    if args.web: serve('HTTP Security Headers Checker', [('url','URL','url','https://example.com')], analyze, args.port)
    elif args.url: print(json.dumps(analyze({'url': args.url}), indent=2))
    else: parser.print_help()

if __name__ == '__main__': main()
