__version__ = "0.3.0"
import argparse
import json
from urllib.request import Request
from common import serve
from security_utils import open_no_redirect, validate_url

HEADERS = {'strict-transport-security':'HSTS','content-security-policy':'CSP','x-content-type-options':'X-Content-Type-Options','x-frame-options':'X-Frame-Options','referrer-policy':'Referrer-Policy','permissions-policy':'Permissions-Policy','cross-origin-opener-policy':'Cross-Origin-Opener-Policy'}

def analyze(values):
    try: parsed=validate_url(values.get('url',''), resolve=True)
    except ValueError as exc: return {'error': str(exc)}
    url = parsed.geturl(); req = Request(url, method='HEAD', headers={'User-Agent':'defensive-header-checker/2.0','Accept':'*/*'})
    try:
        with open_no_redirect(req, timeout=8) as response:
            raw = {k.lower(): v[:2048] for k,v in response.headers.items()}
            present = {label: raw[name] for name,label in HEADERS.items() if name in raw}
            missing = [label for name,label in HEADERS.items() if name not in raw]
            return {'url':url,'status':response.status,'headers_checked':len(HEADERS),'score':round(100*len(present)/len(HEADERS)),'present':present,'missing':missing,'redirects_followed':False,'note':'A missing header is a review signal, not proof of a vulnerability. HEAD is used to avoid downloading page content.'}
    except Exception as exc: return {'error': f'Unable to inspect response headers: {type(exc).__name__}'}

def main():
    parser=argparse.ArgumentParser(description='Inspect common HTTP security headers for one authorized URL.')
    parser.add_argument('url',nargs='?'); parser.add_argument('--web',action='store_true'); parser.add_argument('--port',type=int,default=8080)
    parser.add_argument('--version',action='version',version=__version__)
    args=parser.parse_args()
    if args.web: serve('HTTP Security Headers Checker',[('url','URL','url','https://example.com')],analyze,args.port)
    elif args.url: print(json.dumps(analyze({'url':args.url}),indent=2))
    else: parser.print_help()
if __name__=='__main__': main()
