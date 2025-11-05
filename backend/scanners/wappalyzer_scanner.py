import os
import re
import json
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup

requests.packages.urllib3.disable_warnings()

SIGNATURES = {
    # name: { 'category': '...', 'headers': {key: regex}, 'html': regex|[regex], 'scriptSrc': regex, 'jsvar': regex, 'latest': 'x.y.z' }
    'WordPress': {
        'category': 'CMS',
        'meta': {'generator': r'WordPress\s*(?:([0-9.]+))?'},
        'headers': {'x-powered-by': r'WordPress'},
        'html': r'wp-content|wp-includes',
        'latest': '6.6.2'
    },
    'jQuery': {
        'category': 'JavaScript Library',
        'scriptSrc': r'jquery[-.]([0-9.]+)\.js',
        'latest': '3.7.1'
    },
    'jQuery UI': {
        'category': 'JavaScript Library',
        'scriptSrc': r'jquery-ui[-.]([0-9.]+)\.js',
        'latest': '1.13.3'
    },
    'Bootstrap': {
        'category': 'CSS Framework',
        'scriptSrc': r'bootstrap[-.]([0-9.]+)\.js',
        'html': r'bootstrap(?:\.min)?\.css',
        'latest': '5.3.3'
    },
    'React': {
        'category': 'JavaScript Framework',
        'scriptSrc': r'react[-.]([0-9.]+)\.js',
        'latest': '18.3.1'
    },
    'AngularJS': {
        'category': 'JavaScript Framework',
        'scriptSrc': r'angular[-.]([0-9.]+)\.js',
        'latest': '1.8.3'
    },
    'Vue.js': {
        'category': 'JavaScript Framework',
        'scriptSrc': r'vue[-.]([0-9.]+)\.js',
        'latest': '3.4.0'
    },
    'Apache': {
        'category': 'Web Server',
        'headers': {'server': r'Apache(?:/([0-9.]+))?'},
        'latest': None
    },
    'nginx': {
        'category': 'Web Server',
        'headers': {'server': r'nginx(?:/([0-9.]+))?'},
        'latest': None
    },
    'LiteSpeed': {
        'category': 'Web Server',
        'headers': {'server': r'LiteSpeed(?:/([0-9.]+))?'},
        'latest': None
    },
    'Drupal': {
        'category': 'CMS',
        'meta': {'generator': r'Drupal\s*([0-9.]+)?'},
        'latest': '10.3.0'
    },
    'Joomla': {
        'category': 'CMS',
        'meta': {'generator': r'Joomla!\s*-?\s*([0-9.]+)?'},
        'latest': '5.1.1'
    },
    'PHP': {
        'category': 'Programming Language',
        'headers': {'x-powered-by': r'PHP/?([0-9.]+)?'},
        'latest': None
    },
    'ASP.NET': {
        'category': 'Framework',
        'headers': {'x-aspnet-version': r'([0-9.]+)?', 'x-powered-by': r'ASP.NET'},
        'latest': None
    },
    'Express': {
        'category': 'Web Framework',
        'headers': {'x-powered-by': r'Express'},
        'latest': None
    },
    'Django': {
        'category': 'Web Framework',
        'headers': {'set-cookie': r'csrftoken='},
        'latest': None
    },
    'Laravel': {
        'category': 'Web Framework',
        'headers': {'set-cookie': r'laravel_session='},
        'latest': None
    },
    'Google Analytics': {
        'category': 'Analytics',
        'html': r'www\.googletagmanager\.com|www\.google-analytics\.com',
        'scriptSrc': r'gtag/js|analytics\.js',
        'latest': None
    },
    'Cloudflare': {
        'category': 'CDN',
        'headers': {'server': r'cloudflare', 'cf-ray': r'.+', 'cf-cache-status': r'.+'},
        'latest': None
    },
    'Akamai': {
        'category': 'CDN',
        'headers': {'server': r'AkamaiGHost', 'x-akamai-transformed': r'.+'},
        'latest': None
    },
    'Fastly': {
        'category': 'CDN',
        'headers': {'x-served-by': r'.*fastly.*'},
        'latest': None
    },
    'CloudFront': {
        'category': 'CDN',
        'headers': {'via': r'cloudfront', 'x-amz-cf-pop': r'.+'},
        'latest': None
    },
}


def _cmp_ver(a: str|None, b: str|None) -> int:
    if not a or not b:
        return 0
    try:
        ap = [int(x) for x in a.split('.')]
        bp = [int(x) for x in b.split('.')]
        while len(ap) < len(bp): ap.append(0)
        while len(bp) < len(ap): bp.append(0)
        return (ap > bp) - (ap < bp)
    except Exception:
        return 0


def run_and_parse(target: str, raw_dir: str) -> dict:
    if not target.startswith(('http://', 'https://')):
        target = f'https://{target}'
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"

    findings = {
        'success': False,
        'error': None,
        'url': base,
        'technologies': [],
        'count': 0,
        'categories_summary': {},
        'security_headers_present': [],
        'security_headers_missing': [],
        'cdn': None,
        'server': None
    }

    try:
        resp = requests.get(base, timeout=10, verify=False, allow_redirects=True)
    except Exception as e:
        findings['error'] = str(e)
        return findings

    headers = {k.lower(): v for k, v in resp.headers.items()}
    html = resp.text or ''
    soup = BeautifulSoup(html, 'html.parser')
    metas = {m.get('name','').lower(): m.get('content','') for m in soup.find_all('meta') if m.get('name')}
    scripts = [s.get('src') for s in soup.find_all('script') if s.get('src')]

    technologies = []
    for name, sig in SIGNATURES.items():
        version = None
        confidence = 0
        matched = False

        # headers
        for hk, rx in sig.get('headers', {}).items():
            val = headers.get(hk)
            if val:
                m = re.search(rx, val, re.I)
                if m:
                    matched = True
                    confidence += 40
                    if m.lastindex:
                        version = version or m.group(1)

        # meta generator
        for mk, rx in sig.get('meta', {}).items():
            val = metas.get(mk)
            if val:
                m = re.search(rx, val, re.I)
                if m:
                    matched = True
                    confidence += 40
                    if m.lastindex:
                        version = version or (m.group(1) if m.group(1) else None)

        # html regex
        htmlex = sig.get('html')
        if htmlex:
            if re.search(htmlex, html, re.I):
                matched = True
                confidence += 20

        # script src
        srx = sig.get('scriptSrc')
        if srx:
            for src in scripts:
                if not src:
                    continue
                m = re.search(srx, src, re.I)
                if m:
                    matched = True
                    confidence += 50
                    if m.lastindex:
                        version = version or m.group(1)
                    break

        if matched:
            latest = sig.get('latest')
            outdated = False
            severity = None
            cvss = None
            if latest and version:
                outdated = _cmp_ver(version, latest) < 0
                if outdated:
                    severity = 'high'
                    cvss = 7.5
            technologies.append({
                'name': name,
                'category': sig.get('category'),
                'version': version,
                'latest': latest,
                'outdated': outdated,
                'severity': severity,
                'cvss': cvss,
                'confidence': min(confidence, 100)
            })

    # Summaries and extras
    findings['technologies'] = technologies
    findings['count'] = len(technologies)
    # Categories summary
    cats = {}
    for t in technologies:
        c = t.get('category') or 'Other'
        cats[c] = cats.get(c, 0) + 1
        if t.get('category') == 'CDN' and not findings['cdn']:
            findings['cdn'] = t.get('name')
        if t.get('category') == 'Web Server' and not findings['server']:
            findings['server'] = f"{t.get('name')} {t.get('version') or ''}".strip()
    findings['categories_summary'] = cats

    # Security headers presence/missing
    must_headers = [
        'strict-transport-security',
        'content-security-policy',
        'x-frame-options',
        'x-content-type-options',
        'referrer-policy'
    ]
    present = []
    missing = []
    for h in must_headers:
        if any(k.startswith(h) for k in headers.keys()):
            present.append(h)
        else:
            missing.append(h)
    findings['security_headers_present'] = present
    findings['security_headers_missing'] = missing
    findings['success'] = True
    # Save raw for debugging
    try:
        with open(os.path.join(raw_dir, 'wappalyzer_headers.json'), 'w', encoding='utf-8') as f:
            json.dump(headers, f, indent=2)
    except Exception:
        pass
    return findings
