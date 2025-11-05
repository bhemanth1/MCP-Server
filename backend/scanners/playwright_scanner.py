"""
Advanced Web Scanner using Playwright
Handles JavaScript-heavy sites, dynamic content, pop-ups, and comprehensive crawling
"""

import os
import json
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse
import asyncio
import re

sys.path.insert(0, os.path.dirname(__file__))

async def playwright_scan(target: str, raw_dir: str) -> dict:
    """Advanced scanning with Playwright - handles pop-ups and crawls all data"""
    from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout
    
    findings = {
        "success": False,
        "error": None,
        "url": target,
        "page_title": "",
        "technologies": [],
        "forms": [],
        "links": [],
        "scripts": [],
        "cookies": [],
        "screenshot_path": "",
        "html_size": 0,
        "js_errors": [],
        "network_requests": [],
        "subdomains_found": [],
        "popups_handled": [],
        "pages_crawled": [],
        "all_urls": []
    }
    
    try:
        # Normalize target URL
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        base_domain = urlparse(target).netloc
        
        async with async_playwright() as p:
            # Launch browser with pop-up handling enabled
            browser = await p.chromium.launch(
                headless=True,
                args=['--disable-blink-features=AutomationControlled']
            )
            
            context = await browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                java_script_enabled=True,
                accept_downloads=True,
                ignore_https_errors=True
            )
            
            # Handle pop-ups and dialogs
            popups_handled = []
            
            def handle_dialog(dialog):
                popups_handled.append({
                    "type": dialog.type,
                    "message": dialog.message,
                    "handled": True
                })
                # Accept all dialogs automatically
                dialog.accept()
            
            context.on("dialog", handle_dialog)
            
            page = await context.new_page()
            
            # Track all URLs visited
            all_urls = set()
            pages_crawled = []
            
            # Track network requests
            requests_made = []
            responses_received = []
            
            async def handle_request(request):
                all_urls.add(request.url)
                requests_made.append({
                    "url": request.url,
                    "method": request.method,
                    "headers": dict(request.headers),
                    "resource_type": request.resource_type
                })
            
            async def handle_response(response):
                all_urls.add(response.url)
                try:
                    responses_received.append({
                        "url": response.url,
                        "status": response.status,
                        "status_text": response.status_text,
                        "headers": dict(response.headers)
                    })
                except:
                    pass
            
            page.on("request", handle_request)
            page.on("response", handle_response)
            
            # Track console errors
            js_errors = []
            
            async def handle_console(msg):
                if msg.type == "error":
                    js_errors.append({
                        "text": msg.text,
                        "location": str(msg.location)
                    })
            
            page.on("console", handle_console)
            
            # Handle page pop-ups and new pages
            async def handle_popup(new_page):
                try:
                    popups_handled.append({
                        "type": "new_page",
                        "url": new_page.url,
                        "handled": True
                    })
                    await new_page.close()
                except:
                    pass
            
            context.on("page", handle_popup)
            
            # Navigate to main page
            try:
                response = await page.goto(target, wait_until="networkidle", timeout=60000)
                findings["success"] = True
                
                # Extract page information
                findings["page_title"] = await page.title()
                page_content = await page.content()
                findings["html_size"] = len(page_content)
                
                # Take screenshot
                screenshot_path = os.path.join(raw_dir, "playwright_screenshot.png")
                await page.screenshot(path=screenshot_path, full_page=True)
                findings["screenshot_path"] = screenshot_path
                
                # Save full HTML
                html_path = os.path.join(raw_dir, "playwright_page.html")
                with open(html_path, 'w', encoding='utf-8') as f:
                    f.write(page_content)
                
                # Extract technologies (from meta tags, scripts, etc.)
                techs = await page.evaluate("""
                    () => {
                        const techs = [];
                        // Check for frameworks
                        if (window.React) techs.push('React');
                        if (window.angular) techs.push('Angular');
                        if (window.Vue) techs.push('Vue');
                        if (window.jQuery) techs.push('jQuery');
                        if (window.Ember) techs.push('Ember');
                        if (window.Backbone) techs.push('Backbone');
                        
                        // Check meta tags
                        document.querySelectorAll('meta[name="generator"]').forEach(m => {
                            techs.push(m.content);
                        });
                        
                        // Check for CMS
                        if (document.querySelector('[data-wp-version]')) techs.push('WordPress');
                        if (document.querySelector('[id*="jquery"]')) techs.push('jQuery');
                        
                        return techs;
                    }
                """)
                findings["technologies"] = techs
                
                # Extract all links and find subdomains
                links_data = await page.evaluate("""
                    () => {
                        const links = [];
                        document.querySelectorAll('a[href]').forEach(a => {
                            links.push({
                                href: a.href,
                                text: a.textContent.trim().substring(0, 200),
                                target: a.target
                            });
                        });
                        return links;
                    }
                """)
                
                # Extract subdomains from all links and URLs
                subdomains_found = set()
                base_domain_clean = base_domain.replace('www.', '').split(':')[0]
                
                for link_data in links_data:
                    try:
                        parsed = urlparse(link_data["href"])
                        if parsed.netloc:
                            domain = parsed.netloc.split(':')[0].replace('www.', '')
                            # Check if it's a subdomain (contains base domain but not equal)
                            if domain != base_domain_clean and domain.endswith('.' + base_domain_clean):
                                subdomains_found.add(domain)
                            elif domain != base_domain_clean and '.' + base_domain_clean in domain:
                                # Also catch cases like sub.domain.com
                                subdomains_found.add(domain)
                    except:
                        pass
                
                # Also check all network requests for subdomains
                for req in requests_made:
                    try:
                        parsed = urlparse(req.get("url", ""))
                        if parsed.netloc:
                            domain = parsed.netloc.split(':')[0].replace('www.', '')
                            if domain != base_domain_clean and domain.endswith('.' + base_domain_clean):
                                subdomains_found.add(domain)
                            elif domain != base_domain_clean and '.' + base_domain_clean in domain:
                                subdomains_found.add(domain)
                    except:
                        pass
                
                # Resolve IPs for subdomains and prepare details
                import socket
                subdomain_details = []
                for sd in list(subdomains_found)[:100]:
                    ip = None
                    try:
                        ip = socket.gethostbyname(sd)
                    except:
                        pass
                    scheme = urlparse(target).scheme or 'https'
                    subdomain_details.append({"subdomain": sd, "ip": ip, "url": f"{scheme}://{sd}"})
                findings["subdomains_found"] = list(subdomains_found)
                findings["subdomain_details"] = subdomain_details
                findings["links"] = links_data[:200]  # Limit to 200
                
                # Extract forms
                forms = await page.evaluate("""
                    () => {
                        const forms = [];
                        document.querySelectorAll('form').forEach(form => {
                            forms.push({
                                action: form.action,
                                method: form.method,
                                inputs: Array.from(form.querySelectorAll('input')).map(i => ({
                                    type: i.type,
                                    name: i.name,
                                    id: i.id,
                                    placeholder: i.placeholder
                                }))
                            });
                        });
                        return forms;
                    }
                """)
                findings["forms"] = forms
                
                # Extract script sources
                scripts = await page.evaluate("""
                    () => {
                        const scripts = [];
                        document.querySelectorAll('script[src]').forEach(s => {
                            scripts.push(s.src);
                        });
                        return scripts;
                    }
                """)
                findings["scripts"] = scripts
                # Basic JS library version parsing and outdated detection
                import re
                KNOWN = {
                    "jquery": "3.7.1",
                    "angular": "1.8.3",
                    "vue": "3.4.0",
                    "react": "18.3.1",
                    "bootstrap": "5.3.3",
                    "lodash": "4.17.21",
                    "moment": "2.30.1",
                    "underscore": "1.13.6",
                    "d3": "7.9.0",
                    "three": "0.169.0"
                }
                def parse_lib(url: str):
                    name = None; ver = None
                    fname = url.split('/')[-1]
                    candidates = [
                        ("jquery", r"jquery[-.](\d+\.\d+\.\d+)"),
                        ("angular", r"angular[-.](\d+\.\d+\.\d+)"),
                        ("vue", r"vue[-.](\d+\.\d+\.\d+)"),
                        ("react", r"react[-.](\d+\.\d+\.\d+)"),
                        ("bootstrap", r"bootstrap[-.](\d+\.\d+\.\d+)"),
                        ("lodash", r"lodash[-.](\d+\.\d+\.\d+)"),
                        ("moment", r"moment[-.](\d+\.\d+\.\d+)"),
                        ("underscore", r"underscore[-.](\d+\.\d+\.\d+)"),
                        ("d3", r"d3[-.](\d+\.\d+\.\d+)"),
                        ("three", r"three[-.](\d+\.\d+)")
                    ]
                    for n, rx in candidates:
                        m = re.search(rx, fname, re.IGNORECASE)
                        if m:
                            name = n; ver = m.group(1); break
                    return name, ver
                def cmp_ver(a, b):
                    try:
                        ap = [int(x) for x in a.split('.')]
                        bp = [int(x) for x in b.split('.')]
                        # pad
                        while len(ap) < len(bp): ap.append(0)
                        while len(bp) < len(ap): bp.append(0)
                        return (ap > bp) - (ap < bp)
                    except:
                        return 0
                js_libs = []
                outdated_js = []
                for s in scripts:
                    n, v = parse_lib(s)
                    if n:
                        latest = KNOWN.get(n)
                        js_libs.append({"name": n, "version": v, "latest": latest, "src": s})
                        if v and latest and cmp_ver(v, latest) < 0:
                            outdated_js.append({
                                "library": n,
                                "version": v,
                                "latest": latest,
                                "severity": "high",
                                "cvss": 7.5
                            })
                findings["js_libraries"] = js_libs
                findings["outdated_js"] = outdated_js
                
                # Extract all iframes (often contain subdomains)
                iframes = await page.evaluate("""
                    () => {
                        const iframes = [];
                        document.querySelectorAll('iframe[src]').forEach(iframe => {
                            iframes.push(iframe.src);
                        });
                        return iframes;
                    }
                """)
                
                # Check iframes for subdomains
                for iframe_src in iframes:
                    try:
                        parsed = urlparse(iframe_src)
                        if parsed.netloc:
                            domain = parsed.netloc.split(':')[0].replace('www.', '')
                            if domain != base_domain_clean and domain.endswith('.' + base_domain_clean):
                                subdomains_found.add(domain)
                            elif domain != base_domain_clean and '.' + base_domain_clean in domain:
                                subdomains_found.add(domain)
                    except:
                        pass
                
                findings["subdomains_found"] = list(subdomains_found)
                
                # Get cookies
                cookies = await context.cookies()
                findings["cookies"] = cookies
                
                # Network requests
                findings["network_requests"] = requests_made[:100]  # Limit to 100
                findings["responses"] = responses_received[:100]
                findings["js_errors"] = js_errors
                findings["popups_handled"] = popups_handled
                findings["all_urls"] = list(all_urls)[:200]
                
                # Try to crawl a few more pages
                pages_to_crawl = links_data[:10]  # Limit to first 10 internal links
                for link in pages_to_crawl:
                    try:
                        parsed = urlparse(link["href"])
                        if parsed.netloc == base_domain or parsed.netloc == '':
                            try:
                                new_page = await context.new_page()
                                await new_page.goto(link["href"], wait_until="networkidle", timeout=10000)
                                pages_crawled.append({
                                    "url": link["href"],
                                    "title": await new_page.title()
                                })
                                await new_page.close()
                            except:
                                pass
                    except:
                        pass
                
                findings["pages_crawled"] = pages_crawled
                
            except Exception as e:
                findings["error"] = f"Playwright navigation error: {str(e)}"
            
            # Include traceroute data
            try:
                from scanners.traceroute import run_and_parse as tr_run
                tr = tr_run(base_domain, raw_dir)
                findings["traceroute"] = {"hops": tr.get("hops", []), "hop_count": tr.get("hop_count", 0)}
            except Exception:
                pass
            await browser.close()
    
    except ImportError:
        findings["error"] = "Playwright not installed. Install: pip install playwright && playwright install"
    except Exception as e:
        findings["error"] = f"Playwright scan error: {str(e)}"
    
    return findings

def run_and_parse(target: str, raw_dir: str) -> dict:
    """Synchronous wrapper for async Playwright scan"""
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(playwright_scan(target, raw_dir))
        loop.close()
        return result
    except Exception as e:
        return {
            "success": False,
            "error": f"Async error: {str(e)}"
        }
