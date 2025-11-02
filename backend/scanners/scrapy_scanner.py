"""
Advanced Web Scraper using Scrapy and XPath
For deep HTML analysis and content extraction
"""

import os
import json
import sys
from urllib.parse import urljoin, urlparse
from scrapy.selector import Selector
import requests

sys.path.insert(0, os.path.dirname(__file__))

def scrapy_xpath_scan(target: str, raw_dir: str) -> dict:
    """Advanced HTML analysis with Scrapy XPath"""
    findings = {
        "success": False,
        "error": None,
        "url": target,
        "title": "",
        "meta_tags": {},
        "headings": {},
        "links": [],
        "forms": [],
        "scripts": [],
        "images": [],
        "tables": [],
        "xpath_findings": []
    }
    
    try:
        # Normalize target URL
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        # Fetch page
        response = requests.get(target, timeout=10, verify=False, allow_redirects=True)
        findings["success"] = True
        
        # Parse with Scrapy Selector
        selector = Selector(text=response.text)
        
        # Extract title
        findings["title"] = selector.xpath('//title/text()').get() or ""
        
        # Extract meta tags
        meta_tags = {}
        for meta in selector.xpath('//meta'):
            name = meta.xpath('./@name').get() or meta.xpath('./@property').get()
            content = meta.xpath('./@content').get()
            if name and content:
                meta_tags[name] = content
        findings["meta_tags"] = meta_tags
        
        # Extract headings
        headings = {}
        for level in range(1, 7):
            h_tags = selector.xpath(f'//h{level}/text()').getall()
            headings[f'h{level}'] = [h.strip() for h in h_tags if h.strip()]
        findings["headings"] = headings
        
        # Extract links with XPath
        links = []
        for link in selector.xpath('//a[@href]')[:50]:
            href = link.xpath('./@href').get()
            text = link.xpath('.//text()').get()
            links.append({
                "href": href,
                "text": (text or "").strip()[:100],
                "external": href.startswith('http') if href else False
            })
        findings["links"] = links
        
        # Extract forms with XPath
        forms = []
        for form in selector.xpath('//form')[:10]:
            forms.append({
                "action": form.xpath('./@action').get(),
                "method": form.xpath('./@method').get(),
                "input_count": len(form.xpath('.//input')),
                "textarea_count": len(form.xpath('.//textarea'))
            })
        findings["forms"] = forms
        
        # Extract scripts
        scripts = selector.xpath('//script[@src]/@src').getall()
        findings["scripts"] = scripts[:20]
        
        # Extract images
        images = []
        for img in selector.xpath('//img[@src]')[:20]:
            images.append({
                "src": img.xpath('./@src').get(),
                "alt": img.xpath('./@alt').get()
            })
        findings["images"] = images
        
        # Extract tables
        tables = []
        for table in selector.xpath('//table')[:5]:
            rows = table.xpath('.//tr')
            tables.append({
                "row_count": len(rows),
                "has_headers": len(table.xpath('.//th')) > 0
            })
        findings["tables"] = tables
        
        # Security-related XPath findings
        xpath_findings = []
        
        # Check for password fields
        password_inputs = selector.xpath('//input[@type="password"]')
        if password_inputs:
            xpath_findings.append({
                "type": "password_field",
                "count": len(password_inputs),
                "severity": "medium"
            })
        
        # Check for hidden inputs
        hidden_inputs = selector.xpath('//input[@type="hidden"]')
        if hidden_inputs:
            xpath_findings.append({
                "type": "hidden_inputs",
                "count": len(hidden_inputs),
                "severity": "low"
            })
        
        # Check for iframes
        iframes = selector.xpath('//iframe')
        if iframes:
            xpath_findings.append({
                "type": "iframes",
                "count": len(iframes),
                "severity": "medium"
            })
        
        findings["xpath_findings"] = xpath_findings
    
    except ImportError:
        findings["error"] = "Scrapy not installed. Install: pip install scrapy"
    except Exception as e:
        findings["error"] = f"Scrapy scan error: {str(e)}"
    
    return findings

def run_and_parse(target: str, raw_dir: str) -> dict:
    return scrapy_xpath_scan(target, raw_dir)

