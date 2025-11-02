"""
Advanced Web Scanner using Selenium
For sites requiring full browser automation
"""

import os
import json
import sys
import time
from urllib.parse import urljoin, urlparse

sys.path.insert(0, os.path.dirname(__file__))

def selenium_scan(target: str, raw_dir: str) -> dict:
    """Advanced scanning with Selenium"""
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from webdriver_manager.chrome import ChromeDriverManager
    
    findings = {
        "success": False,
        "error": None,
        "url": target,
        "page_title": "",
        "elements": [],
        "forms": [],
        "buttons": [],
        "inputs": [],
        "images": [],
        "links": [],
        "subdomains_found": [],
        "popups_handled": [],
        "screenshot_path": ""
    }
    
    try:
        # Normalize target URL
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        # Setup Chrome options - non-headless to see pop-ups, but can be made headless
        chrome_options = Options()
        # chrome_options.add_argument('--headless')  # Commented out to see pop-ups
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--window-size=1920,1080')
        chrome_options.add_argument('--disable-blink-features=AutomationControlled')
        chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
        chrome_options.add_experimental_option('useAutomationExtension', False)
        
        # Handle pop-ups - accept all alerts
        prefs = {
            "profile.default_content_setting_values": {
                "notifications": 2  # Block notifications but allow others
            }
        }
        chrome_options.add_experimental_option("prefs", prefs)
        
        # Setup driver
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)
        
        # Handle alerts/pop-ups
        popups_handled = []
        
        try:
            # Navigate to page
            driver.get(target)
            time.sleep(5)  # Wait for dynamic content and pop-ups
            
            # Try to handle any alert that appeared
            try:
                alert = driver.switch_to.alert
                popups_handled.append({
                    "type": "alert",
                    "text": alert.text,
                    "handled": True
                })
                alert.accept()
            except:
                pass  # No alert present
            
            # Wait a bit more for JavaScript to execute
            time.sleep(3)
            
            findings["success"] = True
            findings["page_title"] = driver.title
            
            # Take screenshot
            screenshot_path = os.path.join(raw_dir, "selenium_screenshot.png")
            driver.save_screenshot(screenshot_path)
            findings["screenshot_path"] = screenshot_path
            
            # Extract forms
            forms = driver.find_elements(By.TAG_NAME, "form")
            findings["forms"] = [
                {
                    "action": form.get_attribute("action"),
                    "method": form.get_attribute("method"),
                    "inputs": len(form.find_elements(By.TAG_NAME, "input"))
                }
                for form in forms[:10]
            ]
            
            # Extract buttons
            buttons = driver.find_elements(By.TAG_NAME, "button")
            findings["buttons"] = [
                {
                    "text": btn.text,
                    "type": btn.get_attribute("type"),
                    "id": btn.get_attribute("id")
                }
                for btn in buttons[:20]
            ]
            
            # Extract input fields
            inputs = driver.find_elements(By.TAG_NAME, "input")
            findings["inputs"] = [
                {
                    "type": inp.get_attribute("type"),
                    "name": inp.get_attribute("name"),
                    "id": inp.get_attribute("id")
                }
                for inp in inputs[:30]
            ]
            
            # Extract images
            images = driver.find_elements(By.TAG_NAME, "img")
            findings["images"] = [
                {
                    "src": img.get_attribute("src"),
                    "alt": img.get_attribute("alt")
                }
                for img in images[:20]
            ]
            
            # Extract all links and find subdomains
            links = driver.find_elements(By.TAG_NAME, "a")
            links_data = []
            subdomains_found = set()
            base_domain_clean = urlparse(target).netloc.replace('www.', '').split(':')[0]
            
            for link in links[:200]:  # Limit to 200
                href = link.get_attribute("href")
                if href:
                    links_data.append({
                        "href": href,
                        "text": link.text[:100] if link.text else ""
                    })
                    # Extract subdomain from href
                    try:
                        parsed = urlparse(href)
                        if parsed.netloc:
                            domain = parsed.netloc.split(':')[0].replace('www.', '')
                            if domain != base_domain_clean and domain.endswith('.' + base_domain_clean):
                                subdomains_found.add(domain)
                            elif domain != base_domain_clean and '.' + base_domain_clean in domain:
                                subdomains_found.add(domain)
                    except:
                        pass
            
            # Also check iframes for subdomains
            iframes = driver.find_elements(By.TAG_NAME, "iframe")
            for iframe in iframes[:20]:
                src = iframe.get_attribute("src")
                if src:
                    try:
                        parsed = urlparse(src)
                        if parsed.netloc:
                            domain = parsed.netloc.split(':')[0].replace('www.', '')
                            if domain != base_domain_clean and domain.endswith('.' + base_domain_clean):
                                subdomains_found.add(domain)
                            elif domain != base_domain_clean and '.' + base_domain_clean in domain:
                                subdomains_found.add(domain)
                    except:
                        pass
            
            findings["links"] = links_data
            findings["subdomains_found"] = list(subdomains_found)
            findings["popups_handled"] = popups_handled
            
        except Exception as e:
            findings["error"] = f"Selenium navigation error: {str(e)}"
        finally:
            driver.quit()
    
    except ImportError:
        findings["error"] = "Selenium not installed. Install: pip install selenium webdriver-manager"
    except Exception as e:
        findings["error"] = f"Selenium scan error: {str(e)}"
    
    return findings

def run_and_parse(target: str, raw_dir: str) -> dict:
    return selenium_scan(target, raw_dir)

