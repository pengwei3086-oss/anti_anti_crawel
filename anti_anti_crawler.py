#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
反反爬综合工具 - 纯反爬模块
=============================
从 llm_search_arch 中提取的反爬相关代码，用于进行网站访问。

功能：
1. 多策略请求（httpx + crawl4ai JS渲染 + Playwright + Selenium）
2. 智能 User-Agent 轮换
3. 代理支持（SOCKS5/HTTP）
4. 安全验证检测（Cloudflare/Akamai/WAF/CAPTCHA）
5. 自动绕过策略（等待验证通过、刷新、降级提取）
6. 翻页功能（按钮点击 + URL参数修改）
7. 请求延迟与重试
8. 浏览器指纹隐藏（Selenium/Playwright）
9. 调试页面保存

用法：
    python anti_anti_crawler.py <url> [options]

示例：
    python anti_anti_crawler.py https://example.com
    python anti_anti_crawler.py https://example.com --proxy socks5://127.0.0.1:1080
    python anti_anti_crawler.py https://example.com --strategy playwright
    python anti_anti_crawler.py https://example.com --save-debug
"""

import asyncio
import json
import logging
import os
import random
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any, Union
from urllib.parse import urlparse, parse_qs

# ============================================================
# 配置
# ============================================================

# User-Agent 池 - 模拟不同浏览器
USER_AGENTS = [
    # Chrome 120 Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Chrome 120 macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Chrome 120 Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Firefox 121 Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    # Firefox 121 macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    # Edge 120 Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    # Safari 17 macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
]

# 默认请求头
DEFAULT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}

# 安全验证检测关键词
SECURITY_INDICATORS = {
    "cloudflare": {
        "title": ["just a moment", "please wait", "验证", "安全检查",
                  "attention required", "challenge", "verify"],
        "source": ["cloudflare", "cf-challenge", "cf-browser-verification",
                  "challenge-platform", "turnstile", "cf-turnstile",
                  "checking your browser", "检查浏览器", "验证中"],
        "url": ["cloudflare"]
    },
    "akamai": {
        "title": ["akamai", "access denied"],
        "source": ["akamai", "akamaized", "edgekey"]
    },
    "incapsula": {
        "title": ["incapsula", "security check"],
        "source": ["incapsula", "incapsula-resource"]
    },
    "sucuri": {
        "title": ["sucuri", "website firewall"],
        "source": ["sucuri", "cloudproxy"]
    },
    "generic_waf": {
        "title": ["access denied", "forbidden", "blocked", "拒绝访问", "禁止访问"],
        "source": ["waf", "web application firewall", "security check"]
    },
    "captcha": {
        "title": ["captcha", "recaptcha", "人机验证", "验证码"],
        "source": ["recaptcha", "hcaptcha", "geetest", "极验"]
    }
}

# 翻页参数名
PAGE_PARAM_NAMES = [
    'page', 'p', 'pageNum', 'pagenum', 'Page',
    'start', 'offset', 'pg', 'pageNo', 'pageno',
    'page_number', 'page-number', 'pageIndex',
    'currentPage', 'current-page', 'current_page',
    'page_id', 'pageid', 'PageNo',
    'from', 'skip', 'begin', 'index', 'no',
    'PageIndex', 'pageindex',
]

# 翻页路径模式
PAGE_PATH_PATTERNS = [
    (r'/page/(\d+)', '/page/'),
    (r'/p/(\d+)', '/p/'),
    (r'/pg/(\d+)', '/pg/'),
    (r'/list/(\d+)', '/list/'),
    (r'/index_(\d+)', '/index_'),
]


# ============================================================
# 枚举与数据类
# ============================================================

class FetchStrategy(Enum):
    """抓取策略"""
    HTTPX = "httpx"                    # 直接HTTP请求
    CRAWL4AI = "crawl4ai"              # crawl4ai JS渲染
    PLAYWRIGHT = "playwright"          # Playwright浏览器
    SELENIUM = "selenium"              # Selenium浏览器


class SecurityChallenge(Enum):
    """安全验证类型"""
    NONE = "none"
    CLOUDFLARE = "cloudflare"
    AKAMAI = "akamai"
    INCAPSULA = "incapsula"
    SUCURI = "sucuri"
    GENERIC_WAF = "generic_waf"
    CAPTCHA = "captcha"
    UNKNOWN = "unknown"


class ErrorCategory(Enum):
    """错误分类"""
    NONE = "none"
    NETWORK = "network"
    SSL = "ssl"
    TIMEOUT = "timeout"
    SECURITY_CHALLENGE = "security_challenge"
    INVALID_RESPONSE = "invalid_response"
    UNKNOWN = "unknown"


@dataclass
class FetchResult:
    """抓取结果"""
    url: str
    html: str = ""
    status_code: int = 0
    final_url: str = ""
    strategy: Optional[FetchStrategy] = None
    success: bool = False
    error_category: ErrorCategory = ErrorCategory.NONE
    error_detail: str = ""
    response_time_ms: int = 0
    security_challenge: Optional[SecurityChallenge] = None
    retry_count: int = 0
    headers_used: Dict = field(default_factory=dict)


# ============================================================
# 日志配置
# ============================================================

def setup_logger(name: str = "anti_crawler", log_file: Optional[str] = None,
                 level: int = logging.INFO) -> logging.Logger:
    """配置日志器"""
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.handlers.clear()

    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)s %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # 控制台
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    logger.addHandler(console)

    # 文件
    if log_file:
        os.makedirs(os.path.dirname(log_file) if os.path.dirname(log_file) else ".", exist_ok=True)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    return logger


logger = setup_logger("anti_crawler")


# ============================================================
# User-Agent 管理器
# ============================================================

class UserAgentManager:
    """User-Agent 管理器 - 支持轮换和随机选择"""

    def __init__(self, ua_list: Optional[List[str]] = None):
        self.agents = ua_list or USER_AGENTS
        self._index = 0

    def random(self) -> str:
        """随机选择一个 UA"""
        return random.choice(self.agents)

    def next(self) -> str:
        """轮换到下一个 UA"""
        ua = self.agents[self._index % len(self.agents)]
        self._index += 1
        return ua

    def add(self, ua: str):
        """添加自定义 UA"""
        if ua not in self.agents:
            self.agents.append(ua)


# ============================================================
# 安全验证检测器
# ============================================================

class SecurityDetector:
    """安全验证检测器 - 检测 Cloudflare/Akamai/CAPTCHA 等"""

    @staticmethod
    def detect(page_title: str, page_source: str, current_url: str) -> Tuple[bool, SecurityChallenge, Dict]:
        """
        检测页面是否被安全验证拦截

        Returns:
            (是否检测到, 验证类型, 详细信息)
        """
        result = {"detected": False, "type": SecurityChallenge.NONE, "details": {}}
        title_lower = page_title.lower() if page_title else ""
        source_lower = page_source.lower() if page_source else ""
        url_lower = current_url.lower() if current_url else ""

        for challenge_type, indicators in SECURITY_INDICATORS.items():
            # 检查标题
            for keyword in indicators.get("title", []):
                if keyword in title_lower:
                    return True, SecurityChallenge(challenge_type), {
                        "matched": "title", "keyword": keyword
                    }

            # 检查页面源码
            for keyword in indicators.get("source", []):
                if keyword in source_lower:
                    return True, SecurityChallenge(challenge_type), {
                        "matched": "source", "keyword": keyword
                    }

            # 检查URL
            for keyword in indicators.get("url", []):
                if keyword in url_lower:
                    return True, SecurityChallenge(challenge_type), {
                        "matched": "url", "keyword": keyword
                    }

        # 通用验证关键词
        generic_keywords = ["verify", "verification", "challenge", "captcha",
                           "human verification", "are you human", "确认你是人类",
                           "安全验证", "人机验证", "验证码"]
        for keyword in generic_keywords:
            if keyword in title_lower or keyword in source_lower[:5000]:
                return True, SecurityChallenge.CAPTCHA, {
                    "matched": "generic", "keyword": keyword
                }

        return False, SecurityChallenge.NONE, {}


# ============================================================
# 请求执行器
# ============================================================

class RequestExecutor:
    """
    请求执行器 - 支持多策略抓取
    策略优先级: httpx -> crawl4ai -> playwright -> selenium
    """

    def __init__(
        self,
        proxy: Optional[str] = None,
        timeout: int = 30,
        max_retries: int = 3,
        retry_delay: float = 2.0,
        enable_js_fallback: bool = True,
        enable_browser_fallback: bool = True,
        save_debug_pages: bool = False,
        debug_dir: str = "debug_pages",
        ua_manager: Optional[UserAgentManager] = None,
    ):
        self.proxy = proxy
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.enable_js_fallback = enable_js_fallback
        self.enable_browser_fallback = enable_browser_fallback
        self.save_debug_pages = save_debug_pages
        self.debug_dir = debug_dir
        self.ua_manager = ua_manager or UserAgentManager()

        if save_debug_pages:
            os.makedirs(debug_dir, exist_ok=True)

    async def fetch(
        self,
        url: str,
        preferred_strategy: Optional[FetchStrategy] = None,
        custom_headers: Optional[Dict] = None,
    ) -> FetchResult:
        """
        抓取URL内容 - 自动选择最佳策略

        Args:
            url: 目标URL
            preferred_strategy: 首选策略
            custom_headers: 自定义请求头

        Returns:
            FetchResult
        """
        result = FetchResult(url=url)

        strategies = []
        if preferred_strategy:
            strategies.append(preferred_strategy)

        strategies.extend([
            FetchStrategy.HTTPX,
            FetchStrategy.CRAWL4AI,
            FetchStrategy.PLAYWRIGHT,
            FetchStrategy.SELENIUM,
        ])

        for strategy in strategies:
            if strategy == FetchStrategy.HTTPX:
                result = await self._fetch_with_httpx(url, custom_headers)
            elif strategy == FetchStrategy.CRAWL4AI:
                if not self.enable_js_fallback:
                    continue
                result = await self._fetch_with_crawl4ai(url)
            elif strategy == FetchStrategy.PLAYWRIGHT:
                if not self.enable_browser_fallback:
                    continue
                result = await self._fetch_with_playwright(url)
            elif strategy == FetchStrategy.SELENIUM:
                if not self.enable_browser_fallback:
                    continue
                result = await self._fetch_with_selenium(url)

            if result.success:
                # 保存调试页面
                if self.save_debug_pages:
                    self._save_debug_page(result)
                return result

            # 如果检测到安全验证，尝试绕过
            if result.security_challenge and result.security_challenge != SecurityChallenge.NONE:
                logger.info(f"检测到安全验证: {result.security_challenge.value}，尝试绕过...")
                bypassed = await self._bypass_security(url, result.security_challenge)
                if bypassed:
                    result = await self._fetch_with_httpx(url, custom_headers)
                    if result.success:
                        return result

        return result

    async def _fetch_with_httpx(self, url: str,
                                 custom_headers: Optional[Dict] = None) -> FetchResult:
        """使用 httpx 直接请求"""
        result = FetchResult(url=url, strategy=FetchStrategy.HTTPX)

        try:
            import httpx

            headers = DEFAULT_HEADERS.copy()
            headers["User-Agent"] = self.ua_manager.random()
            if custom_headers:
                headers.update(custom_headers)

            client_kwargs = {
                "timeout": self.timeout,
                "follow_redirects": True,
                "headers": headers,
                "verify": True,
            }

            if self.proxy:
                client_kwargs["proxy"] = self.proxy

            for attempt in range(self.max_retries + 1):
                try:
                    start_time = time.time()
                    async with httpx.AsyncClient(**client_kwargs) as client:
                        response = await client.get(url)

                    result.response_time_ms = int((time.time() - start_time) * 1000)
                    result.status_code = response.status_code
                    result.final_url = str(response.url)
                    result.headers_used = dict(response.headers)

                    html = response.text
                    result.html = html

                    # 检测安全验证
                    title = ""
                    title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.DOTALL | re.IGNORECASE)
                    if title_match:
                        title = title_match.group(1)

                    detected, challenge_type, details = SecurityDetector.detect(
                        title, html, str(response.url)
                    )

                    if detected:
                        result.security_challenge = challenge_type
                        result.error_category = ErrorCategory.SECURITY_CHALLENGE
                        result.error_detail = f"安全验证: {challenge_type.value}"
                        logger.warning(f"检测到安全验证 [{challenge_type.value}]: {url[:80]}...")
                        return result

                    if response.status_code >= 400:
                        result.error_category = ErrorCategory.INVALID_RESPONSE
                        result.error_detail = f"HTTP {response.status_code}"
                        if attempt < self.max_retries:
                            await asyncio.sleep(self.retry_delay)
                            continue
                        # 最后一次尝试失败，返回当前结果
                        return result

                    if not html or len(html) < 100:
                        result.error_category = ErrorCategory.INVALID_RESPONSE
                        result.error_detail = f"HTML太短 ({len(html) if html else 0} chars)"
                        if attempt < self.max_retries:
                            await asyncio.sleep(self.retry_delay)
                            continue
                        # 最后一次尝试失败，返回当前结果
                        return result

                    result.success = True
                    result.retry_count = attempt
                    return result

                except httpx.TimeoutException:
                    result.error_category = ErrorCategory.TIMEOUT
                    result.error_detail = "请求超时"
                    if attempt < self.max_retries:
                        wait = self.retry_delay * (attempt + 1)
                        logger.warning(f"超时，{wait}秒后重试 ({attempt+1}/{self.max_retries})")
                        await asyncio.sleep(wait)
                        # 更换UA
                        headers["User-Agent"] = self.ua_manager.random()
                    continue

                except httpx.ConnectError as e:
                    result.error_category = ErrorCategory.NETWORK
                    result.error_detail = f"连接错误: {e}"
                    if attempt < self.max_retries:
                        await asyncio.sleep(self.retry_delay)
                    continue

                except Exception as e:
                    result.error_category = ErrorCategory.UNKNOWN
                    result.error_detail = str(e)
                    if attempt < self.max_retries:
                        await asyncio.sleep(self.retry_delay)
                    continue

        except ImportError:
            result.error_category = ErrorCategory.UNKNOWN
            result.error_detail = "httpx 未安装 (pip install httpx)"

        return result

    async def _fetch_with_crawl4ai(self, url: str) -> FetchResult:
        """使用 crawl4ai 抓取（支持JS渲染）"""
        result = FetchResult(url=url, strategy=FetchStrategy.CRAWL4AI)

        try:
            from crawl4ai import AsyncWebCrawler

            start_time = time.time()

            async with AsyncWebCrawler(verbose=False) as crawler:
                crawl_result = await crawler.arun(
                    url=url,
                    css_selector="body",
                    js_render=True,
                    js_wait=5000,
                    wait_for="networkidle",
                    bypass_cache=True,
                    timeout=self.timeout,
                )

            result.response_time_ms = int((time.time() - start_time) * 1000)

            if crawl_result and crawl_result.success:
                result.html = crawl_result.html
                result.status_code = 200
                result.final_url = url
                result.success = True

                # 检测安全验证
                title = crawl_result.title or ""
                detected, challenge_type, details = SecurityDetector.detect(
                    title, result.html, url
                )
                if detected:
                    result.security_challenge = challenge_type
                    result.success = False
                    result.error_category = ErrorCategory.SECURITY_CHALLENGE
                    result.error_detail = f"安全验证: {challenge_type.value}"
            else:
                error_msg = crawl_result.error_message if crawl_result else "无返回结果"
                result.error_category = ErrorCategory.INVALID_RESPONSE
                result.error_detail = f"crawl4ai失败: {error_msg}"

        except ImportError:
            result.error_category = ErrorCategory.UNKNOWN
            result.error_detail = "crawl4ai 未安装 (pip install crawl4ai)"
        except Exception as e:
            result.error_category = ErrorCategory.UNKNOWN
            result.error_detail = f"crawl4ai错误: {e}"

        return result

    async def _fetch_with_playwright(self, url: str) -> FetchResult:
        """使用 Playwright 浏览器抓取"""
        result = FetchResult(url=url, strategy=FetchStrategy.PLAYWRIGHT)

        try:
            from playwright.async_api import async_playwright

            start_time = time.time()

            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=[
                        "--disable-blink-features=AutomationControlled",
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                    ]
                )

                context = await browser.new_context(
                    user_agent=self.ua_manager.random(),
                    ignore_https_errors=True,
                    viewport={"width": 1920, "height": 1080},
                )

                page = await context.new_page()

                # 隐藏webdriver特征
                await page.add_init_script("""
                    Object.defineProperty(navigator, 'webdriver', {
                        get: () => undefined
                    });
                """)

                try:
                    await page.goto(url, timeout=self.timeout * 1000, wait_until="networkidle")
                    await page.wait_for_timeout(2000)

                    result.final_url = page.url
                    result.html = await page.content()
                    result.status_code = 200
                    result.response_time_ms = int((time.time() - start_time) * 1000)

                    # 检测安全验证
                    page_title = await page.title()
                    detected, challenge_type, details = SecurityDetector.detect(
                        page_title, result.html, page.url
                    )

                    if detected:
                        # Cloudflare 等待自动通过
                        if challenge_type == SecurityChallenge.CLOUDFLARE:
                            logger.info("Cloudflare验证检测，等待自动通过...")
                            for i in range(15):
                                await page.wait_for_timeout(2000)
                                new_title = await page.title()
                                new_html = await page.content()
                                re_detected, _, _ = SecurityDetector.detect(
                                    new_title, new_html, page.url
                                )
                                if not re_detected:
                                    logger.info(f"Cloudflare验证已通过 (等待{(i+1)*2}秒)")
                                    result.html = new_html
                                    result.final_url = page.url
                                    result.success = True
                                    break
                            else:
                                # 超时后降级提取
                                logger.warning("Cloudflare验证超时，降级提取当前页面内容")
                                result.html = await page.content()
                                if result.html and len(result.html) > 500:
                                    result.success = True
                                    result.error_detail = "页面可能被Cloudflare拦截，但提取到了内容"
                        else:
                            # 其他验证类型，尝试刷新
                            logger.info(f"检测到{challenge_type.value}验证，尝试刷新...")
                            await page.goto(url, timeout=self.timeout * 1000, wait_until="networkidle")
                            await page.wait_for_timeout(2000)
                            new_title = await page.title()
                            new_html = await page.content()
                            re_detected, _, _ = SecurityDetector.detect(
                                new_title, new_html, page.url
                            )
                            if not re_detected:
                                result.html = new_html
                                result.final_url = page.url
                                result.success = True
                            else:
                                # 降级提取
                                result.html = new_html
                                if result.html and len(result.html) > 500:
                                    result.success = True
                                    result.error_detail = f"页面被{challenge_type.value}拦截，但提取到了内容"
                    else:
                        result.success = True

                except Exception as e:
                    result.error_category = ErrorCategory.UNKNOWN
                    result.error_detail = f"Playwright错误: {e}"
                finally:
                    await browser.close()

        except ImportError:
            result.error_category = ErrorCategory.UNKNOWN
            result.error_detail = "playwright 未安装 (pip install playwright)"
        except Exception as e:
            result.error_category = ErrorCategory.UNKNOWN
            result.error_detail = f"Playwright初始化错误: {e}"

        return result

    async def _fetch_with_selenium(self, url: str) -> FetchResult:
        """使用 Selenium 浏览器抓取"""
        result = FetchResult(url=url, strategy=FetchStrategy.SELENIUM)

        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.common.exceptions import TimeoutException

            chrome_options = Options()
            chrome_options.add_argument("--headless=new")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--window-size=1920,1080")
            chrome_options.add_argument("--disable-blink-features=AutomationControlled")
            chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
            chrome_options.add_experimental_option('useAutomationExtension', False)
            chrome_options.add_argument(f"--user-agent={self.ua_manager.random()}")

            start_time = time.time()

            driver = webdriver.Chrome(options=chrome_options)
            driver.set_page_load_timeout(self.timeout)

            try:
                driver.get(url)
                time.sleep(3)

                # 隐藏webdriver特征
                driver.execute_script(
                    "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
                )

                result.final_url = driver.current_url
                result.html = driver.page_source
                result.status_code = 200
                result.response_time_ms = int((time.time() - start_time) * 1000)

                # 检测安全验证
                page_title = driver.title
                detected, challenge_type, details = SecurityDetector.detect(
                    page_title, result.html, driver.current_url
                )

                if detected:
                    if challenge_type == SecurityChallenge.CLOUDFLARE:
                        logger.info("Selenium: Cloudflare验证检测，等待自动通过...")
                        for i in range(15):
                            time.sleep(2)
                            new_title = driver.title
                            new_html = driver.page_source
                            re_detected, _, _ = SecurityDetector.detect(
                                new_title, new_html, driver.current_url
                            )
                            if not re_detected:
                                logger.info(f"Selenium: Cloudflare验证已通过 (等待{(i+1)*2}秒)")
                                result.html = new_html
                                result.final_url = driver.current_url
                                result.success = True
                                break
                        else:
                            result.html = driver.page_source
                            if result.html and len(result.html) > 500:
                                result.success = True
                                result.error_detail = "页面可能被Cloudflare拦截，但提取到了内容"
                    else:
                        result.html = driver.page_source
                        if result.html and len(result.html) > 500:
                            result.success = True
                            result.error_detail = f"页面被{challenge_type.value}拦截，但提取到了内容"
                else:
                    result.success = True

            except TimeoutException:
                result.error_category = ErrorCategory.TIMEOUT
                result.error_detail = "Selenium页面加载超时"
                # 超时后尝试获取已加载的内容
                try:
                    driver.execute_script("window.stop();")
                    time.sleep(1)
                    result.html = driver.page_source
                    if result.html and len(result.html) > 500:
                        result.success = True
                        result.error_detail = "页面加载超时，但提取到了部分内容"
                except:
                    pass
            except Exception as e:
                result.error_category = ErrorCategory.UNKNOWN
                result.error_detail = f"Selenium错误: {e}"
            finally:
                try:
                    driver.quit()
                except:
                    pass

        except ImportError:
            result.error_category = ErrorCategory.UNKNOWN
            result.error_detail = "selenium 未安装 (pip install selenium)"
        except Exception as e:
            result.error_category = ErrorCategory.UNKNOWN
            result.error_detail = f"Selenium初始化错误: {e}"

        return result

    async def _bypass_security(self, url: str, challenge: SecurityChallenge) -> bool:
        """尝试绕过安全验证"""
        logger.info(f"尝试绕过安全验证 [{challenge.value}]: {url[:80]}...")

        if challenge == SecurityChallenge.CLOUDFLARE:
            # 使用Playwright等待Cloudflare自动通过
            try:
                from playwright.async_api import async_playwright
                async with async_playwright() as p:
                    browser = await p.chromium.launch(headless=True)
                    page = await browser.new_page()
                    await page.goto(url, timeout=30000)
                    for i in range(15):
                        await page.wait_for_timeout(2000)
                        title = await page.title()
                        html = await page.content()
                        detected, _, _ = SecurityDetector.detect(title, html, page.url)
                        if not detected:
                            await browser.close()
                            logger.info(f"Cloudflare绕过成功 (等待{(i+1)*2}秒)")
                            return True
                    await browser.close()
                    return False
            except:
                return False

        elif challenge in [SecurityChallenge.AKAMAI, SecurityChallenge.GENERIC_WAF]:
            # 尝试更换UA和IP（如果有代理）
            return False

        return False

    def _save_debug_page(self, result: FetchResult):
        """保存调试页面"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_url = re.sub(r'[^\w]', '_', result.url[:50])
            filename = f"{result.strategy.value}_{safe_url}_{timestamp}.html"
            filepath = os.path.join(self.debug_dir, filename)

            with open(filepath, "w", encoding="utf-8") as f:
                f.write(f"<!-- URL: {result.url} -->\n")
                f.write(f"<!-- Final URL: {result.final_url} -->\n")
                f.write(f"<!-- Status: {result.status_code} -->\n")
                f.write(f"<!-- Strategy: {result.strategy.value if result.strategy else 'none'} -->\n")
                f.write(f"<!-- Success: {result.success} -->\n")
                f.write(f"<!-- Time: {result.response_time_ms}ms -->\n")
                f.write(f"<!-- Error: {result.error_detail} -->\n")
                f.write(result.html)

            logger.debug(f"调试页面已保存: {filepath}")
        except Exception as e:
            logger.warning(f"保存调试页面失败: {e}")


# ============================================================
# 翻页处理器
# ============================================================

class PaginationHandler:
    """翻页处理器 - 支持按钮点击和URL参数修改"""

    def __init__(self, executor: RequestExecutor):
        self.executor = executor

    async def get_next_page_url(self, current_url: str, current_html: str) -> Optional[str]:
        """
        获取下一页URL

        策略：
        1. 查找"下一页"链接
        2. 修改URL参数
        3. 修改URL路径
        """
        # 策略1: 从HTML中查找下一页链接
        next_url = self._find_next_link_in_html(current_html, current_url)
        if next_url:
            return next_url

        # 策略2: 修改URL参数
        next_url = self._modify_url_param(current_url)
        if next_url:
            return next_url

        # 策略3: 修改URL路径
        next_url = self._modify_url_path(current_url)
        if next_url:
            return next_url

        return None

    def _find_next_link_in_html(self, html: str, base_url: str) -> Optional[str]:
        """在HTML中查找下一页链接"""
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, 'html.parser')

            # 查找 rel="next"
            link = soup.find('link', rel='next')
            if link and link.get('href'):
                return urllib.parse.urljoin(base_url, link['href'])

            # 查找 a[rel="next"]
            link = soup.find('a', rel='next')
            if link and link.get('href'):
                return urllib.parse.urljoin(base_url, link['href'])

            # 查找包含"下一页"文本的链接
            next_texts = ['下一页', 'next', 'Next', '>', '»', '›', '→', '下页']
            for text in next_texts:
                links = soup.find_all('a', string=re.compile(re.escape(text), re.IGNORECASE))
                for link in links:
                    if link.get('href'):
                        return urllib.parse.urljoin(base_url, link['href'])

            # 查找 aria-label 包含 next 的链接
            link = soup.find('a', attrs={'aria-label': re.compile(r'next|下一页|下页', re.IGNORECASE)})
            if link and link.get('href'):
                return urllib.parse.urljoin(base_url, link['href'])

            # 查找分页容器中的数字链接
            pagination_selectors = [
                '.pagination', '.pager', '.pages', '.page-navigation',
                '.paging', '.nav-links', '.page-nav', '.wp-pagenavi',
                '.page-numbers', '[class*="pagination"]'
            ]
            for selector in pagination_selectors:
                container = soup.select_one(selector)
                if container:
                    links = container.find_all('a')
                    for link in links:
                        text = link.get_text().strip()
                        if text in ['>', '»', '›', '→', 'Next', 'next']:
                            if link.get('href'):
                                return urllib.parse.urljoin(base_url, link['href'])

        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"查找下一页链接失败: {e}")

        return None

    def _modify_url_param(self, url: str) -> Optional[str]:
        """通过修改URL参数获取下一页"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param_name in PAGE_PARAM_NAMES:
                if param_name in params:
                    try:
                        current_val = int(params[param_name][0])
                        if current_val > 1000:
                            continue

                        new_params = params.copy()
                        if param_name in ['start', 'offset', 'from', 'skip', 'begin', 'index']:
                            step = current_val if current_val > 0 else 10
                            new_params[param_name] = [str(current_val + step)]
                        else:
                            new_params[param_name] = [str(current_val + 1)]

                        new_query = "&".join([f"{k}={v[0]}" for k, v in new_params.items()])
                        new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                        return new_url
                    except (ValueError, IndexError):
                        continue

        except Exception:
            pass

        return None

    def _modify_url_path(self, url: str) -> Optional[str]:
        """通过修改URL路径获取下一页"""
        try:
            parsed = urlparse(url)

            for pattern, replacement in PAGE_PATH_PATTERNS:
                match = re.search(pattern, parsed.path)
                if match:
                    current_val = int(match.group(1))
                    if current_val > 1000:
                        continue

                    new_path = re.sub(pattern, f"{replacement}{current_val + 1}", parsed.path)
                    new_url = f"{parsed.scheme}://{parsed.netloc}{new_path}"
                    if parsed.query:
                        new_url += f"?{parsed.query}"
                    return new_url

        except Exception:
            pass

        return None


# ============================================================
# 反反爬主类
# ============================================================

class AntiAntiCrawler:
    """
    反反爬综合工具主类

    功能：
    - 多策略请求（httpx → crawl4ai → playwright → selenium）
    - 安全验证检测与绕过
    - User-Agent 轮换
    - 代理支持
    - 翻页
    - 调试页面保存
    """

    def __init__(
        self,
        proxy: Optional[str] = None,
        timeout: int = 30,
        max_retries: int = 3,
        retry_delay: float = 2.0,
        enable_js: bool = True,
        enable_browser: bool = True,
        save_debug: bool = False,
        debug_dir: str = "debug_pages",
        verbose: bool = False,
    ):
        self.proxy = proxy
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.enable_js = enable_js
        self.enable_browser = enable_browser
        self.save_debug = save_debug
        self.debug_dir = debug_dir
        self.verbose = verbose

        if verbose:
            logger.setLevel(logging.DEBUG)

        self.ua_manager = UserAgentManager()
        self.executor = RequestExecutor(
            proxy=proxy,
            timeout=timeout,
            max_retries=max_retries,
            retry_delay=retry_delay,
            enable_js_fallback=enable_js,
            enable_browser_fallback=enable_browser,
            save_debug_pages=save_debug,
            debug_dir=debug_dir,
            ua_manager=self.ua_manager,
        )
        self.pagination = PaginationHandler(self.executor)

        # 统计信息
        self.stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "bypassed_security": 0,
            "total_time_ms": 0,
        }

    async def fetch(
        self,
        url: str,
        preferred_strategy: Optional[FetchStrategy] = None,
        custom_headers: Optional[Dict] = None,
    ) -> FetchResult:
        """
        抓取URL内容

        Args:
            url: 目标URL
            preferred_strategy: 首选策略
            custom_headers: 自定义请求头

        Returns:
            FetchResult
        """
        self.stats["total_requests"] += 1
        start_time = time.time()

        result = await self.executor.fetch(url, preferred_strategy, custom_headers)

        elapsed = int((time.time() - start_time) * 1000)
        self.stats["total_time_ms"] += elapsed

        if result.success:
            self.stats["successful_requests"] += 1
        else:
            self.stats["failed_requests"] += 1

        if result.security_challenge and result.security_challenge != SecurityChallenge.NONE:
            self.stats["bypassed_security"] += 1

        return result

    async def fetch_pages(
        self,
        url: str,
        max_pages: int = 3,
        preferred_strategy: Optional[FetchStrategy] = None,
    ) -> List[FetchResult]:
        """
        抓取多页内容（翻页）

        Args:
            url: 起始URL
            max_pages: 最大翻页数
            preferred_strategy: 首选策略

        Returns:
            List[FetchResult]
        """
        results = []
        current_url = url

        for page_num in range(1, max_pages + 1):
            logger.info(f"翻页 {page_num}/{max_pages}: {current_url[:80]}...")

            result = await self.fetch(current_url, preferred_strategy)
            results.append(result)

            if not result.success:
                logger.warning(f"第{page_num}页抓取失败: {result.error_detail}")
                break

            if page_num < max_pages:
                next_url = await self.pagination.get_next_page_url(
                    current_url, result.html
                )
                if next_url:
                    current_url = next_url
                else:
                    logger.info("未找到下一页链接，停止翻页")
                    break

        return results

    def get_stats(self) -> Dict:
        """获取统计信息"""
        total = self.stats["total_requests"]
        success = self.stats["successful_requests"]
        avg_time = 0
        if success > 0:
            avg_time = self.stats["total_time_ms"] / success

        success_rate = 0
        if total > 0:
            success_rate = (success / total) * 100

        return {
            **self.stats,
            "average_time_ms": round(avg_time, 2),
            "success_rate_percent": round(success_rate, 2),
        }


# ============================================================
# 命令行入口
# ============================================================

def main():
    """命令行入口"""
    import argparse

    parser = argparse.ArgumentParser(
        description="反反爬综合工具 - 多策略网站访问",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 直接访问URL
  python anti_anti_crawler.py https://example.com

  # 使用代理
  python anti_anti_crawler.py https://example.com --proxy socks5://127.0.0.1:1080

  # 指定策略
  python anti_anti_crawler.py https://example.com --strategy playwright

  # 翻页
  python anti_anti_crawler.py https://example.com --max-pages 3

  # 保存调试页面
  python anti_anti_crawler.py https://example.com --save-debug

  # 详细日志
  python anti_anti_crawler.py https://example.com --verbose
        """,
    )

    parser.add_argument("url", help="目标URL")
    parser.add_argument("--proxy", "-p", help="代理地址 (socks5://... 或 http://...)")
    parser.add_argument(
        "--strategy", "-s",
        choices=["httpx", "crawl4ai", "playwright", "selenium"],
        help="首选抓取策略",
    )
    parser.add_argument("--max-pages", "-n", type=int, default=1, help="最大翻页数")
    parser.add_argument("--timeout", "-t", type=int, default=30, help="请求超时（秒）")
    parser.add_argument("--retries", "-r", type=int, default=3, help="最大重试次数")
    parser.add_argument("--delay", "-d", type=float, default=2.0, help="重试延迟（秒）")
    parser.add_argument("--no-js", action="store_true", help="禁用JS渲染回退")
    parser.add_argument("--no-browser", action="store_true", help="禁用浏览器回退")
    parser.add_argument("--save-debug", action="store_true", help="保存调试页面")
    parser.add_argument("--debug-dir", default="debug_pages", help="调试页面保存目录")
    parser.add_argument("--verbose", "-v", action="store_true", help="详细日志")

    args = parser.parse_args()

    # 创建反反爬工具
    aac = AntiAntiCrawler(
        proxy=args.proxy,
        timeout=args.timeout,
        max_retries=args.retries,
        retry_delay=args.delay,
        enable_js=not args.no_js,
        enable_browser=not args.no_browser,
        save_debug=args.save_debug,
        debug_dir=args.debug_dir,
        verbose=args.verbose,
    )

    # 策略映射
    strategy_map = {
        "httpx": FetchStrategy.HTTPX,
        "crawl4ai": FetchStrategy.CRAWL4AI,
        "playwright": FetchStrategy.PLAYWRIGHT,
        "selenium": FetchStrategy.SELENIUM,
    }
    preferred_strategy = strategy_map.get(args.strategy)

    # 打印信息
    print("=" * 60)
    print("🛡️  反反爬综合工具")
    print("=" * 60)
    print(f"  URL:      {args.url}")
    print(f"  策略:     {args.strategy or '自动'}")
    print(f"  翻页:     {args.max_pages} 页")
    print(f"  代理:     {args.proxy or '无'}")
    print(f"  超时:     {args.timeout}s")
    print(f"  重试:     {args.retries}次")
    print("=" * 60)

    # 执行
    async def run():
        if args.max_pages > 1:
            results = await aac.fetch_pages(args.url, args.max_pages, preferred_strategy)
        else:
            result = await aac.fetch(args.url, preferred_strategy)
            results = [result]

        # 输出结果
        for i, result in enumerate(results):
            status = "✅ 成功" if result.success else "❌ 失败"
            print(f"\n📄 第{i+1}页结果:")
            print(f"  状态:     {status}")
            print(f"  策略:     {result.strategy.value if result.strategy else '无'}")
            print(f"  状态码:   {result.status_code}")
            print(f"  耗时:     {result.response_time_ms}ms")
            print(f"  最终URL:  {result.final_url[:100] if result.final_url else '无'}")
            print(f"  HTML大小: {len(result.html)} 字符")

            if result.security_challenge and result.security_challenge != SecurityChallenge.NONE:
                print(f"  ⚠️ 安全验证: {result.security_challenge.value}")

            if result.error_detail:
                print(f"  ⚠️ 错误: {result.error_detail}")

        # 统计
        stats = aac.get_stats()
        print("\n" + "=" * 50)
        print("📊 请求统计")
        print("=" * 50)
        print(f"  总请求数:     {stats['total_requests']}")
        print(f"  成功请求:     {stats['successful_requests']}")
        print(f"  失败请求:     {stats['failed_requests']}")
        print(f"  成功率:       {stats['success_rate_percent']}%")
        print(f"  绕过安全验证: {stats['bypassed_security']}")
        print(f"  平均耗时:     {stats['average_time_ms']}ms")
        print(f"  总耗时:       {stats['total_time_ms']}ms")
        print("=" * 50)

    asyncio.run(run())


if __name__ == "__main__":
    main()
