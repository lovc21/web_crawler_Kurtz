import concurrent
import platform
import threading
from urllib.error import URLError
import urllib3
from flask import Flask, request, jsonify, make_response
from selenium import webdriver
from selenium.common import StaleElementReferenceException, TimeoutException
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
import requests
import os
import time
from datetime import datetime
import xml.etree.ElementTree as Et
import validators
import hashlib
import logging
from io import StringIO
from urllib.parse import urlparse, urlunparse, urljoin
from concurrent.futures import ThreadPoolExecutor
import sqlite3
import psycopg2
import re
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as ec
from logging import StreamHandler
from logging.handlers import RotatingFileHandler
from urllib.parse import urlparse, urlunparse


# Logging helper
class CustomStreamHandler(StreamHandler):
    def __init__(self, stream=None, errors='replace'):
        super().__init__(stream)
        self.errors = errors

    def emit(self, record):
        try:
            msg = self.format(record)
            stream = self.stream
            stream.write(msg + self.terminator)
            self.flush()
        except Exception:
            self.handleError(record)


class CustomRotatingFileHandler(RotatingFileHandler):
    def __init__(self, filename, mode='a', maxBytes=0, backupCount=0, encoding=None, delay=False, errors='replace'):
        super().__init__(filename, mode, maxBytes, backupCount, encoding, delay)
        self.errors = errors

    def emit(self, record):
        try:
            msg = self.format(record)
            stream = self.stream
            stream.write(msg + self.terminator)
            self.flush()
        except Exception:
            self.handleError(record)


class MyWebScraper:
    WEB_DRIVER_LOCATION = None
    TIMEOUT = 5
    BIN_EXT = [".PDF", ".DOC", ".DOCX", ".PPT", ".PPTX"]
    found_bin = ""

    def __init__(self):
        self.app = Flask("MyWebScraper_number")
        self.app.route('/scrape', methods=['POST'])(self.scrape)
        self.app.route('/logs', methods=['GET'])(self.get_logs)

        # Simple requests session
        self.session = requests.Session()

        # Set up logger
        self.log_stream = StringIO()
        log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s\n')

        # Log to stream (endpoint)
        stream_handler = CustomStreamHandler(self.log_stream)
        stream_handler.setFormatter(log_formatter)
        stream_handler.encoding = 'utf-8'

        # Log to file
        file_handler = CustomRotatingFileHandler('web_scraper.log', maxBytes=100 * 1024 * 1024, backupCount=5)
        file_handler.setFormatter(log_formatter)

        self.logger = logging.getLogger('web_scraper')
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(stream_handler)
        self.logger.addHandler(file_handler)

        self.driver = None

        # Set up database
        self.init_database()

        # Set up chromedriver
        if not MyWebScraper.WEB_DRIVER_LOCATION:
            MyWebScraper.WEB_DRIVER_LOCATION = self.find_chromedriver()

    # Database setup
    def init_database(self):
        conn = sqlite3.connect('frontier.db')
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS frontier_links (
                                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                                    url TEXT UNIQUE NOT NULL
                                    )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS url_hashes (
                                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                                            hash TEXT UNIQUE NOT NULL,
                                            page_id INTEGER UNIQUE NOT NULL
                                            
                                            )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS old_frontier (
                                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                                        url TEXT UNIQUE NOT NULL
                                        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS domain_crawl_delays (
                                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                                domain TEXT UNIQUE NOT NULL,
                                                crawl_delay REAL NOT NULL
                                                )''')
        conn.commit()
        conn.close()

    # Flask app STUFF and find chromedriver
    def start(self, host='0.0.0.0', port=5000):
        try:
            self.app.run(host=host, port=port)
        except Exception as e:
            self.logger.error(f'Error starting the Flask app: {e}', exc_info=True)

    def scrape_task(self, input_value):
        try:
            self.main([input_value])
            self.logger.info(f'Successfully scraped URL: {input_value}')
        except Exception as e:
            self.logger.error(f'Error processing 1 URL {input_value}: {e}')

    def scrape(self):
        input_messages = request.get_json().get('messages', [])
        for input_value in input_messages:
            self.logger.info(f'Starting scrape for URL: {input_value}\n')
            t = threading.Thread(target=self.scrape_task, args=(input_value,))
            t.start()
        return jsonify({"message": "OK, scraper is working"})

    def get_logs(self):
        logs = self.log_stream.getvalue().split('\n')
        logs_html = '<br>'.join(logs)
        response = make_response(logs_html, 200)
        response.mimetype = "text/html"
        return response

    def find_chromedriver(self):
        cwd = os.getcwd()
        system = platform.system()
        chromedriver_file = {
            'Windows': 'chromedriver.exe',
            'Darwin': 'chromedriver',
            'Linux': 'chromedriver',
        }

        if system in chromedriver_file:
            for root, dirs, files in os.walk(cwd):
                if chromedriver_file[system] in files:
                    self.logger.info(f'Found chromedriver at {os.path.join(root, chromedriver_file[system])}')
                    return os.path.join(root, chromedriver_file[system])

        return None
    # Parsing part
    def is_allowed_extension(self, url):
        disallowed_extensions = ['.zip', '.rar', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt',
                                 '.ods', '.odp', '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.ico', '.svg',
                                 '.mp3', '.wav', '.mp4', '.avi', '.mov', '.mkv', '.webm']

        url_extension = os.path.splitext(urlparse(url).path)[1].lower()
        if url_extension in disallowed_extensions:
            return False
        else:
            return True

    def get_sitemap_host(self, driver):
        sitemap_host = None
        self.logger.info("Getting sitemap host")
        page_source = driver.page_source
        lines = page_source.split('\n')

        for line in lines:
            line = line.strip()
            if line.lower().startswith('sitemap:'):
                try:
                    sitemap_host = line[len('sitemap:'):].strip()
                    break
                except TypeError as e:
                    self.logger.error(f"Error extracting sitemap host from line: {line}, error: {e}", exc_info=True)
                    return (None, False)

        sub_str = ".xml"

        if sitemap_host and sub_str in sitemap_host:
            # self.logger.debug(f"Extracted sitemap_host value: {sitemap_host}")
            sitemap_host = sitemap_host[:sitemap_host.index(sub_str) + len(sub_str)]

            response = requests.get(sitemap_host)
            if response.status_code == 404:
                self.logger.warning(f"Sitemap host {sitemap_host} returned 404 error", exc_info=True)
                return (sitemap_host, False)
            else:
                self.logger.info(f"Sitemap host: {sitemap_host}")
                return (sitemap_host, True)
        else:
            self.logger.warning("No sitemap host found", exc_info=True)
            return (sitemap_host, False)

    def get_sitemap_content(self, sitemap_host):

        self.logger.info("Getting sitemap links")
        urls = set()
        try:
            def process_sitemap(host):
                nonlocal urls
                if not host:
                    return

                try:
                    response = requests.get(host)
                    if response.status_code != 200:
                        self.logger.error(f"Error getting sitemap content: {response.status_code}", exc_info=True)
                        return

                    response = requests.get(host)
                    root = Et.fromstring(response.content)

                    self.logger.info(f"Processing sitemap: {host}")

                    for child in root:
                        for url in child:
                            url_text = url.text
                            if url_text and "http" in url_text:

                                if "xml" in url_text:
                                    # self.logger.info(f"Found nested sitemap: {url_text}\n")
                                    process_sitemap(url_text)
                                else:
                                    canonized_sitemap_url = self.canonize_url(url_text)
                                    # self.logger.info(f"Found URL: {canonized_sitemap_url}\n")
                                    urls.add(canonized_sitemap_url)

                except Exception as ex:
                    self.logger.error(f"Error getting sitemap content: {ex}", exc_info=True)

            process_sitemap(sitemap_host)

        except Exception as ex:
            self.logger.error(f"Error getting sitemap content: {ex}", exc_info=True)
            return None

        self.logger.info(f"Found {len(list(urls))} URLs")
        return list(urls)

    def check_robot_txt(self, driver):
        self.logger.info("Checking robot.txt")

        robot_delay = None
        robot_allowance = "User agent is allowed to crawl the website"

        robots_url = driver.current_url.rstrip('/') + '/robots.txt'

        response = requests.get(robots_url)
        if response.status_code == 200:
            html = response.text
            lines = html.splitlines()

            concerns_this = False
            for x in lines:
                if not x:
                    continue
                line = x.split()
                if len(line) < 2:
                    continue
                directive, value = line[0].lower(), line[1]

                if directive == "user-agent:":
                    concerns_this = value == "*"
                elif concerns_this:
                    if directive in ["disallow:", "allow:"]:
                        if value == '/':
                            robot_allowance = "User agent is not allowed to crawl the website"
                            break
                    elif directive == "crawl-delay:":
                        robot_delay = int(value)

            self.logger.info(f"Robot.txt allowance: {robot_allowance}")
        else:
            self.logger.warning("Failed to fetch robots.txt")

        return robot_delay, robot_allowance

    def parse_links(self, a_tags):
        self.logger.info("Parsing links")
        links = []

        for link in a_tags:
            try:
                href = link.get_attribute("href")
                onclick = link.get_attribute("onclick")

                if onclick:
                    href = self.driver.execute_script("""
                            var link = document.createElement("a");
                            link.onclick = function() { %s };
                            link.click();
                            return link.href;
                        """ % onclick)

                if href is not None and validators.url(href):
                    canonized_href = self.canonize_url(href)
                    links.append(canonized_href)

            except StaleElementReferenceException:
                self.logger.warning("Encountered a stale element. Skipping this link.", exc_info=True)

        self.logger.info("URL canonization")
        self.logger.info(f"Found {len(links)} links")
        return links

    def canonize_url(self, url):
        url = url.split("#")[0]
        url = url.split("?")[0]

        parsed_url = urlparse(url)
        netloc_parts = parsed_url.netloc.split(".")

        if len(netloc_parts) < 3:
            netloc = "www." + parsed_url.netloc.lower()
        else:
            netloc = parsed_url.netloc.lower()

        temp = parsed_url.path.strip().split("/")
        temp = list(filter(None, temp))

        canonized_path = "/".join(temp)
        canonized_url = urlunparse(parsed_url._replace(netloc=netloc, fragment='', path=canonized_path))

        return urljoin(canonized_url, '')

    def parse_img(self, imgs):
        self.logger.info("Parsing images")
        images = []
        base64_pattern = re.compile(r'data:image/(.+);base64')

        for img in imgs:
            try:
                src = img.get_attribute("src")
            except StaleElementReferenceException:
                self.logger.warning("StaleElementReferenceException encountered. Retrying...")
                continue
            if src:
                ext_match = base64_pattern.match(src)
                if ext_match:
                    ext = ext_match.group(1)
                else:
                    src_without_query_string = src.split('?')[0]
                    ext = src_without_query_string[src_without_query_string.rfind('.') + 1:]

                ALLOWED_EXTENSIONS = ['png', 'jpg', 'jpeg', 'gif', 'svg', 'bmp', 'webp']
                if ext and ext.lower() in ALLOWED_EXTENSIONS:
                    if len(src) > 255:
                        src = src.split('/')[-1]
                        if len(src) > 255:
                            src = src[:255]
                    image = {
                        "filename": src,
                        "contentType": ext,
                        "data": [],
                        "accessedTime": datetime.now().isoformat(),
                    }
                    images.append(image)
                else:
                    self.logger.error(f"Invalid ext: {ext}", exc_info=True)
        self.logger.info(f"Found {len(images)} images")
        return images

    def check_binary(self, url):
        self.logger.info("Checking binary")
        for ext in self.BIN_EXT:
            if url.upper().endswith(ext):
                self.found_bin = ext.replace(".", "")
                self.logger.info("Found binary")
                return True
        self.logger.info("Not binary\n")
        return False

    def hash_html(self, html_content):
        self.logger.info("Hashing html")
        return hashlib.md5(html_content.encode('utf-8')).hexdigest()

    def process_url(self, url):

        if url.lower().endswith('.zip'):
            self.logger.warning(f"Skipping URL {url} because it's a .zip file", exc_info=True)
            return {'url': url, 'skipped': True}
        if self.is_url_in_database(url):
            self.logger.info(f"URL {url} is already in the database, skipping", exc_info=True)
            return {'url': url, 'skipped': True}
        try:
            options = webdriver.ChromeOptions()
            options.add_argument('--headless')
            options.add_argument('--disable-gpu')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--blink-settings=imagesEnabled=false')
            options.add_argument('--ignore-certificate-errors')
            options.add_argument("--ignore-urlfetcher-cert-requests")
            options.add_argument("--allow-running-insecure-content")
            options.add_argument("--ignore-certificate-errors-spki-list")
            options.add_argument('user-agent=fri-ieps-Lt-Colonel-Kilgore-team')

            driver_service = Service(self.WEB_DRIVER_LOCATION)
            driver_service.start()

            with webdriver.Chrome(service=driver_service, options=options) as driver:

                self.driver = driver

                sitemap_content = []

                robot_delay = None

                try:
                    driver.get(url + "robots.txt")
                except Exception as e:
                    error_message = str(e)
                    if (
                            "net::ERR_BAD_SSL_CLIENT_AUTH_CERT" in error_message or "net::ERR_NAME_NOT_RESOLVED" in error_message or
                            "net::ERR_CONNECTION_RESET" in error_message or "net::ERR_BAD_SSL_CLIENT_AUTH_CERT" in error_message):
                        self.logger.warning(f"Error accessing URL {url}: No CERT error message {e}", exc_info=True)
                        return {'url': url, 'error': str(e)}
                    else:
                        raise

                domain = urlparse(url).netloc

                visited_domains = self.get_domains_from_db()

                result_robot = {}
                if domain not in visited_domains:
                    self.logger.info("Domain not visited yet")

                    robot_txt_content = driver.page_source
                    sitemap_host = self.get_sitemap_host(driver)
                    sitemap_content = self.get_sitemap_content(sitemap_host[0])
                    robot_delay, robot_allowance = self.check_robot_txt(driver)

                    self.save_domain_crawl_delay_to_db(domain, robot_delay)

                    # print(sitemap_host)

                    if sitemap_host[1] is False and sitemap_host[0] == "{}":
                        sitemap_host_content = "Empty/No sitemap"
                    else:
                        sitemap_host_content = sitemap_host[0]

                    result_robot = {
                        'domain': domain,
                        'robot_txt_content': robot_txt_content,
                        'sitemap_host_content': sitemap_host_content,
                        'robot_delay': robot_delay,
                        'robot_allowance': robot_allowance,
                        'sitemap_content_links': sitemap_content,
                        'hash': None,
                    }
                else:
                    self.logger.info("Domain visited\n")

                domain_crawl_delay = self.get_domain_crawl_delay(domain)

                if domain_crawl_delay is not None:
                    self.TIMEOUT = max(self.TIMEOUT, robot_delay)

                time.sleep(self.TIMEOUT)

                try:
                    status_code = self.session.get(url).status_code if not self.check_binary(url) else ""
                except URLError as e:
                    self.logger.error(f"Error processing URL {url}: {e}", exc_info=True)
                    return {'url': url, 'error': str(e)}

                if self.check_binary(url):
                    self.logger.info("Binary content found")

                    try:
                        driver.get(url)
                    except Exception as e:
                        error_message = str(e)
                        if ( "net::ERR_BAD_SSL_CLIENT_AUTH_CERT" in error_message or "net::ERR_NAME_NOT_RESOLVED" in error_message or "net::ERR_CONNECTION_RESET" in error_message or "net::ERR_BAD_SSL_CLIENT_AUTH_CERT" in error_message):
                            self.logger.warning(f"Error accessing URL {url}: No CERT error message {e}", exc_info=True)
                            return {'url': url, 'error': str(e)}
                        else:
                            raise

                    self.logger.info("Binary content found")
                    result_parse = {
                        'url': self.canonize_url(url),
                        'html': "",
                        'httpStatusCode': status_code,
                        'accessedTime': datetime.now().isoformat(),
                        'pageType': "BINARY",
                        'data_type': self.found_bin,
                        'Domain': domain,
                        'hash': None,
                    }
                    #print(result_parse)
                else:

                    try:
                        driver.get(url)
                    except Exception as e:
                        error_message = str(e)
                        if (
                                "net::ERR_BAD_SSL_CLIENT_AUTH_CERT" in error_message or "net::ERR_NAME_NOT_RESOLVED" in error_message or "net::ERR_CONNECTION_RESET" in error_message or "net::ERR_BAD_SSL_CLIENT_AUTH_CERT" in error_message):
                            self.logger.warning(f"Error accessing URL {url}: No CERT error message {e}", exc_info=True)
                            return {'url': url, 'error': str(e)}
                        else:
                            raise

                    try:
                        wait = WebDriverWait(driver, 10)
                        wait.until(ec.presence_of_all_elements_located((By.TAG_NAME, "a")))
                    except TimeoutException:
                        self.logger.warning(
                            f"TimeoutException: Unable to locate elements with tag 'a' on the page {url}")
                        a_tags = []
                    else:
                        a_tags = driver.find_elements(By.TAG_NAME, "a")

                    if not self.is_allowed_extension(url):
                        self.logger.warning(f"Skipping URL {url} because it has a disallowed extension", exc_info=True)
                        return {'url': url, 'skipped': True}

                    # a_tags = driver.find_elements(By.TAG_NAME, "a")
                    imgs = driver.find_elements(By.TAG_NAME, "img")
                    html = driver.page_source

                    self.logger.info("HTML content found")
                    links = self.parse_links(a_tags)
                    img = self.parse_img(imgs)
                    html_hash = self.hash_html(html)

                    self.add_links_to_db(list(set(sitemap_content + links)))

                    result_parse = {
                        'url': self.canonize_url(url),
                        'html': html,
                        'img': img,
                        'links': links,
                        'pageType': "HTML",
                        'httpStatusCode': status_code,
                        'accessedTime': datetime.now().isoformat(),
                        'hash': html_hash,  # if not self.check_binary(url) else None,
                        'Domain': domain,
                        'data_type': self.found_bin,
                    }

                return result_robot, result_parse

        except urllib3.exceptions.ProtocolError as e:
            self.logger.error(f"Error processing URL {url}: {e}", exc_info=True)
            return {'url': url, 'error': str(e)}

        except Exception as e:
            self.logger.error(f"Error processing 2 URL {url}: {e}\n", exc_info=True)
            return {'url': url, 'error': str(e)}

    # Database part
    def add_links_to_db(self, links):
        conn = sqlite3.connect('frontier.db')
        cursor = conn.cursor()

        for link in links:
            try:
                cursor.execute("SELECT COUNT(*) FROM old_frontier WHERE url = ?", (link,))
                count = cursor.fetchone()[0]
                if count == 0:
                    cursor.execute("INSERT INTO frontier_links (url) VALUES (?)", (link,))
                    self.logger.info(f"Added link: {link}")
                else:
                    self.logger.info(f"Skipped existing link in old_frontier: {link}")

            except sqlite3.IntegrityError:
                self.logger.info(f"Skipped existing link in frontier_links: {link}")

        conn.commit()
        conn.close()

    def get_links_from_db(self):
        self.logger.info("Getting links from frontier")
        conn = sqlite3.connect('frontier.db')
        cursor = conn.cursor()
        cursor.execute("SELECT url FROM frontier_links")
        result = [row[0] for row in cursor.fetchall()]
        conn.close()

        return result

    def delete_link_from_db(self, url):
        conn = sqlite3.connect('frontier.db')
        cursor = conn.cursor()

        try:
            cursor.execute("INSERT INTO old_frontier (url) SELECT url FROM frontier_links WHERE url = ?", (url,))
            cursor.execute("DELETE FROM frontier_links WHERE url = ?", (url,))
            self.logger.info(f"Deleted link: {url}")
        except sqlite3.Error as e:
            self.logger.error(f"Error deleting link from db: {e} {url}", exc_info=True)

        conn.commit()
        conn.close()

    def add_hash_to_db(self, url_hash, page_id):
        conn = sqlite3.connect('frontier.db')
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO url_hashes (hash,page_id) VALUES (?,?)", (url_hash, page_id))
            self.logger.info(f"Added hash: {url_hash}")
        except sqlite3.IntegrityError:
            self.logger.info(f"Skipped existing hash: {url_hash}")
        conn.commit()
        conn.close()

    def get_hashes_from_db(self):
        conn = sqlite3.connect('frontier.db')
        cursor = conn.cursor()
        cursor.execute("SELECT hash, page_id FROM url_hashes")
        rows = cursor.fetchall()

        hashes = [row[0] for row in rows]
        page_id_hashes = {row[0]: row[1] for row in rows}

        conn.close()
        return page_id_hashes

    def get_domains_from_db(self):
        try:
            conn = psycopg2.connect(
                host="localhost",
                database="user",
                user="user",
                password="SecretPassword"
            )

            conn.autocommit = True
            cursor = conn.cursor()

            cursor.execute("SELECT domain FROM crawldb.site")
            domains = [row[0] for row in cursor.fetchall()]

            conn.close()
            return domains

        except (Exception, psycopg2.DatabaseError) as error:
            self.logger.error(f"Error fetching domains from database: {error}", exc_info=True)
            return []

    def save_domain_crawl_delay_to_db(self, domain, crawl_delay):
        if crawl_delay is None:
            self.logger.warning(f"Skipping saving crawl delay for domain {domain}: crawl_delay is None")
            return

        conn = sqlite3.connect('frontier.db')
        cursor = conn.cursor()

        try:
            cursor.execute("INSERT OR REPLACE INTO domain_crawl_delays (domain, crawl_delay) VALUES (?, ?)",
                           (domain, crawl_delay))
            self.logger.info(f"Saved crawl delay for domain {domain}: {crawl_delay}")
        except sqlite3.Error as e:
            self.logger.error(f"Error saving crawl delay for domain {domain}: {e}", exc_info=True)

        conn.commit()
        conn.close()

    def get_domain_crawl_delay(self, domain):
        conn = sqlite3.connect('frontier.db')
        cursor = conn.cursor()

        cursor.execute("SELECT crawl_delay FROM domain_crawl_delays WHERE domain = ?", (domain,))
        result = cursor.fetchone()

        conn.close()

        if result:
            return result[0]
        else:
            return None

    def is_url_in_database(self, url):
        try:
            conn = psycopg2.connect(
                host="localhost",
                database="user",
                user="user",
                password="SecretPassword"
            )
            conn.autocommit = True
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM crawldb.page WHERE url = %s", (url,))
            result = cursor.fetchone()[0]

            conn.close()
            return result > 0

        except (Exception, psycopg2.DatabaseError) as error:
            self.logger.error(f"Error checking if URL is in database: {error}", exc_info=True)
            return False

    def save_result_to_db(self, result_robot, result_parse):
        try:
            conn = psycopg2.connect(
                host="localhost",
                database="user",
                user="user",
                password="SecretPassword"
            )
            conn.autocommit = True
            cursor = conn.cursor()

        except (Exception, psycopg2.DatabaseError) as error:
            self.logger.error(f"Error connecting to database: {error}", exc_info=True)
            return

        self.logger.info("Saving result to db\n")
        hashes = self.get_hashes_from_db()

        try:
            if result_parse['hash'] is not None:
                # self.logger.debug(f"Result parse data: {result_parse}")
                duplicates_page_id = hashes.get(result_parse['hash'])
        except Exception as e:
            self.logger.error(f"Error getting hash from db:{e} {result_parse}", exc_info=True)
            print(result_parse)

        try:
            if result_robot:
                visited_domains = self.get_domains_from_db()
                if result_robot['domain'] not in visited_domains:
                    try:
                        cursor.execute(
                            "INSERT INTO crawldb.site (domain, robots_content, sitemap_content) VALUES (%s, %s, %s)",
                            (result_robot['domain'], result_robot['robot_txt_content'],
                             result_robot['sitemap_host_content']))
                    except (Exception, psycopg2.DatabaseError) as error:
                        self.logger.error(f"Error inserting site data: {error}", exc_info=True)
            else:
                self.logger.info("No result_robot data to insert")

            cursor.execute("SELECT id FROM crawldb.site WHERE domain = %s", (result_parse['Domain'],))
            site_id = cursor.fetchone()[0]

            if result_parse['hash'] is not None and duplicates_page_id:
                cursor.execute(
                    "INSERT INTO crawldb.page (site_id, url, html_content, http_status_code, accessed_time, page_type_code) VALUES (%s, %s, %s, %s, %s, %s)",
                    (site_id, result_parse['url'], None, result_parse['httpStatusCode'],
                     result_parse['accessedTime'], "DUPLICATE"))

                #print(f"Duplicate page found, added to duplicates page {result_parse['url']}")
                cursor.execute("SELECT id FROM crawldb.page WHERE site_id = %s AND url = %s",
                               (site_id, result_parse['url']))

                page_id = cursor.fetchone()[0]

                #print(f"Added link from {page_id} to {duplicates_page_id}")
                cursor.execute("INSERT INTO crawldb.link (from_page, to_page) VALUES (%s, %s)",
                               (page_id, duplicates_page_id))
                self.logger.info("Duplicate page found, added link to duplicates page")
                self.logger.info(f"Added link from {page_id} to {duplicates_page_id}")
                cursor.execute("SELECT id FROM crawldb.page WHERE url = %s", (result_parse['url'],))
                return

            if result_parse['pageType'] != "BINARY":
                try:
                    cursor.execute(
                        "INSERT INTO crawldb.page (site_id, url, html_content, http_status_code, accessed_time, page_type_code) VALUES (%s, %s, %s, %s, %s, %s)",
                        (site_id, result_parse['url'], result_parse['html'], result_parse['httpStatusCode'],
                         result_parse['accessedTime'], result_parse['pageType']))

                except (Exception, psycopg2.DatabaseError) as error:
                    self.logger.error(f"Error inserting page data: {error}", exc_info=True)

            cursor.execute("SELECT id FROM crawldb.page WHERE site_id = %s AND url = %s",
                           (site_id, result_parse['url']))
            page_id = cursor.fetchone()[0]

            if result_parse['pageType'] != "BINARY":
                self.add_hash_to_db(result_parse['hash'], page_id)

            try:
                if result_parse['img']:
                    for img in result_parse['img']:
                        cursor.execute(
                            "INSERT INTO crawldb.image (page_id, filename, content_type, data, accessed_time) VALUES (%s, %s, %s, %s, %s)",
                            (page_id, img['filename'], img['contentType'], img['data'],
                             result_parse['accessedTime']))

                cursor.execute("SELECT id FROM crawldb.page WHERE site_id = %s AND url = %s",
                               (site_id, result_parse['url']))
                page_id = cursor.fetchone()[0]

                cursor.execute(
                    "INSERT INTO crawldb.page_data (page_id, data_type_code) VALUES (%s, %s)",
                    (page_id, result_parse['data_type']))

            except (Exception, psycopg2.DatabaseError) as error:
                self.logger.error(f"Error inserting image, page_data, or link data: {error}", exc_info=True)

            conn.commit()
            conn.close()
            self.logger.info(
                f"Successfully saved data for domain: {result_robot.get('domain')} and URL: {result_parse['url']}")
        except (Exception, psycopg2.DatabaseError) as error:
            self.logger.error(f"Error inserting data into database: {error}", exc_info=True)

    # Multithreading part
    def main(self, urls):

        while True:
            if urls is None or len(urls) == 0:
                urls = self.get_links_from_db()

            if len(urls) == 0:
                break

            results = []
            with ThreadPoolExecutor(max_workers=50) as executor:
                gov_si_urls = [url for url in urls if 'gov.si' in url and not url.lower().endswith('.zip')]
                futures = {executor.submit(self.process_url, url): url for url in gov_si_urls}
                for future in concurrent.futures.as_completed(futures):
                    url = futures[future]
                    try:
                        result = future.result()
                        results.append(result)
                        if isinstance(result, tuple) and len(result) == 2:
                            result_robot, result_parse = result
                            self.save_result_to_db(result_robot, result_parse)
                            self.logger.info(f"Saved result for URL: {url}")
                        else:
                            self.logger.error(f"Error processing URL: {url} with error: {result['error']}")
                        self.delete_link_from_db(url)
                    except Exception as exc:
                        self.logger.error(f'Error processing 3 URL {url}: {exc}', exc_info=True)
                        results.append({'url': url, 'error': str(exc)})
            self.logger.info("Finished scraping sending results to frontier")
            urls = []


if __name__ == '__main__':
    scraper = MyWebScraper()
    scraper.start(host='0.0.0.0', port=5000)
