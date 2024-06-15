from flask import Blueprint, render_template, request
from .scans import xss

main = Blueprint('main', __name__)

@main.route('/')
def home():
    return render_template('index.html')

@main.route('/scan', methods=['POST'])
def scan():
    url = request.form['url']
    if not is_valid_url(url):
        return "Invalid URL", 400
    results = run_scanner(url)
    return render_template('results.html', url=url, results=results)

def is_valid_url(url):
    try:
        from urllib.parse import urlparse
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def run_scanner(url):
    xss_result = xss.check_xss(url)
    return xss_result
