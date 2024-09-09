import os
import requests
from urllib.parse import urlparse
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# API credentials from the environment variables
FACEBOOK_ACCESS_TOKEN = os.getenv('FACEBOOK_ACCESS_TOKEN')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
GROUP_ID = os.getenv('GROUP_ID')

# Facebook Graph API URLs
FB_GRAPH_API_URL = f'https://graph.facebook.com/v17.0/{GROUP_ID}/feed'
FB_BAN_USER_API_URL = f'https://graph.facebook.com/v17.0/{GROUP_ID}/banned'

# VirusTotal API URL
VIRUSTOTAL_API_URL = 'https://www.virustotal.com/vtapi/v2/url/report'


def get_group_posts():
    """Fetches recent posts from the Facebook group."""
    params = {
        'access_token': FACEBOOK_ACCESS_TOKEN
    }
    response = requests.get(FB_GRAPH_API_URL, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error fetching group posts: {response.status_code}")
        return None


def scan_url_virustotal(url):
    """Scans the URL using VirusTotal and returns the result."""
    # Make sure the URL is properly formatted
    url_encoded = urlparse(url).geturl()
    params = {
        'apikey': VIRUSTOTAL_API_KEY,
        'resource': url_encoded
    }
    response = requests.get(VIRUSTOTAL_API_URL, params=params)
    
    if response.status_code == 200:
        result = response.json()
        return result
    else:
        print(f"Error scanning URL: {response.status_code}")
        return None


def ban_member(user_id):
    """Bans a user from the Facebook group."""
    data = {
        'uid': user_id,
        'access_token': FACEBOOK_ACCESS_TOKEN
    }
    response = requests.post(FB_BAN_USER_API_URL, data=data)
    
    if response.status_code == 200:
        print(f"User {user_id} banned successfully.")
    else:
        print(f"Failed to ban user {user_id}: {response.status_code}, {response.text}")


def extract_urls(message):
    """Basic URL extraction from post content."""
    # This is a simple implementation. You may enhance it with regex for better URL extraction.
    words = message.split()
    urls = [word for word in words if word.startswith('http')]
    return urls


def process_posts():
    """Processes posts in the group and scans URLs for malicious content."""
    posts = get_group_posts()
    
    if not posts or 'data' not in posts:
        print("No posts found or error fetching posts.")
        return
    
    for post in posts['data']:
        message = post.get('message', '')
        user_id = post.get('from', {}).get('id')
        
        if not user_id or not message:
            continue
        
        urls = extract_urls(message)
        
        if urls:
            for url in urls:
                print(f"Scanning URL: {url}")
                vt_result = scan_url_virustotal(url)
                
                if vt_result and vt_result.get('positives', 0) > 0:
                    print(f"Malicious URL detected: {url}")
                    ban_member(user_id)
                else:
                    print(f"URL is safe: {url}")
        else:
            print("No URLs found in the message.")


if __name__ == '__main__':
    process_posts()
