import feedparser
import ssl
from datetime import datetime, timezone

def fetch_feeds(feed_urls):
    if hasattr(ssl, '_create_unverified_context'):
        ssl._create_default_https_context = ssl._create_unverified_context
    
    articles = []
    for url in feed_urls:
        try:
            feed = feedparser.parse(url)
            for entry in feed.entries:
                content = ''
                if 'content' in entry:
                    content = entry.content[0].value
                else:
                    content = entry.get('summary', 'No content available.')
                
                published_time = datetime.now(timezone.utc)
                if hasattr(entry, 'published_parsed') and entry.published_parsed:
                    published_time = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
                
                articles.append({
                    'title': entry.get('title', 'No Title'),
                    'link': entry.get('link', '#'),
                    'published_time': published_time,
                    'published_str': published_time.strftime('%Y-%m-%d %H:%M'),
                    'content': content,
                    'source': feed.feed.get('title', url)
                })
        except Exception as e:
            print(f"Error fetching feed {url}: {e}")
            continue
            
    return sorted(articles, key=lambda x: x['published_time'], reverse=True)
