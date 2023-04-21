import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

# Enter the starting URL of the web application
base_url = 'https://www.example.com/'

# Set the maximum number of pages to crawl
max_pages = 100

# Initialize the set of visited URLs
visited_urls = set()

# Initialize the list of URLs to visit
urls_to_visit = [base_url]

# Crawl the web application
while len(urls_to_visit) > 0 and len(visited_urls) < max_pages:
    # Get the next URL to visit
    url = urls_to_visit.pop(0)

    # Skip the URL if it has already been visited
    if url in visited_urls:
        continue

    # Add the URL to the set of visited URLs
    visited_urls.add(url)

    # Print the URL being visited
    print(f'Visiting: {url}')

    try:
        # Make a GET request to the URL
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')

        # Get all the links on the page
        links = soup.find_all('a')

        # Visit all the links on the page
        for link in links:
            href = link.get('href')

            # Skip the link if it is None or empty
            if href is None or href == '':
                continue

            # Parse the link URL and join it with the base URL
            parsed_url = urlparse(href)
            if parsed_url.netloc == '':
                href = urljoin(url, href)

            # Skip the link if it is not on the same domain as the base URL
            if urlparse(href).netloc != urlparse(base_url).netloc:
                continue

            # Add the link URL to the list of URLs to visit
            if href not in visited_urls and href not in urls_to_visit:
                urls_to_visit.append(href)

    except Exception as e:
        print(f'Error: {e}')
        continue
