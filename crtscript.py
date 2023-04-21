import requests
import re
import time
import telegram

# Enter your Telegram bot token and chat ID here
bot_token = 'YOUR_TELEGRAM_BOT_TOKEN'
chat_id = 'YOUR_TELEGRAM_CHAT_ID'

# Initialize the Telegram bot
bot = telegram.Bot(token=bot_token)

# Set the time interval for checking the new subdomains
interval = 3600  # 1 hour

# Set the initial list of subdomains
subdomains = set()

while True:
    try:
        # Make a GET request to crt.sh to retrieve the subdomains
        response = requests.get('https://crt.sh/?q=%25&output=json')
        data = response.json()

        # Extract the subdomains from the response data
        new_subdomains = set(re.findall(r'\w+\.\w+\.\w+', str(data)))

        # Find the new subdomains that were not in the previous list
        added_subdomains = new_subdomains - subdomains

        # Send a notification for each new subdomain
        for subdomain in added_subdomains:
            message = f'New subdomain found: {subdomain}'
            bot.send_message(chat_id=chat_id, text=message)

        # Update the subdomains list
        subdomains = new_subdomains

        # Wait for the specified time interval before checking for new subdomains again
        time.sleep(interval)
    except Exception as e:
        print(f'Error: {e}')
        continue
