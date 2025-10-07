# Tld-Finder-
Find all TLD of Org 

# Install dependencies
pip3 install whois>=0.8.0   
pip3 install  dnspython>=2.4.0
pip3 install  requests>=2.31.0  

# Basic usage
python main.py "Google Inc" -d google.com

# Multiple domains (for subsidiaries)
python main.py "Alphabet Inc" -d google.com youtube.com
