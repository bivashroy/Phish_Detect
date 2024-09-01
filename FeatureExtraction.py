# importing required packages
import pandas as pd
from urllib.parse import urlparse
import ipaddress
import re
import whois
from datetime import datetime
import requests

# 1. Domain of the URL (Domain)
def getDomain(url):  
    domain = urlparse(url).netloc
    if re.match(r"^www.", domain):
        domain = domain.replace("www.", "")
    return domain

# 2. Checks for IP address in URL (Have_IP)
def havingIP(url):
    try:
        ipaddress.ip_address(url)
        ip = 1
    except:
        ip = 0
    return ip

# 3. Checks the presence of @ in URL (Have_At)
def haveAtSign(url):
    return 1 if "@" in url else 0

# 4. Finding the length of URL and categorizing (URL_Length)
def getLength(url):
    return 0 if len(url) < 54 else 1

# 5. Gives number of '/' in URL (URL_Depth)
def getDepth(url):
    return len([i for i in urlparse(url).path.split('/') if i])

# 6. Checking for redirection '//' in the url (Redirection)
def redirection(url):
    return 1 if url.rfind('//') > 7 else 0

# 7. Existence of “HTTPS” Token in the Domain Part of the URL (https_Domain)
def httpDomain(url):
    return 1 if 'https' in urlparse(url).netloc else 0

# 8. Checking for Shortening Services in URL (Tiny_URL)
shortening_services = r"(bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|...)" # truncated for brevity
def tinyURL(url):
    return 1 if re.search(shortening_services, url) else 0

# 9. Checking for Prefix or Suffix Separated by (-) in the Domain (Prefix/Suffix)
def prefixSuffix(url):
    return 1 if '-' in urlparse(url).netloc else 0

# 10. DNS Record availability (DNS_Record)
def check_dns(url):
    try:
        domain_name = whois.whois(urlparse(url).netloc, timeout=10)
        return 0, domain_name
    except:
        return 1, None

# 11. Survival time of domain: The difference between termination time and creation time (Domain_Age)  
def domainAge(domain_name):
    try:
        creation_date = domain_name.creation_date
        expiration_date = domain_name.expiration_date
        if isinstance(creation_date, str) or isinstance(expiration_date, str):
            creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        if creation_date is None or expiration_date is None or type(expiration_date) is list or type(creation_date) is list:
            return 1
        ageofdomain = abs((expiration_date - creation_date).days)
        return 1 if (ageofdomain / 30) < 6 else 0
    except:
        return 1

# 12. End time of domain: The difference between termination time and current time (Domain_End) 
def domainEnd(domain_name):
    try:
        expiration_date = domain_name.expiration_date
        if isinstance(expiration_date, str):
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        if expiration_date is None or type(expiration_date) is list:
            return 1
        today = datetime.now()
        end = abs((expiration_date - today).days)
        return 1 if (end / 30) < 6 else 0
    except:
        return 1

# 13. IFrame Redirection (iFrame)
def iframe(response):
    if response == "":
        return 1
    return 0 if re.findall(r"[<iframe>|<frameBorder>]", response.text) else 1

# 14. Checks the effect of mouse over on status bar (Mouse_Over)
def mouseOver(response): 
    if response == "":
        return 1
    return 1 if re.findall("<script>.+onmouseover.+</script>", response.text) else 0

# 15. Checks the status of the right-click attribute (Right_Click)
def rightClick(response):
    if response == "":
        return 1
    return 0 if re.findall(r"event.button ?== ?2", response.text) else 1

# 16. Checks the number of forwardings (Web_Forwards)    
def forwarding(response):
    if response == "":
        return 1
    return 0 if len(response.history) <= 2 else 1

def featureExtractions(url):
    features = []
    
    # Address bar-based features (8)
    features.append(havingIP(url))
    features.append(haveAtSign(url))
    features.append(getLength(url))
    features.append(getDepth(url))
    features.append(redirection(url))
    features.append(httpDomain(url))
    features.append(tinyURL(url))
    features.append(prefixSuffix(url))
    
    # Domain-based features (3)
    dns, domain_name = check_dns(url)
    features.append(dns)
    if dns == 0:
        features.append(domainAge(domain_name))
        features.append(domainEnd(domain_name))
    else:
        features.append(0)  # default value for domainAge
        features.append(0)  # default value for domainEnd

    # HTML & Javascript-based features (4)
    try:
        response = requests.get(url, timeout=5)
    except:
        response = ""
    
    features.append(iframe(response))
    features.append(mouseOver(response))
    features.append(rightClick(response))
    features.append(forwarding(response))

    features.insert(0, getDomain(url))  # Insert the getDomain(url) feature at the beginning

    print("Features:", features)
    print("Length of features:", len(features))
    
    return features