import re
import csv
import dns.resolver
import socket
from pathlib import Path
import time
from collections import Counter
import os
import unicodedata
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Get validation mode from environment variables
VALIDATION_MODE = os.getenv('VALIDATION_MODE', 'strict').lower()
MAX_DOMAIN_FREQUENCY = int(os.getenv('MAX_DOMAIN_FREQUENCY', 20))
DNS_TIMEOUT = int(os.getenv('DNS_TIMEOUT', 5))

print(f"Starting email cleaning process with {VALIDATION_MODE} validation mode...")
# Setup
print("Starting email cleaning process with enhanced Squarespace compatibility...")

# File paths
input_csv = "path_to_your_email.csv"
output_csv = "path_to_your_email.csv"
squarespace_csv = "path_to_your_email.csv"
rejected_csv = "path_to_your_email.csv"

# Initialize variables
valid_emails = set()
spam_emails = set()
invalid_format_emails = set()
no_mx_emails = set()
suspicious_emails = set()
role_based_emails = set()
duplicate_domain_emails = set()
typo_domain_emails = set()
temporary_emails = set()
total_emails = 0

# Even more strict email regex - RFC 5322 compliant plus additional restrictions
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._%+-]{0,63}@[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}\.[a-zA-Z]{2,}$")

# Patterns that might indicate spam emails - expanded
SPAM_PATTERNS = [
    r'^test[0-9]*@',           # test emails
    r'^example[0-9]*@',        # example emails
    r'^spam[0-9]*@',           # spam emails
    r'^info@',                 # generic info addresses
    r'^noreply@',              # no-reply addresses
    r'^mail@',                 # generic mail addresses
    r'^admin@',                # admin addresses
    r'^support@',              # support addresses
    r'^contact@',              # contact addresses
    r'^hello@',                # generic hello addresses
    r'^webmaster@',            # webmaster addresses
    r'^postmaster@',           # postmaster addresses
    r'^sales@',                # sales addresses
    r'^marketing@',            # marketing addresses
    r'^newsletter@',           # newsletter addresses
    r'^office@',               # office addresses
    r'^[a-z0-9]{1,2}@',        # Very short username (likely fake)
    r'[0-9]{6,}@',             # Numbers-only username (6+ digits)
    r'@example\.',             # example domains
    r'@test\.',                # test domains
    r'@mailinator\.',          # disposable email domain
    r'@yopmail\.',             # disposable email domain
    r'@tempmail\.',            # disposable email domain
    r'@10minutemail\.',        # disposable email domain
    r'@guerrillamail\.',       # disposable email domain
    r'@sharklasers\.',         # disposable email domain
    r'@trashmail\.',           # disposable email domain
    r'@gmai\.',                # typo domain (gmail)
    r'@hitmail\.',             # typo domain (hotmail)
    r'@gmial\.',               # typo domain (gmail)
    r'@homail\.',              # typo domain (hotmail)
    r'@gamil\.',               # typo domain (gmail)
    # Additional spam patterns
    r'^[0-9]+@',               # Email starts with numbers
    r'^[a-z][0-9]{5,}@',       # Single letter followed by numbers
    r'^user[0-9]*@',           # Generic user accounts
    r'^temp[0-9]*@',           # Temporary accounts
    r'^fake[0-9]*@',           # Fake accounts 
    r'^anonymous@',            # Anonymous accounts
    r'^[a-z]{1,3}[0-9]{3,}@',  # Few letters followed by many numbers
    r'^noreply[0-9]*@',        # No-reply addresses with numbers
    r'^do-?not-?reply@',       # Do not reply addresses
    r'^no-?reply@',            # No reply addresses
    r'^[a-z0-9]{10,}@',        # Very long random-looking usernames
    r'^([a-z])\1{2,}@',        # Repeated characters (aaa@ etc.)
    r'^test[0-9]*@',
    r'^example[0-9]*@',
    r'^spam[0-9]*@',
    r'@example\.',
    r'@test\.'
]
SPAM_REGEX = re.compile('|'.join(SPAM_PATTERNS), re.IGNORECASE)

# Role-based emails that often bounce or are not personal
ROLE_PATTERNS = [
    r'^info@',
    r'^admin@',
    r'^contact@',
    r'^hello@',
    r'^support@',
    r'^webmaster@',
    r'^postmaster@',
    r'^sales@',
    r'^marketing@',
    r'^team@',
    r'^office@',
    r'^jobs@',
    r'^careers@',
    r'^service@',
    r'^help@',
    r'^inquiry@',
    r'^billing@',
    r'^accounts@',
    r'^hr@',
    r'^media@',
    r'^press@',
    r'^privacy@',
    r'^legal@',
    r'^abuse@',
    r'^security@',
    # Additional role-based patterns
    r'^newsletter@',
    r'^noc@',
    r'^hostmaster@',
    r'^community@',
    r'^customerservice@',
    r'^feedback@',
    r'^no-reply@',
    r'^noreply@',
    r'^orders@',
    r'^partners@',
    r'^recruitment@',
    r'^dev@',
    r'^developer@',
    r'^development@',
    r'^mailing@',
    r'^mailbox@',
    r'^receptionist@',
    r'^secretary@',
    r'^notifications@',
    r'^alerts@',
    r'^news@',
]
ROLE_REGEX = re.compile('|'.join(ROLE_PATTERNS), re.IGNORECASE)

# Suspicious TLDs with higher spam rates or often rejected
SUSPICIOUS_TLDS = [
    '.xyz', '.top', '.win', '.bid', '.loan', '.online', '.site', '.stream',
    '.click', '.space', '.gdn', '.review', '.trade', '.date', '.download',
    '.cf', '.ga', '.gq', '.ml', '.tk', '.pw', '.icu', '.club', '.live',
    '.racing', '.fit', '.party', '.webcam', '.uno', '.science', '.faith',
    '.work', '.rest', '.co.jp', '.rocks', 
    # Additional suspicious TLDs
    '.men', '.store', '.tech', '.app', '.casa', '.bar', '.website', '.shop', 
    '.link', '.guru', '.life', '.world', '.fun', '.today', '.agency',
    '.company', '.digital', '.email', '.network', '.solutions', '.zone',
    '.monster', '.skin', '.best', '.buzz', '.cool', '.direct', '.express', 
    '.promo', '.financial', '.support', '.services', '.business',
    '.fail', '.pics', '.codes', '.host', '.press', '.wtf', '.lol',
    '.city', '.run', '.gg', '.tv', '.cam'
]

# Expanded list of temporary/disposable email domains
TEMP_DOMAINS = [
    # Common disposable email domains
    'mailinator.com', 'yopmail.com', 'guerrillamail.com', '10minutemail.com', 'tempmail.com',
    'sharklasers.com', 'trashmail.com', 'mailnesia.com', 'temp-mail.org', 'disposable.com',
    'dispostable.com', 'mailcatch.com', 'tempail.com', 'spamgourmet.com', 'getairmail.com',
    'getnada.com', 'emailondeck.com', 'fakeinbox.com', 'tempinbox.com', 'mintemail.com',
    'opayq.com', 'throwawaymail.com', 'maildrop.cc', 'mailforspam.com', 'burnthis.email',
    'throwam.com', 'tempinbox.com', 'fakemail.net', 'spambog.com', 'meltmail.com',
    'tempr.email', 'discard.email', 'tempmail.ninja', 'mailsac.com', 'temp-mail.io',
    'jetable.org', 'mailezee.com', 'mailexpire.com', 'mytrashmail.com', 'mailtemp.net',
    'inboxalias.com', '10mail.org', '33mail.com', 'spamex.com', 'spam4.me',
    'guerrillamail.net', 'guerrillamail.org', 'guerrillamail.biz', 'mailsucker.net',
    'tempmailaddress.com', 'fakemailgenerator.com', 'safetymail.info', 'throwawaymail.com',
    'yopmail.fr', 'yopmail.net', 'cool.fr.nf', 'jetable.fr.nf', 'nospam.ze.tc',
    'nomail.xl.cx', 'mega.zik.dj', 'speed.1s.fr', 'courriel.fr.nf', 'moncourrier.fr.nf',
    'monemail.fr.nf', 'monmail.fr.nf', 'temporary-mail.net', 'mohmal.com', 'mailtemp.eu',
    'temp.bartdevos.be', 'anonmails.de', 'anonymbox.com', 'trash-mail.com', 'spamoff.de',
    'spoofmail.de', 'wegwerfmail.de', 'wegwerfmail.net', 'wegwerfmail.org', 'mailmetrash.com',
    # Additional domains from previous list
    'gmailk.com', 'ymail.com', 'servus-mail.de', 'mail.de', 'email.de',
    'zedat.fu-berlin.de', 'outlook.fr', 'gmx.com', 'gmx.at', 
    'googlemail.de', 'poster.de', 'arcor.de', 'inbox.ru', 'internet-apotheke.de',
    # More domains commonly blocked
    'spam.la', 'no-spam.ws', 'temp-mail.ru', 'acemail.com', 'gawab.com',
    'mailmetrash.com', 'spamspot.com', 'antispam.de', 'anonymail.dk', 'trash-mail.de',
    'discardmail.com', 'spamfree24.org', 'mailscrap.com', 'emailsensei.com', 'soodo.com',
    'tempemails.io', 'temporaryinbox.com', 'instantemailaddress.com', 'mailzero.com',
    '0box.eu', '0clickemail.com', '0wnd.net', '0wnd.org', '10mail.org', '10minutemail.cf',
    '10minutemail.co.uk', '10minutemail.co.za', '10minutemail.de', '10minutemail.ga',
    '10minutemail.gq', '10minutemail.ml', '12minutemail.com', '1ce.us', '1chuan.com',
    '1mail.ml', '1pad.de', '1zhuan.com', '20email.eu', '20mail.in', '20minutemail.com',
    '2prong.com', '30minutemail.com', '33mail.com', '3d-painting.com', '3mail.ga',
    '4mail.cf', '4mail.ga', '5mail.cf', '5mail.ga', '6mail.cf', '6mail.ga',
    '7mail.ga', '8mail.cf', '8mail.ga', '8mail.ml', '9mail.cf', '9mail.ga',
    'deadfake.com', 'fakeinbox.com', 'fakemailgenerator.com', 'filzmail.com', 'freemail.ms',
    'get-mail.ml', 'get-mail.net', 'getonemail.com', 'getonemail.net', 'gishpuppy.com',
    'guerillamail.com', 'guerillamail.de', 'guerillamail.info', 'guerillamail.net',
    'guerillamail.org', 'guerillamailblock.com', 'haltospam.com', 'inboxalias.com', 'mailinator.co.uk',
    'mailinator.info', 'mailinator.net', 'mailinator.org', 'mailinator2.com', 'mailtothis.com',
    'mt2015.com', 'mt2016.com', 'mymail-in.net', 'mytrashmail.com', 'notmailinator.com',
    'outlooky.com', 'reallymymail.com', 'recyclemail.com', 'rhyta.com', 'thisisnotmyrealemail.com',
    'throam.com', 'tradermail.info', 'trash2009.com', 'trash2010.com', 'trash2011.com',
    'trashymail.com', 'veryrealemail.com', 'vipmailz.com', 'wants.dicksinhisan.us', 'wants.dicksinmyan.us',
    'watchfull.net', 'wetrainbayarea.com', 'wilemail.com', 'willhackforfood.biz', 'willselfdestruct.com',
    'winemaven.info', 'writeme.com', 'yopmail.net', 'yopmail.org', 'z1p.biz'
]

# Common email providers that are generally reliable
RELIABLE_DOMAINS = [
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'outlook.de',
    'aol.com', 'icloud.com', 'gmx.de', 'web.de', 'gmx.net', 
    't-online.de', 'googlemail.com', 'mail.ru', 'yandex.ru',
    'protonmail.com', 'proton.me', 'tutanota.com', 'zoho.com',
    'posteo.de', 'mailbox.org', 'fastmail.com', 'yahoo.fr',
    'yahoo.de', 'yahoo.co.uk', 'yahoo.it', 'msn.com', 'live.com',
    'hotmail.de', 'hotmail.fr', 'hotmail.co.uk', 'mac.com',
    'me.com', 'aol.de', 'mail.com', 'posteo.net', 'posteo.eu',
    'freenet.de', 'berlin.de', 'arcor.de', 'gmx.com', 'gmx.at',
    'gmx.ch', 'gmx.fr', 'gmx.es', 'gmx.co.uk', 'gmx.us', 'gmx.net','email.de'
]

# Common company email domains that are generally reliable
RELIABLE_COMPANY_DOMAINS = [
    'apple.com', 'google.com', 'microsoft.com', 'amazon.com',
    'facebook.com', 'twitter.com', 'linkedin.com', 'ibm.com',
    'intel.com', 'oracle.com', 'samsung.com', 'sony.com',
    'vodafone.com', 't-mobile.com', 'salesforce.com', 'adobe.com',
    'spotify.com', 'netflix.com', 'airbnb.com', 'uber.com',
]

# Track domain frequency to identify potential duplicated accounts
domain_counter = Counter()

# DNS cache to speed up lookups
mx_record_cache = {}

def normalize_email(email):
    """Normalize email address by removing dots from gmail and converting to lowercase"""
    email = email.lower()
    if '@gmail.com' in email:
        username, domain = email.split('@', 1)
        # Remove dots from Gmail username (Gmail ignores dots)
        username = username.replace('.', '')
        # Remove everything after + in Gmail (Gmail ignores +xyz suffix)
        if '+' in username:
            username = username.split('+', 1)[0]
        return f"{username}@{domain}"
    return email

def check_mx_records(domain):
    """Check if domain has valid MX records, with caching for performance"""
    if domain in mx_record_cache:
        return mx_record_cache[domain]
    
    try:
        # Set a specific timeout for DNS queries to avoid hanging
        answers = dns.resolver.resolve(domain, 'MX', lifetime=5)
        result = len(answers) > 0
    except Exception:
        result = False
    
    # Cache the result
    mx_record_cache[domain] = result
    return result

def has_suspicious_tld(domain):
    """Check if domain has a suspicious TLD"""
    return any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)

def is_temporary_domain(domain):
    """Check if domain is a known temporary/disposable email domain"""
    return domain in TEMP_DOMAINS

def is_role_account(email):
    """Check if email is a role-based account"""
    return bool(ROLE_REGEX.search(email))

def has_invalid_username_format(local_part):
    """Check for specific username format issues"""
    # Check for consecutive dots
    if '..' in local_part:
        return True
        
    # Check for starting/ending with dot
    if local_part.startswith('.') or local_part.endswith('.'):
        return True
        
    # Check for unusually long usernames (potential spam)
    if len(local_part) > 40:
        return True
    
    # Check for unusually short usernames
    if len(local_part) < 3:
        return True
        
    # Check for suspicious character patterns (repeated characters)
    if re.search(r'(.)\1{4,}', local_part):  # Same character repeated 5+ times
        return True
        
    # Check for too many non-alphanumeric characters
    non_alnum_count = sum(not c.isalnum() for c in local_part)
    if non_alnum_count > len(local_part) / 3:  # More than 1/3 special chars
        return True
        
    # Check for numeric-only usernames (often spam)
    if local_part.isdigit():
        return True
    
    # Check for patterns of alternating letters and numbers (often automated/spam)
    if re.match(r'^([a-z][0-9]){3,}$', local_part, re.IGNORECASE):
        return True
    
    # Check for username ending with many digits (often automated)
    if re.match(r'^[a-z]+[0-9]{4,}$', local_part, re.IGNORECASE):
        return True
    
    return False

def is_common_typo_domain(domain):
    # Skip checking reliable domains
    if domain in RELIABLE_DOMAINS:
        return False
        
    # Rest of your typo detection code...
    typo_patterns = {
        r'g?ma?il?[.-]?c?o?m?': 'gmail.com',
        r'ho?t?ma?il?[.-]?c?o?m?': 'hotmail.com',
        r'ya?h?o?o?[.-]?c?o?m?': 'yahoo.com',
        r'outlo?o?k?[.-]?c?o?m?': 'outlook.com',
        r'gmx[.-]?d?e?': 'gmx.de',
        r'web[.-]?d?e?': 'web.de',
        r'aol[.-]?c?o?m?': 'aol.com',
        r'icloud[.-]?c?o?m?': 'icloud.com',
        r'protonmail[.-]?c?o?m?': 'protonmail.com',
        r't[-]?online[.-]?d?e?': 't-online.de',
    }
    
    for pattern, correct in typo_patterns.items():
        if pattern in domain:
            return True
    
    return False

def has_forbidden_chars(email):
    """Check for characters that might cause issues in CSV/database import"""
    forbidden_chars = [',', ';', '"', "'", '\\', '/', '\n', '\r', '\t']
    return any(char in email for char in forbidden_chars)

def contains_non_ascii(text):
    """Check if text contains non-ASCII characters"""
    return any(ord(char) > 127 for char in text)

# Read and process emails
print("Reading input file...")

# First pass - count domains for duplicate detection
with open(input_csv, "r", newline='', encoding='utf-8') as csvfile:
    reader = csv.reader(csvfile)
    for row in reader:
        if row and row[0].strip():
            email = row[0].strip().strip('"').strip().lower()
            if '@' in email:
                domain = email.split('@')[1]
                domain_counter[domain] += 1

# Second pass - main processing
with open(input_csv, "r", newline='', encoding='utf-8') as csvfile:
    reader = csv.reader(csvfile)
    for row in reader:
        if row:  # Skip empty rows
            # Clean the email
            email = row[0].strip().strip('"').strip()
            if email:
                total_emails += 1
                
                # Convert to lowercase for consistent checks
                email_lower = email.lower()
                
                # Check for non-ASCII characters
                if contains_non_ascii(email_lower):
                    print(f"Contains non-ASCII characters: {email}")
                    invalid_format_emails.add(email)
                    continue
                
                # Check for forbidden characters
                if has_forbidden_chars(email_lower):
                    print(f"Contains forbidden characters: {email}")
                    invalid_format_emails.add(email)
                    continue
                
                # Basic format check
                if not EMAIL_REGEX.match(email_lower):
                    print(f"Invalid format: {email}")
                    invalid_format_emails.add(email)
                    continue
                
                # Split email for additional checks
                try:
                    local_part, domain = email_lower.split('@', 1)
                except ValueError:
                    invalid_format_emails.add(email)
                    continue

                # Username format issues
                if has_invalid_username_format(local_part):
                    print(f"Invalid username format: {email}")
                    invalid_format_emails.add(email)
                    continue
                
                # Consider validation mode when checking spam patterns
                if VALIDATION_MODE == 'strict' and SPAM_REGEX.search(email_lower):
                    print(f"Spam pattern detected: {email}")
                    spam_emails.add(email)
                    continue
                elif VALIDATION_MODE == 'lenient' and email_lower.startswith(('test@', 'example@', 'spam@')):
                    # Only flag the most obvious spam in lenient mode
                    print(f"Obvious spam detected: {email}")
                    spam_emails.add(email)
                    continue
                
                # Role-based email check
                if is_role_account(email_lower):
                    print(f"Role account detected: {email}")
                    role_based_emails.add(email)
                    continue
                
                # Suspicious TLD check
                if has_suspicious_tld(domain):
                    print(f"Suspicious TLD: {email}")
                    suspicious_emails.add(email)
                    continue
                
                # Temporary domain check
                if is_temporary_domain(domain):
                    print(f"Temporary domain: {email}")
                    temporary_emails.add(email)
                    continue
                
                # Common typo domain check
                if is_common_typo_domain(domain):
                    print(f"Likely typo in domain: {email}")
                    typo_domain_emails.add(email)
                    continue
                
                # Domain popularity check - use lenient threshold if configured
                if (domain_counter[domain] > MAX_DOMAIN_FREQUENCY and 
                    domain not in RELIABLE_DOMAINS and 
                    domain not in RELIABLE_COMPANY_DOMAINS):
                    print(f"Unusual domain popularity: {email} (domain has {domain_counter[domain]} emails)")
                    duplicate_domain_emails.add(email)
                    continue
                
                # MX record check - skip for lenient mode or check with configured timeout
                if VALIDATION_MODE == 'lenient' or check_mx_records(domain):
                    normalized = normalize_email(email_lower)
                    valid_emails.add(normalized)
                    print(f"Valid email: {email}")
                else:
                    print(f"No MX records: {email}")
                    no_mx_emails.add(email)
                
                # Add a small delay to prevent DNS rate limiting
                time.sleep(0.05)

# Sort emails
sorted_emails = sorted(valid_emails)

# Create output directories if needed
Path(output_csv).parent.mkdir(parents=True, exist_ok=True)

# Write cleaned emails to file in standard format
print("\nWriting cleaned emails to file...")
with open(output_csv, "w", newline='', encoding='utf-8') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(['email'])  # Header
    for email in sorted_emails:
        writer.writerow([email])

# Write Squarespace-compatible CSV (with different formatting)
print("\nCreating Squarespace-compatible CSV...")
with open(squarespace_csv, "w", newline='', encoding='utf-8') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(['Email', 'First Name', 'Last Name'])  # Squarespace header format
    for email in sorted_emails:
        writer.writerow([email, '', ''])  # Empty first/last name

# Write rejected emails to file
with open(rejected_csv, "w", newline='', encoding='utf-8') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(['email', 'reason'])  # Header
    for email in invalid_format_emails:
        writer.writerow([email, 'Invalid format'])
    for email in spam_emails:
        writer.writerow([email, 'Spam pattern'])
    for email in role_based_emails:
        writer.writerow([email, 'Role-based account'])
    for email in suspicious_emails:
        writer.writerow([email, 'Suspicious TLD'])
    for email in typo_domain_emails:
        writer.writerow([email, 'Likely typo in domain'])
    for email in temporary_emails:
        writer.writerow([email, 'Temporary/disposable domain'])
    for email in duplicate_domain_emails:
        writer.writerow([email, 'Unusual domain popularity'])
    for email in no_mx_emails:
        writer.writerow([email, 'No MX records'])

# Print statistics
print(f"\nProcessing complete!")
print(f"Total emails processed: {total_emails}")
print(f"Valid unique emails found: {len(valid_emails)}")
print(f"Invalid format emails: {len(invalid_format_emails)}")
print(f"Spam pattern emails: {len(spam_emails)}")
print(f"Role-based emails: {len(role_based_emails)}")
print(f"Suspicious TLD emails: {len(suspicious_emails)}")
print(f"Typo domain emails: {len(typo_domain_emails)}")
print(f"Temporary/disposable domain emails: {len(temporary_emails)}")
print(f"Unusual domain popularity emails: {len(duplicate_domain_emails)}")
print(f"No MX record emails: {len(no_mx_emails)}")
total_rejected = (len(invalid_format_emails) + len(spam_emails) + len(role_based_emails) + 
                 len(suspicious_emails) + len(typo_domain_emails) + len(temporary_emails) +
                 len(duplicate_domain_emails) + len(no_mx_emails))
print(f"Total rejected: {total_rejected}")
print(f"Cleaned emails saved to: {output_csv}")
print(f"Squarespace-compatible emails saved to: {squarespace_csv}")
print(f"Rejected emails saved to: {rejected_csv}")
