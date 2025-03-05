# Email Sanitizer Pro

A robust Python utility for cleaning, validating, and sanitizing email addresses with enhanced compatibility for Squarespace and other platforms.

## Features

- Comprehensive email validation against RFC standards
- Detection and filtering of spam patterns
- Identification of role-based emails
- Correction of common typos in domain names
- Removal of duplicate entries
- Support for bulk email processing
- Customizable validation rules

## Installation

```bash
# Clone the repository
git clone https://github.com/umerkhan95/Email-Sanitizer-Pro.git

# Navigate to the project directory
cd Email-Sanitizer-Pro

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
python email_sanitizer.py input_file.csv output_directory
```

## Configuration

Create a `.env` file based on the provided `.env.example` with your configuration:

```
VALIDATION_MODE=strict  # or 'lenient'
BATCH_SIZE=20
DNS_TIMEOUT=5  # timeout in seconds for DNS queries
MAX_DOMAIN_FREQUENCY=20  # maximum number of emails allowed from same domain
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please check out our contribution guidelines in CONTRIBUTING.md.