# SQL Injection Scanner

This SQL Injection Scanner is an educational tool designed to help you identify potential SQL injection vulnerabilities in web applications. The scanner is implemented in Python using asyncio for asynchronous HTTP requests.

## Features

- Identify the type of database used by the target website.
- Test a website for potential SQL injection vulnerabilities.
- (Additional features can be implemented, such as dumping the database, extracting table names, extracting column names, and fetching the database name.)

## Requirements

- Python 3.7 or higher
- aiohttp
- BeautifulSoup4

## Installation

1. Clone the repository:

```
git clone https://github.com/bdunlap9/SQL-Injection-Scanner.git
```

2. Change to the project directory:

```
cd SQL-Injection-Scanner
```

3. Install the required Python packages:

```
pip install -r requirements.txt
```

## Usage

To use the SQL Injection Scanner, run the following command:

```
python sql.py <target_url> <database_type> [--test TEST_URL]
```

- `<target_url>`: The target URL to scan for SQL injection vulnerabilities.
- `<database_type>`: The type of database used by the target website. Supported types are MySQL, PostGre, Microsoft_SQL, Oracle, Advantage_Database, and Firebird.
- `--test TEST_URL`: (Optional) Test a specific URL for SQL injection vulnerabilities.

## Disclaimer

This tool is for educational purposes only. Use it responsibly and only on websites for which you have permission to test. Unauthorized use of this tool may result in criminal charges and legal consequences. The authors of this tool are not responsible for any misuse or damage caused by this tool.
