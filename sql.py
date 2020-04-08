import requests, argparse
from bs4 import BeautifulSoup as BS

def Main(test, get_database_type):
    if args.test:
        urls = [args.test + "'", args.test + '"', args.test[:-4] + ';', args.test[:-4] + ")", args.test[:-4] + "')", args.test[:-4] + '")', args.test[:-4] + '*'] 
        vulnerable_text = ['MySQL Query fail:', '/www/htdocs/', 'Query failed', 'mysqli_fetch_array()', 'mysqli_result', 'Warning: ', 'MySQL server', 'SQL syntax', 'You have an error in your SQL syntax;', 'mssql_query()', "Incorrect syntax near '='", 'mssql_num_rows()', 'Notice: ']
        for url in urls:
            results = requests.get(url)
            data = results.text
            soup = BS(data, features='html.parser')
            for vuln in vulnerable_text:
                if vuln in data:
                    string = vuln
                    vulnerable = True
        if vulnerable:
            print('Site is vulnerable!')
        else:
            print('Site is not vulnerable!')
    elif args.get_database_type:
        urls = [args.get_database_type + "'", args.get_database_type + '"', args.get_database_type[:-4] + ';', args.get_database_type[:-4] + ")", args.get_database_type[:-4] + "')", args.get_database_type[:-4] + '")', args.get_database_type[:-4] + '*']
        database_identifiers = ['MySQL']
        for url in urls:
            results = requests.get(url)
            data = results.text
            soup = BS(data, features='html.parser')
            for dbi in database_identifiers:
                if dbi in database_identifiers:
                    continue
        if dbi == 'MySQL':
            print('Database type is: MySQL')
        else:
            print('Database type is: Unknown')
    else:
        print('Invalid Argument given!')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SQL Injection Assistent')
    ap = argparse.ArgumentParser(prog='sql.py', usage='%(prog)s [options] -t <Target to test for SQLI Vulnerablities>', description='SQL Injection Assistent')
    ap.add_argument('-t', '--test', type=str, help='Test Target for SQLI Vulnerablities')
    ap.add_argument('-gdt', '--get_database_type', type=str, help='Find backend DB type')
    args = ap.parse_args()
    test = args.test
    get_database_type = args.get_database_type
    Main(test, get_database_type)
