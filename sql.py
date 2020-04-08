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
        
        # Database Identifiers
        MySQL_list = ['MySQL', 'MySQL Query fail:', 'SQL syntax', 'You have an error in your SQL syntax', 'mssql_query()', 'mssql_num_rows()']
        PostGre_list = ['']
        Microsoft_SQL_list = ['']
        Oracle_list = ['']
        Advantage_Database_list = ['']
        Firebird_list = ['']
        Azure_list = ['']
        SqlCe_list = ['']
        VistaDb_list = ['']

        for url in urls:
            results = requests.get(url)
            data = results.text
            soup = BS(data, features='html.parser')
            for dbi in MySQL_list:
                if dbi in MySQL_list:
                    MySQL = True
            for dbi in PostGre_list:
                if dbi in PostGre_list:
                    PostGre = True
            for dbi in Microsoft_SQL_list:
                if dbi in Microsoft_SQL_list:
                    Microsoft_SQL = True
            for dbi in Oracle_list:
                if dbi in Oracle_list:
                    Oracle = True
            for dbi in Advantage_Database_list:
                if dbi in Advantage_Database_list:
                    Advantage_Database_Server = True
            for dbi in Firebird_list:
                if dbi in Firebird_list:
                    Firebird = True
            for dbi in Azure_list:
                if dbi in Azure_list:
                    Azure = True
            for dbi in SqlCe_list:
                if dbi in SqlCe_list:
                    SqlCe = True
            for dbi in VistaDb_list:
                if dbi in VistaDb_list:
                    VistaDb = True
        if MySQL:
            print('Database type is: MySQL')
        elif PostGre:
            print('Database type is: PostGre')
        elif Microsoft_SQL:
            print('Database type is: Microsoft SQL Server')
        elif Oracle:
            print('Database type is: Oracle')
        elif Advantage_Database_Server:
            print('Database type is: Advantage Database Server')
        elif Firebird:
            print('Database type is: Firebird')
        elif Azure:
            print('Database type is: Azure')
        elif SqlCe:
            print('Database type is: SqlCe')
        elif VistaDb:
            print('Database type is: VistaDb')
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
