import logging
from typedb.client import *
from .loader import Loader

import re

class CveInsertGenerator:

    def __init__(self, uri, database='omnitest',reset=False):
        self._client = TypeDB.core_client(uri)
        self.database = database

        if self._client.databases().contains(database):
            self.load_schema()
        else:
            raise Exception('Database is not initialized')

    def escape_string(self,string_text):
        return re.sub('\W+', ' ', string_text)
        #return re.sub('[A-Za-z0-9\s]+','', string_text)

    def load_schema(self,entity_type='cve'):
        with self._client.session(self.database, SessionType.SCHEMA) as session:
            with session.transaction(TransactionType.READ) as tx:

                self._schema = {}

                for value_type in ['string','long','boolean','datetime']:
                    q_att = f'match $s type {entity_type}, owns $a;\
                    $a sub attribute, value {value_type};\
                    get $s,$a;'

                    for a in tx.query().match(q_att):
                        attr= a.map().get("a").get_label()
                        self._schema[str(attr)]=value_type

    def generate_queries(self,entity_type='cve',cve_list=[]):

        queries = []
        head_query = 'insert $cve isa cve,'
        for cve_dict in cve_list:
            props = []
            for attr_name in self._schema:
                if attr_name in cve_dict:
                    if self._schema[attr_name] == 'string':
                        value = self.escape_string(cve_dict[attr_name])
                        props.append(f'has {attr_name} "{value}"')

            if len(props)>0:
                query = head_query + ','.join(props) + ';'
                queries.append(query)

        logging.debug(f"Generated {len(queries)} insert queries for CVE")
        return queries


if __name__ == '__main__':
    cve = CveInsertGenerator(uri='192.168.2.17:1729',database='omnitest',reset=True)
    cve.load_schema()
    test_cves = [{'name':'ciao','description':' hello "escaped"'},{'name':'miao','description':' a "b" c !!! ///\"'}]
    print(cve._schema)

    queries = cve.generate_queries(cve_list=test_cves)
    print(queries)