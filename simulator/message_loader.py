import logging
from typedb.client import *
from typedb_query_builder.typedb_query_builder import TypeDBQueryBuilder

import re

class MessageGenerator:

    def __init__(self, uri, database='omnitest',reset=False):
        self._client = TypeDB.core_client(uri)
        self.database = database

        if self._client.databases().contains(database):
            #self.load_schema()
            pass
        else:
            raise Exception('Database is not initialized')

    def set_mapping(self,mapping):
        self._mapping = mapping

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

    def generate_queries(self,messages=[]):

        for message in messages:
            tqb = TypeDBQueryBuilder()
            prop_dict = self._mapping['message']
            queries = {}
            vars = []
            for field in message.get_fields():
                if field in self._mapping['message']:
                    atom = self._mapping['message'][field]

                    if atom['entity'] in queries:
                        old_ql = queries[atom['entity']]
                        old_ql.has(atom[field], message[field])
                        queries[atom['entity']] = old_ql
                    else:
                        #var is first letter + number
                        var_name = atom['entity'][0]
                        if var_name in vars:
                            var_name = var_name + '1'

                        insert_ql = tqb.insert_entity(atom['entity'], var_name)

                        insert_ql.has(atom['attribute'], message.get_field(field))
                        queries[atom['entity']] = insert_ql

            with self._client.session(self.database, SessionType.DATA) as session:
                with session.transaction(TransactionType.WRITE) as tx:
                    tqb.compile_query()
                    final_query = tqb.get_query()  # Get query
                    insert_iterator = tx.query().insert(final_query)

                    tx.commit()

                    print(f'Total entities {len(queries)}')

        return