import logging
from typedb.client import *
from typedb_query_builder.typedb_query_builder import TypeDBQueryBuilder
import random
import string
import re
from pathlib import Path
import os
import yaml

# create and configure main logger
logger = logging.getLogger(__name__)

class MessageGenerator:

    def __init__(self, uri, database='omnitest',schema_folder=Path(__file__).parent,reset=False):
        self._client = TypeDB.core_client(uri)
        self._database = database

        if reset: self._client.databases().get(database).delete()

        if self._client.databases().contains(database):
            self.create_schema(schema_folder)

        else:
            self._client.databases().create(database)
            self.create_schema(schema_folder)

    def create_schema(self,schema_folder:Path):

        # Read YAML file
        with open(schema_folder.joinpath('order.yaml'), 'r') as stream:
            list_tql = yaml.safe_load(stream)

            with self._client.session(self._database, SessionType.SCHEMA) as session:
                for file_name in list_tql['base']:
                    with open(os.path.join(schema_folder,file_name), 'r') as schema:
                        define_query = schema.read()
                        with session.transaction(TransactionType.WRITE) as transaction:
                            transaction.query().define(define_query)
                            transaction.commit()
                            logger.info(f"Loaded {file_name} into {self._database}")

                for file_name in list_tql['extensions']:
                    with open(os.path.join(schema_folder,file_name), 'r') as schema:
                        define_query = schema.read()
                        with session.transaction(TransactionType.WRITE) as transaction:
                            transaction.query().define(define_query)
                            transaction.commit()
                            logger.info(f"Loaded {file_name} into {self._database}")

    def set_mapping(self,mapping):
        self._mapping = mapping
        self.load_schemas()

    def escape_string(self,string_text):
        return re.sub('\W+', ' ', string_text)
        #return re.sub('[A-Za-z0-9\s]+','', string_text)

    def load_schemas(self):
        with self._client.session(self._database, SessionType.SCHEMA) as session:
            with session.transaction(TransactionType.READ) as tx:
                entities = set()
                for field in self._mapping['entities']:
                    atom = self._mapping['entities'][field]
                    entities.add(atom['entity'])

                self._schema = {}
                for entity_type in entities:
                    entity_prop  = {}
                    for value_type in ['string','long','boolean','datetime']:
                        q_att = f'match $s type {entity_type}, owns $a;\
                        $a sub attribute, value {value_type};\
                        get $s,$a;'

                        for a in tx.query().match(q_att):
                            attr= a.map().get("a").get_label()
                            entity_prop[str(attr)]=value_type

                    self._schema[entity_type] = entity_prop
                logger.info(f"Loaded {len(self._schema)} entities from config mappings")

                relations = set()
                for field in self._mapping['relations']:
                    atom = self._mapping['relations'][field]
                    relations.add(atom['relation'])

                for relation_type in relations:
                    entity_prop  = {}
                    for value_type in ['string','long','boolean','datetime']:
                        q_att = f'match $s type {relation_type}, owns $a;\
                        $a sub attribute, value {value_type};\
                        get $s,$a;'

                        for a in tx.query().match(q_att):
                            attr= a.map().get("a").get_label()
                            entity_prop[str(attr)]=value_type

                    self._schema[relation_type] = entity_prop

    def check_var(self,name:str,var_list:list):
        if name not in var_list:
            return name
        else:
            new_var = name + str(random.randint(0, 9))
            return self.check_var(new_var,var_list)

    def generate_queries(self,messages=[]):
        total_inserts = 0

        for message in messages:
            tqb = TypeDBQueryBuilder()
            queries = {}
            vars = []
            for field in message.get_fields():
                if field in self._mapping['entities']:
                    atom = self._mapping['entities'][field]
                    # load schema properties
                    property_types = self._schema[atom['entity']]
                    if atom['entity'] in queries:
                        old_ql = queries[atom['entity']]
                        old_ql.has(atom[field], message.get_field(field),property_types[atom['attribute']])
                        queries[atom['entity']] = old_ql
                    else:
                        var_name = self.check_var(atom['entity'][0],vars)

                        insert_ql = tqb.insert_entity(atom['entity'], var_name)

                        insert_ql.has(atom['attribute'], message.get_field(field),property_types[atom['attribute']])
                        queries[atom['entity']] = insert_ql

                        vars.append(var_name)

                if field in self._mapping['relations']:
                    atom = self._mapping['relations'][field]

                    var_name = self.check_var(atom['relation'][0], vars)

                    insert_rel = tqb.insert_relationship(atom['relation'], var_name)
                    # recover the variables now
                    for role in atom['roles']:
                        # need to find the original variable ...
                        insert_rel.relates(atom['roles'][role], queries[role])
                    # load schema properties
                    relation_types = self._schema[atom['relation']]

                    prop_type = relation_types[atom['attribute']]
                    if prop_type == 'datetime':
                        #TODO: needs a fix in the building library sadly .... for now workaround
                        tstamp = message.get_field(field).replace(microsecond=0).isoformat()
                        insert_rel.has(atom['attribute'], tstamp,"long")
                    else:
                        insert_rel.has(atom['attribute'], tstamp, prop_type)

                    vars.append(var_name)
                    queries[atom['relation']] = insert_rel

            with self._client.session(self._database, SessionType.DATA) as session:
                with session.transaction(TransactionType.WRITE) as tx:
                    tqb.compile_query()
                    final_query = tqb.get_query()  # Get query
                    logger.debug(final_query)
                    insert_iterator = tx.query().insert(final_query)

                    for v in vars:
                        concepts = [ans.get(v) for ans in insert_iterator]
                        total_inserts += len(concepts)

                    tx.commit()

        logger.debug(f'Total inserted objects {total_inserts}')

        return total_inserts