import logging
from functools import partial
from multiprocessing.dummy import Pool as ThreadPool
from timeit import default_timer as timer
from pathlib import Path
from typedb.client import *
import os

# create and configure main logger
logger = logging.getLogger(__name__)

class Loader:

    def __init__(self, uri, database, batch_size=50, num_threads=16):
        self.database = database
        self.batch_size = batch_size
        self.num_threads = num_threads
        self.client = TypeDB.core_client(uri)

        if self.client.databases().contains(self.database)==False:
            self.client.databases().create(self.database)

    def create_schema(self,schema_folder):
        with self.client.session(self.database, SessionType.SCHEMA) as session:
            for tql_file in Path(schema_folder).glob('**/*.tql'):
                if tql_file.name == '011_cve.tql':
                    with open(os.path.join(schema_folder,'011_cve.tql'), 'r') as schema:
                        define_query = schema.read()
                        logger.debug(f"Writing schema {tql_file.name}")
                        with session.transaction(TransactionType.WRITE) as transaction:
                            transaction.query().define(define_query)
                            transaction.commit()
                            logger.info("Loaded the " + self.database + " schema")

    def get_count(self,entity_type='thing'):
        with self.client.session(self.database, SessionType.DATA) as session:
            with session.transaction(TransactionType.READ) as tx:
                return tx.query().match_aggregate(f"match $x isa {entity_type}; count;").get().as_int()

    def insert(self, queries):
        start = timer()
        batch = []
        batches = []
        logger.debug(f"Inserting {len(queries)} queries...")
        for q in queries:
            batch.append(q)
            if len(batch) == self.batch_size:
                batches.append(batch)
                batch = []

        batches.append(batch)

        with self.client.session(self.database, SessionType.DATA) as session:
            pool = ThreadPool(self.num_threads)
            pool.map(partial(self._insert_query_batch, session), batches)
            pool.close()
            pool.join()
        end = timer()
        logger.debug(f"Inserted {len(queries)} in {end - start} seconds")

    def _insert_query_batch(self, session, batch):
        with session.transaction(TransactionType.WRITE) as tx:
            for query in batch:
                tx.query().insert(query)
            tx.commit()

    def delete(self):
        if self.client.databases().contains(self.database):
            self.client.databases().get(self.database).delete()

    def close(self):
        logger.debug("Closing database")
        self.client.close()