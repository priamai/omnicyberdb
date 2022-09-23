from pathlib import Path
from typedb.client import *
from typedb_query_builder.typedb_query_builder import TypeDBQueryBuilder
import requests
import logging
from sources import CveMitreSource,CweMitreSource
import re

# create and configure main logger
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Enricher:

    def __init__(self, uri, database='omnitest',schema_folder=Path(__file__).parent,reset=False):
        self._client = TypeDB.core_client(uri)
        self._database = database

    def autoload(self,entities  = ['cve_record_4']):
        '''
        Should list all the entities first and then see what enrichments we have...

        :param entities:
        :return:
        '''

        queries = []

        with self._client.session(self._database, SessionType.DATA) as session:
            for entity in entities:
                with session.transaction(TransactionType.READ) as rx:
                    if entity == 'cve_record_4':
                        cve_src = CveMitreSource()

                        query = f'match $x isa {entity}, has attribute $id; get $id;'

                        for a in rx.query().match(query):
                            cve_id = a.map().get('id')._value
                            try:
                                logger.info(f"Found CVE {cve_id}")
                                data = cve_src.get_cve(cve_id)
                                tql = cve_src.tql_versions(data)
                                if tql: queries.append(tql)
                            except Exception as e:
                                logger.error(e)

                    elif entity == 'problemtype':
                        cwe_src = CweMitreSource()

                        query = f'match $x isa cve_problemtype, has attribute $val; get $val;'

                        for a in rx.query().match(query):
                            value = a.map().get('val')._value

                            found = re.findall("CWE\-(\d+)", value)
                            for cweid in found:
                                logger.info(cweid)
                                cwe_info = cwe_src.get_cwe(cweid)
                                if cwe_info:
                                    logger.info(cwe_info['Name'])
                                    logger.info(cwe_info['Weakness Abstraction'])
                                else:
                                    logger.warning("CWE not found!")
        with self._client.session(self._database, SessionType.DATA) as session:

            for tql in queries:
                with session.transaction(TransactionType.WRITE) as tx:
                    try:
                        tx.query().insert(tql)
                        tx.commit()
                    except Exception as e:
                        logger.error(e)

import argparse
import db

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--reset", help="delete all properties before enriching",action="store_true")
    parser.add_argument("--entities", help="which entity to enrich", nargs='+', default=["problemtype"])

    args = parser.parse_args()

    e = Enricher(uri=db.DB_URL,database=db.DB_NAME)
    e.autoload(args.entities)