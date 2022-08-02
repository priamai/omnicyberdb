import unittest
from typedb.client import TypeDB, SessionType, TransactionType
import sys

if sys.version_info[0] >= 3:
    from urllib.request import urlretrieve
else:
    # Not Python 3 - today, it is most likely to be Python 2
    # But note that this might need an update when Python 4
    # might be around one day
    from urllib import urlretrieve

import gzip
import csv
import os
from .config import DB_URL,DB_NAME

from omnicyberdb.tools.loader import Loader
from omnicyberdb.tools.cve import CveInsertGenerator
from pathlib import Path


import logging

logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)

# create and configure main logger
logger = logging.getLogger(__name__)

class TestCVE(unittest.TestCase):
    def setUp(self):

        self._client = Loader(uri=DB_URL,database=DB_NAME)

        top_path = Path(__file__).parent.parent.absolute()
        schema_path = Path.joinpath(top_path, "schema")
        self._client.create_schema(schema_path)

    def test_one_cve(self):
        example_cve = {'name':'CVE-2021-44832',
                       'status':'Candidate',
                       'description':'Description with "escaped" strings',
                       'references':'CISCO:20211210 Vulnerabilities in Apache Log4j Library Affecting Cisco Products: December 2021\n',
                       'phase':'Assigned (20211211)',
                       'votes':"None (candidate not yet proposed)",
                       'comments':'Any comments here'}

        cve = CveInsertGenerator(uri=DB_URL, database=DB_NAME, reset=False)
        cve.load_schema()

        queries = cve.generate_queries(cve_list=[example_cve])

        self.assertTrue(len(queries)==1,'Query generated')

    def test_cve_from_csv(self):

        cve = CveInsertGenerator(uri=DB_URL, database=DB_NAME, reset=False)
        cve.load_schema()

        if os.path.exists("allitems.csv.gz")==False:
            urlretrieve("https://cve.mitre.org/data/downloads/allitems.csv.gz", "allitems.csv.gz")

        with gzip.open("allitems.csv.gz", "rt", encoding='Latin1') as file:
            reader = csv.reader(file)
            #thi is is row number 3
            columns = ['Name', 'Status', 'Description', 'References', 'Phase', 'Votes', 'Comments']

            attributes = [x.lower() for x in columns]
            start = False
            all_cve = []

            for row in reader:
                if start == True:
                    self.assertEqual(len(row),len(columns))
                    cve_dict = dict(zip(attributes, row))
                    all_cve.append(cve_dict)
                elif start == False:
                    start = all(len(s) == 0 for s in row)

            logger.debug(f'Loaded {len(all_cve)} cve')

            self.assertGreater(len(all_cve),242000)

            queries = cve.generate_queries(cve_list=all_cve)

            self.assertEqual(len(all_cve), len(queries))

            self._client.insert(queries=queries)

            # check count
            inserted = self._client.get_count(entity_type='cve')

            logger.debug(f'Inserted {inserted} cve')

            self.assertEqual(len(queries), inserted)

    @unittest.skip("reason for skipping")
    def count_check(self):
        with self._session.transaction(TransactionType.WRITE) as transaction:
            total = transaction.query().match_aggregate("match $x isa cve_record; get $x; count;").get().as_int()

    def tearDown(self):
        logger.debug("Deleted the " + DB_NAME + " database")
        self._client.delete()
        logger.debug("Closed " + DB_NAME + " database")
        self._client.close()


if __name__ == '__main__':
    unittest.main()