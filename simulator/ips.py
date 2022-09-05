import random
import urllib.request, json
from datetime import datetime
import time
from faker import Faker
import yaml
import sys
import pprint
from loader import MessageGenerator
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
cisa_url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

class ProtoBuf:
    '''
    This models a proto buf simple payload
    '''
    def __init__(self,**kwargs):
        self._attributes = kwargs

    def get_field(self,name):
        if name in self._attributes:
            return self._attributes[name]
        else:
            raise Exception('Field is missing')
    def get_fields(self):
        return self._attributes.keys()

    def __str__(self):
        return str(self._attributes)

DB_URL = "typedb.westeurope.cloudapp.azure.com:1729"
DB_NAME = "omnibuscyber"
import argparse

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--reset", help="reset the database",action="store_true")
    parser.add_argument("--eps", help="events per second", default=1,type=int)
    parser.add_argument("--total", help="total events", default=1, type=int)

    args = parser.parse_args()

    # Read YAML file
    with open("config.yaml", 'r') as stream:
        config_data = yaml.safe_load(stream)
        folder = Path(__file__).parent.parent.joinpath('schema')
        mg = MessageGenerator(uri=DB_URL,database=DB_NAME,schema_folder=folder,reset=args.reset)
        mg.set_mapping(config_data)

    if args.eps > 0:
        with urllib.request.urlopen(cisa_url) as url:
            data = json.loads(url.read().decode())
            logger.info(f"Total vulnerabilities {data['count']}")

            # pick a vulnerability from 2022
            vulns = data['vulnerabilities']

            cves = [v['cveID'] for v in vulns if v['cveID'].startswith('CVE-2022')]

            rand_cves = random.choices(cves, k=10)
            running = True
            past = datetime.now()

            fake = Faker()
            Faker.seed(0)

            totals = 0
            logger.info(f'Begin simulation loop with eps = {args.eps}')
            while running:
                now = datetime.now()
                delta_sec = (now - past).total_seconds()
                if delta_sec > 1:
                    logger.info(f'Step {now}')
                    events = []
                    for x in range(1,args.eps+1):
                        ips_event = ProtoBuf(hostname=fake.hostname(0),cve=random.choices(cves, k=1)[0],count=random.randint(1,100),timestamp=now)
                        events.append(ips_event)
                    mg.generate_queries(events)
                    totals += len(events)
                if totals>=args.total: running = False
                past = now
                time.sleep(1)

            logger.info(f'Done simulation loop {totals}')