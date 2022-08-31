import random
import urllib.request, json
from datetime import datetime
import time
from faker import Faker
import yaml
import sys
import pprint
from message_loader import MessageGenerator

cisa_url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

class IpsProto:
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

if __name__ == "__main__":

    # Read YAML file
    with open("config.yaml", 'r') as stream:
        config_data = yaml.safe_load(stream)
        pprint.pprint(config_data)
        mg = MessageGenerator(uri=DB_URL,database='omnibuscyber')
        mg.set_mapping(config_data)

    with urllib.request.urlopen(cisa_url) as url:
        data = json.loads(url.read().decode())
        print(f"Total vulnerabilities {data['count']}")

        # pick a vulnerability from 2022
        vulns = data['vulnerabilities']

        cves = [v['cveID'] for v in vulns if v['cveID'].startswith('CVE-2022')]

        rand_cves = random.choices(cves, k=10)
        running = True
        past = datetime.now()

        fake = Faker()
        Faker.seed(0)

        while running:
            now = datetime.now()
            delta_sec = (now - past).total_seconds()
            if delta_sec > 1:
                ips_event = IpsProto(hostname=fake.hostname(0),cve=random.choices(cves, k=1)[0],count=random.randint(1,100))
                mg.generate_queries([ips_event])
                print(ips_event)
            past = now
            time.sleep(1)

