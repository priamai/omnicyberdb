import requests, zipfile, io
from typedb_query_builder.typedb_query_builder import TypeDBQueryBuilder
import csv
from io import TextIOWrapper, BytesIO
import logging
logger = logging.getLogger(__name__)

class CweMitreSource():
    _url = 'https://cwe.mitre.org/data/csv/699.csv.zip'

    def __init__(self):
        r = requests.get(self._url)
        self._cwes = []
        zipObj = zipfile.ZipFile(io.BytesIO(r.content))
        # Get list of ZipInfo objects
        listOfiles = zipObj.infolist()
        # Iterate of over the list of ZipInfo objects & access members of the object
        for elem in listOfiles:
            with zipObj.open(elem.filename) as csvfile:
                self._reader = csv.DictReader(TextIOWrapper(csvfile, 'utf-8'), delimiter=',')
                count = 0
                for line in self._reader:
                    self._cwes.append(line)
                    count += 1
                logger.info(f'Loaded {count} CWEs')


    def get_cwe(self,cwe_id:str):
        for row in self._cwes:
            if row['CWE-ID'] == cwe_id.upper():
                return row
        return None

class CveMitreSource():
    _url = 'https://www.cve.org/'
    _headers = {"user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36",
                'accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'}
    def __init__(self):
        self._session = requests.Session()
        self._session.headers.update(self._headers)
        r = self._session.get(self._url)

    def get_cve(self,cve_id:str):
        '''
        Schemas are available here for each version: https://github.com/CVEProject/cve-schema/blob/master/schema/v4.0/CVE_JSON_4.0_min_public.schema

        :param cve_id:
        :return:
        '''
        params = {'action':'getCveById','cveId':cve_id}
        r = self._session.get(self._url+'api/',params=params)

        if r.status_code == 200:
            return r.json()
        else:
            raise Exception(f'Status error {r.status_code}')

    def tql_versions(self,cve_dict:dict):
        if 'data_version' in cve_dict:
            cve_format = cve_dict['data_version']
            if cve_format=='4.0':
                tqb = TypeDBQueryBuilder()
                c = tqb.insert_entity(f"cve_record_{cve_format[0]}", 'cve')

                meta = cve_dict['CVE_data_meta']
                c.has("id", meta['ID'])

                if 'ASSIGNER' in meta: c.has("assigner", meta['ASSIGNER'])
                if 'STATE' in meta: c.has("state", cve_dict['CVE_data_meta']['STATE'])
                if 'TITLE' in meta: c.has("title", cve_dict['CVE_data_meta']['TITLE'])

                for idx, problem in enumerate(cve_dict['problemtype']['problemtype_data']):
                    problem_i = tqb.insert_entity("cve_problemtype", f'pbm{idx}')
                    problem_i.has("lang", problem['description'][0]['lang'])
                    problem_i.has("val", problem['description'][0]['value'])

                    problems_rel = tqb.insert_relationship('has_problems', f'pbmr{idx}')
                    problems_rel.relates('cve', c)  # Add related entities
                    problems_rel.relates('problemtype', problem_i)

                tqb.compile_query()  # Compile query
                query = tqb.get_query()  # Get query
                return query
            else:
                raise Exception(f'CVE format {cve_format} not supported yet')
