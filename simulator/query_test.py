from typedb_query_builder.typedb_query_builder import TypeDBQueryBuilder

tqb = TypeDBQueryBuilder()

c = tqb.insert_entity("cve_record_4",'c')
c.has("id","CVE-2022-123")
c.has("title","ciao")

h = tqb.insert_entity("host",'h')
h.has("hostname","ciao")

r = tqb.insert_relationship("has_source","r")
r.relates("origin",h)
r.relates("cve",c)
tqb.compile_query()                                         # Compile query
query = tqb.get_query()                                     # Get query

print(query)