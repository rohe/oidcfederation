#!/usr/bin/env python3
# 2.1
import json

from cryptojwt.jwt import utc_time_sans_frac
from fedservice import apply_policy
from fedservice import combine_policy
from fedservice.message import EntityStatement
from fedservice.message import FederationEntity
from fedservice.message import MetadataPolicy
from fedservice.message import TrustMark
from oidcmsg.oidc import ProviderConfigurationResponse
from oidcmsg.oidc import RegistrationRequest
from oidcmsg.oidc import RegistrationResponse

txt = open("2.1.json").read()

es = EntityStatement().from_json(txt)

now = utc_time_sans_frac()
es['iat'] = now
es['exp'] = now+3600

print("2.1", es.verify())


# 3.6

txt = open("3.6.json").read()

fe = FederationEntity().from_json(txt)

print("3.6", fe.verify())

# 4.1.3.1

pol_1 = open("4.1.3.1_1.json").read()

mp_1 = MetadataPolicy().from_json(pol_1)

print("4.1.3.1_1", mp_1.verify())

pol_2 = open("4.1.3.1_2.json").read()

mp_2 = MetadataPolicy().from_json(pol_2)

print("4.1.3.1_2", mp_2.verify())

comb_policy = MetadataPolicy(**combine_policy(mp_1, mp_2))
print(json.dumps(comb_policy.to_dict(), indent=4, sort_keys=True))

comb = open("4.1.3.1_comb.json").read()

comb = MetadataPolicy().from_json(comb)

print("=", comb_policy.to_dict() == comb.to_dict())
print("comb", comb_policy.verify())

# ============== 4.1.6 ==================
print("-"*20, "4.1.6", "-"*20)
fed_pol = open("4.1.6_fed_policy.json").read()
mp_fed = MetadataPolicy().from_json(fed_pol)
print("4.1.6_fed_policy.json", mp_fed.verify())

org_pol = open("4.1.6_org_policy.json").read()
mp_org = MetadataPolicy().from_json(org_pol)
print("4.1.6_org_policy.json", mp_org.verify())

comb_policy = MetadataPolicy(**combine_policy(mp_fed, mp_org))
print("comb", comb_policy.verify())

metadata = open("4.1.6_metadata.json").read()
md = RegistrationResponse().from_json(metadata)
print("4.1.6_metadata.json", mp_org.verify())

# apply policy

res = apply_policy(md, comb_policy)
res_md = RegistrationResponse(**res)

print(json.dumps(res_md.to_dict(), indent=4, sort_keys=True))
print('=', md.to_dict() == res_md.to_dict())

# ============== 4.3.3 ==================
print("-"*20, "4.3.3", "-"*20)

for item in ['4.3.3_1.json', '4.3.3_2.json']:
    data = open(item).read()
    tm = TrustMark().from_json(data)
    print(item, tm.verify())

# ============== 5.2 ==================
print("-"*20, "5.2", "-"*20)

txt = open("5.2.json").read()

es = EntityStatement().from_json(txt)

now = utc_time_sans_frac()
es['iat'] = now
es['exp'] = now+3600

print("5.2", es.verify())

# ============== 6.1.2 ==================
print("-"*20, "6.1.2", "-"*20)

txt = open("6.1.2.json").read()

es = EntityStatement().from_json(txt)

now = utc_time_sans_frac()
es['iat'] = now
es['exp'] = now+3600

print("6.1.2", es.verify())

# ============== 6.2.2 ==================
sec = "6.2.2"
print("-"*20, sec, "-"*20)

txt = open("{}.json".format(sec)).read()

ps = ProviderConfigurationResponse().from_json(txt)

if 'iat' in ps or 'exp' in ps:
    now = utc_time_sans_frac()
    es['iat'] = now
    es['exp'] = now+3600

print(sec, es.verify())

# ============== A.1.* ==================
for sec in ['A.1.1', 'A.1.2', 'A.1.3', 'A.1.4', 'A.1.5', 'A.1.6', 'A.1.7']:
    print("-"*20, sec, "-"*20)

    txt = open("{}.json".format(sec)).read()

    es = EntityStatement().from_json(txt)

    now = utc_time_sans_frac()
    es['iat'] = now
    es['exp'] = now+3600

    print(sec, es.verify())

# ============== A.1.8 ==================

metadata = open("A.1.1.json".format(sec)).read()
es = EntityStatement()
es.from_json(metadata)

org = open("A.1.3.json".format(sec)).read()
org_es = EntityStatement().from_json(org)

fed = open("A.1.5.json".format(sec)).read()
fed_es = EntityStatement().from_json(fed)

comb_policy = MetadataPolicy(**combine_policy(fed_es['metadata_policy']['openid_provider'],
                                              org_es['metadata_policy']['openid_provider']))
print("comb", comb_policy.verify())

# apply policy

res = apply_policy(es['metadata']["openid_provider"], comb_policy)
res_pcr = ProviderConfigurationResponse(**res)
print("provider config", res_pcr.verify())

fp = open('a.1.8_res.json', 'w')
fp.write(json.dumps(res_pcr.to_dict(), indent=2, sort_keys=True))
fp.close()

# ============== A.2.1.2 ==================

metadata = open("A.2.1.2_3.json".format(sec)).read()
reg_req = RegistrationRequest()
reg_req.from_json(metadata)

org = open("A.2.1.2_1.json".format(sec)).read()
org_es = MetadataPolicy().from_json(org)

fed = open("A.2.1.2_2.json".format(sec)).read()
fed_es = MetadataPolicy().from_json(fed)

comb_policy = MetadataPolicy(**combine_policy(fed_es['openid_relying_party'],
                                              org_es['openid_relying_party']))
print("comb", comb_policy.verify())

# apply policy

res = apply_policy(reg_req, comb_policy)
rr = RegistrationRequest(**res)
print("Client registration request", rr.verify())

fp = open('a.2.1.2_4_res.json', 'w')
fp.write(json.dumps(rr.to_dict(), indent=2, sort_keys=True))
fp.close()

# ============== A.2.2 ==================

pol = open("A.2.2_1.json".format(sec)).read()
op_pol = MetadataPolicy().from_json(pol)

res2 = apply_policy(rr, op_pol["openid_relying_party"])
rr2 = RegistrationRequest(**res2)
print("Client registration request", rr2.verify())

fp = open('a.2.2_2_res.json', 'w')
fp.write(json.dumps(rr2.to_dict(), indent=2, sort_keys=True))
fp.close()
