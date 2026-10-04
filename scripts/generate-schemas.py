#!/usr/bin/env python3
"""Generate the strict wire schemas. No crypto or runtime dependencies."""
import json,pathlib
root=pathlib.Path(__file__).resolve().parents[1]/'schemas'
S=lambda **kw:dict(type='string',**kw)
I=lambda minimum=0,maximum=9007199254740991:dict(type='integer',minimum=minimum,maximum=maximum)
R=lambda n:{'$ref':n+'.schema.json'}
A=lambda item,**kw:dict(type='array',items=item,**kw)
O=lambda props:dict(type='object',properties=props,required=list(props),additionalProperties=False)
H=S(pattern='^[0-9a-f]{64}$');PH=S(pattern='^([0-9a-f]{64})?$')
K=S(pattern='^[A-Za-z0-9_-]{43}$');B=S(pattern='^[A-Za-z0-9_-]*$')
D=S(pattern='^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$',maxLength=253)
schemas={}
schemas['signature']=O({'protected':S(pattern='^[A-Za-z0-9_-]+$'),'signature':S(pattern='^[A-Za-z0-9_-]{86}$')})
schemas['member']=O({'id':S(pattern='^[a-z0-9-]+$'),'key':K,'root':S(pattern='^[A-Za-z0-9_-]+$'),'url':S(pattern='^[\\x20-\\x7e]*$')})
schemas['config']=O({'version':{'const':1},'epoch':I(1),'logId':S(minLength=1),'approvalQuorum':I(1,100),'finalityQuorum':I(1,100),'maxByzantine':I(0,99),'members':A(R('member'),minItems=1,maxItems=100)})
schemas['proposal']=O({'version':{'const':1},'epoch':I(1),'configHash':H,'event':{'enum':['issue','rotate','recover','revoke','heartbeat']},'subject':D,'key':S(pattern='^([A-Za-z0-9_-]{43})?$'),'generation':I(1),'previous':PH,'activate':I(),'retire':I(),'expires':I(),'nonce':S(minLength=16,maxLength=128,pattern='^[\\x20-\\x7e]+$')})
schemas['proposal']['allOf']=[{'if':{'properties':{'event':{'enum':['revoke','heartbeat']}}},'then':{'properties':{'key':{'const':''}}},'else':{'properties':{'key':K}}}]
schemas['request']=O({'proposal':R('proposal'),'owner':R('signature'),'recovery':{'type':'boolean'}})
schemas['approval']=O({'operator':S(pattern='^ca-[0-9]+$'),'certificate':B,'vote':R('signature')})
schemas['entry']=O({'version':{'const':1},'sequence':I(1),'timestamp':I(),'previous':PH,'proposal':R('proposal'),'approvals':A(R('approval'),minItems=1,maxItems=100)})
schemas['state']=O({'subject':D,'generation':I(1),'entryHash':H,'key':K,'oldKey':S(pattern='^([A-Za-z0-9_-]{43})?$'),'activate':I(),'retire':I(),'expires':I(),'revoked':{'type':'boolean'}})
schemas['head']=O({'version':{'const':1},'epoch':I(1),'configHash':H,'logId':S(minLength=1),'size':I(),'root':H,'stateRoot':H,'timestamp':I(),'previous':PH})
schemas['checkpoint']=O({'head':R('head'),'votes':A(R('signature'),maxItems=100)})
schemas['candidate']=O({'entries':A(R('entry'),minItems=1),'parent':R('checkpoint'),'head':R('head')})
schemas['bundle']=O({'entry':R('entry'),'checkpoint':R('checkpoint'),'inclusion':A(H),'state':R('state'),'stateIndex':I(),'stateCount':I(1),'stateProof':A(H),'consistency':A(H)})
schemas['stored']=O({'entries':A(R('entry')),'checkpoints':A(R('checkpoint'))})
schemas['simulation']=O({'validators':I(1,100),'quorum':I(1,100),'finality':I(1,100),'byzantine':I(0,99),'seed':I(-9007199254740991),'minLatencyMs':I(0,10000),'maxLatencyMs':I(0,10000),'failurePercent':I(0,100),'maliciousValidators':A(S()),'unavailableValidators':A(S()),'badSignatureValidators':A(S()),'refuseValidators':A(S()),'networkPartitions':A(S()),'realtime':{'type':'boolean'}})
schemas['event']=O({'kind':S(),'operator':S(),'subject':S(),'message':S(),'count':I(),'required':I(),'head':{'anyOf':[R('head'),{'type':'null'}]},'time':I()})
for n,s in schemas.items():
 s={'$schema':'https://json-schema.org/draft/2020-12/schema','$id':'https://quorum-pki.invalid/schemas/'+n+'.schema.json',**s}
 (root/(n+'.schema.json')).write_text(json.dumps(s,indent=2)+'\n')
