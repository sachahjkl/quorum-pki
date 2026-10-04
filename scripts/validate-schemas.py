#!/usr/bin/env python3
"""Validate generated schemas and fixtures using JSON Schema 2020-12.
Optional development dependency: pip install jsonschema (not used by Go binaries).
"""
import json,pathlib
try:
 import jsonschema
 from referencing import Registry,Resource
except ImportError:
 raise SystemExit('Install the optional dev dependency: python3 -m pip install jsonschema')
root=pathlib.Path(__file__).resolve().parents[1];reg=Registry()
for f in (root/'schemas').glob('*.json'):
 s=json.loads(f.read_text());jsonschema.Draft202012Validator.check_schema(s);reg=reg.with_resource(s['$id'],Resource.from_contents(s))
for typ in ['bundle','config']:
 s=json.loads((root/'schemas'/f'{typ}.schema.json').read_text());data=json.loads((root/'results'/'fixture'/f'{typ}.json').read_text());v=jsonschema.Draft202012Validator(s,registry=reg);v.validate(data)
 data['unexpected']=True
 try:v.validate(data)
 except jsonschema.ValidationError:pass
 else:raise AssertionError('additional properties were accepted')
print('PASS schema metaschemas, signed fixtures and extra-member rejection')
