from charm.toolbox.pairinggroup import PairingGroup
from base64 import b64encode, b64decode
import json, ast

def byte_to_base64(byte_str, code='utf-8'):
	return b64encode(byte_str).decode(code)

def base64_to_byte(base64_str, code='utf-8'):
	return b64decode(base64_str.encode(code))

def groupE_to_base64(groupE, groupObj, code='utf-8'):
	for name, value in groupE.items():
		if type(value) == type(groupObj.random()):
			temp = groupObj.serialize(value)
			groupE[name] = byte_to_base64(temp)
		elif type(value) == type({}):
			groupE[name] = groupE_to_base64(value, groupObj)
		elif type(value) == type([]):
			value = value.copy()
			if type(value[0]) == type(groupObj.random()):
				for i in range(len(value)):
					value[i] = byte_to_base64(groupObj.serialize(value[i]))
			groupE[name] = ' '.join(value)
		elif type(value) == type(""):
			pass
		else:
			raise TypeError("Check the type of ciphertext's values...")

	groupE_str = json.dumps(groupE)
	return byte_to_base64(groupE_str.encode(code))

def base64_to_groupE(base64_str, groupObj, code='utf-8'):
	GE_str = base64_to_byte(base64_str).decode(code)
	groupE = ast.literal_eval(GE_str)
	isSearchToken = False
	for name, value in groupE.items():
		if name == "E3":
			groupE[name] = base64_to_groupE(value, groupObj)
		elif name == "attributes":
			groupE[name] = value.split()
		elif name == "policy":
			isSearchToken = True
		else:
			if isSearchToken:
				groupE[name] = value.split()
				for i in range(len(groupE[name])):
					groupE[name][i] = groupObj.deserialize(base64_to_byte(groupE[name][i]))
			else:
				groupE[name] = groupObj.deserialize(base64_to_byte(value))
	return groupE

def write_json(file, jsondata=None, mix=False):
	if mix:
		json_string = json.dumps(jsondata)
		with open(file, "w") as f:
			f.write(byte_to_base64(json_string.encode('utf-8')))
		f.close()
	else:
		with open(file, "w") as f:
			json.dump(jsondata, f)
		f.close()

def read_json(file, mix=False):
	if mix:
		with open(file, "r") as f:
			data = base64_to_byte(f.read()).decode('utf-8')
		f.close()
		return ast.literal_eval(data)
	else:
		with open(file) as f:
			data = json.load(f)
		f.close()
		return data
