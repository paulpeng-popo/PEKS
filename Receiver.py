from argparse import ArgumentParser
from PEKS.Symcrypt import *
from PEKS.Scheme import *
from os import listdir

GroupCurve = "MNT224"
KeysFile = "Server_keys"

def main(debug=False):
	# ======= set up eliptic curve parameters =======
	groupObj = PairingGroup(GroupCurve)
	kpabe = KPabe(groupObj, debug)
	try:
		(msk, pk) = kpabe.import_keys(KeysFile)
		if debug:
			print("\nmsk:\n", msk)
			print("\npk:\n", pk)
	except Exception:
		print("\nFile: \"%s\" notfound.\n" % KeysFile)
		exit(1)

	# ======= policy creation =======
	# policy = input("\nSearch policy: { available operator:(, ), and, or }\n")
	policy = input("\nSearch attributes: { always OR }\n")
	peko = policy[:3]
	if peko == "#! ":
		policy = policy[3:]
	else:
		policy = policy.replace(" ", " or ")
	print("\nSearch Policy: ", policy)

	# ======= generate search token =======
	search_key = kpabe.keygen(pk, msk, policy)
	search_key_base64 = groupE_to_base64(search_key.copy(), groupObj)
	if debug: print("\nSearch token:\n", search_key_base64)
	# ======= access file list =======
	onlyMails = [ f for f in listdir(".") if f.endswith(".nmail") ]
	print("\nYou have mails:\n", onlyMails)

	# ======= get encrypted data =======
	result = []
	for file in onlyMails:
		json_data = read_json(file, True)
		Chead = base64_to_groupE(json_data['Chead'], groupObj)
		if debug: print("\nChead:\n", Chead)

		# ======= trapdoor function =======
		if kpabe.trapdoor(Chead, search_key):
			result.append(file)
		if debug: print("\nSecret:\n", plainChead)

	print("\nSearch results:")
	print(result)

	choose = input("\nChoose one file to check content:\n")
	print("\nDecrypt file: ", choose)
	json_data = read_json(choose, True)
	Nonce = base64_to_byte(json_data['Nonce'])
	Content = base64_to_byte(json_data['Content'])
	Tag = base64_to_byte(json_data['Tag'])
	Chead = base64_to_groupE(json_data['Chead'], groupObj)
	session = kpabe.decrypt(Chead, search_key)
	symenc = AES_EAX(session, debug)
	data = symenc.decrypt(Nonce, Content, Tag)
	print("\nContent:\n\n%s" % data.decode('utf-8'))

if __name__ == "__main__":
	main()
	print("")
