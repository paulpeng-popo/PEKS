from argparse import ArgumentParser
from PEKS.Symcrypt import *
from PEKS.Scheme import *
import os.path

GroupCurve = "MNT224"
KeysFile = "Server_keys"

def main(debug=False):
	# ======= set up eliptic curve parameters =======
	groupObj = PairingGroup(GroupCurve)
	kpabe = KPabe(groupObj, debug)
	if os.path.isfile(KeysFile):
		(msk, pk) = kpabe.import_keys(KeysFile)
	else:
		(msk, pk) = kpabe.setup()
		kpabe.export_keys(msk.copy(), pk.copy(), KeysFile)
	if debug:
		print("\nmsk:\n", msk)
		print("\npk:\n", pk)

	# ======= make argments' parser =======
	parser = ArgumentParser(description='ABE with keyword search.')
	parser.add_argument('Path', type=str, help='the file to be encrypted')
	parser.add_argument('File', type=str, help='the file named after encrypted')
	parser.add_argument('Attrs', type=str, help='attributes chosen related to file')
	args = parser.parse_args()

	# ======= open the file to be encrypted =======
	path = args.Path
	try:
		f = open(path, 'r')
		msg = f.read().encode("utf-8")
	except:
		f = open(path, 'rb')
		msg = base64.b64encode(f.read())
	f.close()
	if debug: print("\nmsg:\n", byte_to_base64(msg))

	# ======= generate session key's seed =======
	session = groupObj.random(GT)

	# ======= AES encryption =======
	symenc = AES_EAX(session, debug)
	nonce, ciphered_msg, verfication_tag = symenc.encrypt(msg)

	# ======= create attributes in dictionary =======
	attributes = args.Attrs.split()

	# ======= encrypt session by attributes =======
	ciphertext = kpabe.encrypt(pk, session, attributes)
	if debug: print("\nciphertext:\n", ciphertext)

	# ======= make result of encryption converted into string =======
	outputJSON = {
		'Nonce': byte_to_base64(nonce),
		'Content': byte_to_base64(ciphered_msg),
		'Tag': byte_to_base64(verfication_tag),
		'Chead': groupE_to_base64(ciphertext, groupObj)
	}
	write_json(args.File, outputJSON, True)

if __name__ == "__main__":
	main()
	print("")
