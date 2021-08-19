from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc
from PEKS.Othertools.utils import *

class KPabe(ABEnc):

    def __init__(self, groupObj, Debug=False):
        ABEnc.__init__(self)
        global util, group, debug
        util = SecretUtil(groupObj, Debug)
        group = groupObj
        debug = Debug

    def import_keys(self, Kfile):
        data = read_json(Kfile)
        msk = base64_to_groupE(data['msk'], group)
        pk = base64_to_groupE(data['pk'], group)
        return (msk, pk)

    def export_keys(self, msk, pk, Kfile='Server_keys'):
        keysJSON = {
            'msk': groupE_to_base64(msk, group),
            'pk': groupE_to_base64(pk, group)
        }
        write_json(Kfile, keysJSON)

    def setup(self):
        # pick random exponents
        alpha1, alpha2, b = group.random(ZR), group.random(ZR), group.random(ZR)

        alpha = alpha1 * alpha2
        g_G1, g_G2 = group.random(G1), group.random(G2) # PK 1,2
        h_G1, h_G2 = group.random(G1), group.random(G2) # PK 3
        g1b = g_G1 ** b
        e_gg_alpha = pair(g_G1,g_G2) ** alpha

        #public parameters # 'g_G2^b':(g_G2 ** b), 'g_G2^b2':g_G2 ** (b * b),
        pk = { 'g_G1':g_G1, 'g_G2':g_G2, 'g_G1_b':g1b,
              'g_G1_b2':g1b ** b, 'h_G1_b':h_G1 ** b, 'e(gg)_alpha':e_gg_alpha }
        #secret parameters
        msk = { 'alpha1':alpha1, 'alpha2':alpha2, 'b':b, 'h_G1':h_G1, 'h_G2':h_G2 }
        return (msk, pk)

    def encrypt(self, pk, M, attr_list):
        if debug: print('Encryption Algorithm...')
        # s will hold secret
        t = group.init(ZR, 0)
        s = group.random(); sx = [s]
        for i in range(len(attr_list)):
            sx.append(group.random(ZR))
            sx[0] -= sx[i]

        E3 = {}
        #E4, E5 = {}, {}
        for i in range(len(attr_list)):
            attr = attr_list[i]
            E3[attr] = group.hash(attr, G1) ** s
            #E4[attr] = pk['g_G1_b'] ** sx[i]
            #E5[attr] = (pk['g_G1_b2'] ** (sx[i] * group.hash(attr))) * (pk['h_G1_b'] ** sx[i])

        E1 = (pk['e(gg)_alpha'] ** s) * M
        E2 = pk['g_G2'] ** s
        return { 'E1':E1, 'E2':E2, 'E3':E3, 'attributes':attr_list }

    def keygen(self, pk, msk, policy_str):
        policy = util.createPolicy(policy_str)
        attr_list = util.getAttributeList(policy)

        s = msk['alpha1']; secret = s
        shares = util.calculateSharesDict(secret, policy)

        D = { 'policy': policy_str }
        for x in attr_list:
            y = util.strip_index(x)
            d = []; r = group.random(ZR)
            if not self.negatedAttr(x): # meaning positive
                d.append((pk['g_G1'] ** (msk['alpha2'] * shares[x])) * (group.hash(y, G1) ** r))   # compute D1 for attribute x
                d.append((pk['g_G2'] ** r))  # compute D2 for attribute x
            #else:
                #d.append((pk['g2_G1'] ** shares[x]) * (pk['g_G1_b2'] ** r)) # compute D3
                #d.append((pk['g_G1_b'] ** (r * group.hash(x))) * (pk['h_G1'] ** r)) # compute D4
                #d.append(pk['g_G1'] ** -r) # compute D5
            D[x] = d
        if debug: print("Access Policy for key: %s" % policy)
        if debug: print("Attribute list: %s" % attr_list)
        return D

    def negatedAttr(self, attribute):
        if type(attribute) != str: attr = attribute.getAttribute()
        else: attr = attribute
        if attr[0] == '!':
            if debug: print("Checking... => %s" % attr[0])
            return True
        return False

    def trapdoor(self, E, D):
        policy = util.createPolicy(D['policy'])
        attrs = util.prune(policy, E['attributes'])
        if attrs == False:
            return False
        return True

    def decrypt(self, E, D):
        policy = util.createPolicy(D['policy'])
        attrs = util.prune(policy, E['attributes'])
        if attrs == False:
            print("\nAttributes not match: Failed to decrypt...\n")
            exit(1)
        coeff = util.getCoefficients(policy)

        Z = {}; prodT = 1
        for i in range(len(attrs)):
            x = attrs[i].getAttribute()
            y = attrs[i].getAttributeAndIndex()
            if not self.negatedAttr(y):
                 Z[y] = pair(D[y][0], E['E2']) / pair(E['E3'][x], D[y][1])
                 prodT *= Z[y] ** coeff[y]

        return E['E1'] / prodT
