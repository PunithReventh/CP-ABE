"""
A Multiauthority Attribute Based Cryptosystem with Expressive Policies

* type:          attribute-based encryption (public key)
* setting:       bilinear pairing group of prime order
* assumption:    complex q-type assumption

"""

from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
import re
import json
debug = False


def merge_dicts(*dict_args):
    """
    Given any number of dicts, shallow copy and merge into a new dict,
    precedence goes to key value pairs in latter dicts.
    """
    result = {}
    for dictionary in dict_args:
        result.update(dictionary)
    return result


class MaabeKPA(ABEncMultiAuth):
    """
    A Multiauthority Attribute Based Cryptosystem with Expressive Policies

    >>> group = PairingGroup('SS512')
    >>> maabe = MaabeKPA(group)
    >>> public_parameters = maabe.setup()

        Setup the attribute authorities
    attributes1 = ['ONE', 'TWO', 'THREE', 'FOUR']
    attributes2 = ['THREE', 'FOUR']
    >>> (public_key1, secret_key1) = maabe.authsetup(public_parameters, 'AB')
    >>> (public_key2, secret_key2) = maabe.authsetup(public_parameters, 'CD')
    >>> (public_key3, secret_key3) = maabe.authsetup(public_parameters, 'EF')
    >>> (public_key4, secret_key4) = maabe.authsetup(public_parameters, 'GH')
    >>> public_keys = {'AB': public_key1, 'CD': public_key2, 'EF': public_key3, 'GH': public_key4 }

        Setup a user and give him some keys
    >>> gid = "bob"
    >>> user_attributes1 = ['A1@AB', 'B1@AB', 'C1@AB', 'D1@AB']
    >>> user_attributes2 = ['A2@CD', 'B2@CD', 'C2@CD', 'D2@CD']
    >>> user_attributes3 = ['A3@EF', 'B3@EF', 'C3@EF', 'D3@EF']
    >>> user_attributes4 = ['A4@GH', 'B4@GH', 'C4@GH', 'D4@GH']
    >>> user_keys1 = maabe.multiple_attributes_keygen(public_parameters, secret_key1, gid, user_attributes1)
    >>> user_keys2 = maabe.multiple_attributes_keygen(public_parameters, secret_key2, gid, user_attributes2)
    >>> user_keys3 = maabe.multiple_attributes_keygen(public_parameters, secret_key3, gid, user_attributes3)
    >>> user_keys4 = maabe.multiple_attributes_keygen(public_parameters, secret_key4, gid, user_attributes4)
    >>> user_keys = {'GID': gid, 'keys': merge_dicts(user_keys1, user_keys2, user_keys3, user_keys4)}

        Create a random message
    >>> message = group.random(GT)

        Encrypt the message
    >>> access_policy = '(A1@AB or D2@CD) and (B3@EF or C4@GH)'
    >>> cipher_text = maabe.encrypt(public_parameters, public_keys, message, access_policy)

        Decrypt the message
    >>> decrypted_message = maabe.decrypt(public_parameters, user_keys, cipher_text)
    >>> decrypted_message == message
    True
    
        Check for key sanity
    >>> sanityCheck = maabe.sanitycheck(public_parameters, public_keys, user_keys, cipher_text['policy'])
    Sanity Check
    SanityCheck1: True
    SanityCheck2: True
    
    >>> sanityCheck == True
    True
    """

    def __init__(self, group, verbose=False):
        ABEncMultiAuth.__init__(self)
        self.group = group
        self.util = SecretUtil(group, verbose)
        f = open('Benchmarks.txt','a+')
        f.write("\n")
        f.close()
        
    def setup(self):
        g1 = self.group.random(G1)
        g2 = self.group.random(G2)
        egg = pair(g1, g2)
        H = lambda x: self.group.hash(x, G2)
        F = lambda x: self.group.hash(x, G2)
        gp = {'g1': g1, 'g2': g2, 'egg': egg, 'H': H, 'F': F}
        if debug:
            print("Setup")
            print(gp)
        return gp

    def unpack_attribute(self, attribute):
        """
        Unpacks an attribute in attribute name, authority name and index
        :param attribute: The attribute to unpack
        :return: The attribute name, authority name and the attribute index, if present.

        >>> group = PairingGroup('SS512')
        >>> maabe = MaabeKPA(group)
        >>> maabe.unpack_attribute('STUDENT@UT')
        ('STUDENT', 'UT', None)
        >>> maabe.unpack_attribute('STUDENT@UT_2')
        ('STUDENT', 'UT', '2')
        """
        parts = re.split(r"[@_]", attribute)
        assert len(parts) > 1, "No @ char in [attribute@authority] name"
        return parts[0], parts[1], None if len(parts) < 3 else parts[2]

    def authsetup(self, gp, name):
        """
        Setup an attribute authority.
        :param gp: The global parameters
        :param name: The name of the authority
        :return: The public and private key of the authority
        """
        f = open('Benchmarks.txt','a+')
        assert self.group.InitBenchmark(), "failed to initialize benchmark"
        self.group.StartBenchmark(["RealTime", "Mul", "Exp", "Pair"])
        alpha, y = self.group.random(), self.group.random()
        a, b = self.group.random(), self.group.random()
        egga = gp['egg'] ** alpha
        gy = gp['g1'] ** y
        ga = gp['g1'] ** a
        gb = gp['g1'] ** b
        pk = {'name': name, 'egga': egga, 'gy': gy, 'ga': ga, 'gb': gb}
        sk = {'name': name, 'alpha': alpha, 'y': y, 'a':a, 'b':b}
        self.group.EndBenchmark()
        msmtDict = self.group.GetGeneralBenchmarks()
        f.write("\nAuth Setup Benchmarks for %s:" % name)
        json.dump(msmtDict, f)
        f.close()
        if debug:
            print("Authsetup: %s" % name)
            print(pk)
            print(sk)
        return pk, sk

    def keygen(self, gp, sk, gid, attribute):
        """
        Generate a user secret key for the attribute.
        :param gp: The global parameters.
        :param sk: The secret key of the attribute authority.
        :param gid: The global user identifier.
        :param attribute: The attribute.
        :return: The secret key for the attribute for the user with identifier gid.
        """
        _, auth, _ = self.unpack_attribute(attribute)
        assert sk['name'] == auth, "Attribute %s does not belong to authority %s" % (attribute, sk['name'])

        t = self.group.random()
        i = self.group.random()
        gid_hash = self.group.hash(gid, ZR)
        j = sk['a'] + sk['a'] * sk['b'] * gid_hash
        K4 = gp['g2'] ** i
        K1 = gp['g2'] ** sk['alpha'] * K4 ** j * gp['H'](gid) ** sk['y'] * gp['F'](attribute) ** t
        K2 = gid
        K3 = K4 ** sk['b']
        K5 = gp['g1'] ** t
        if debug:
            print("Keygen")
            print("User: %s, Attribute: %s" % (gid, attribute))
            print({'K1': K1, 'K2': K2, 'K3': K3, 'K4': K4, 'K5': K5})
        return {'K1': K1, 'K2': K2, 'K3': K3, 'K4': K4, 'K5': K5}

    def multiple_attributes_keygen(self, gp, sk, gid, attributes):
        """
        Generate a dictionary of secret keys for a user for a list of attributes.
        :param gp: The global parameters.
        :param sk: The secret key of the attribute authority.
        :param gid: The global user identifier.
        :param attributes: The list of attributes.
        :return: A dictionary with attribute names as keys, and secret keys for the attributes as values.
        """
        uk = {}
        f = open('Benchmarks.txt','a+')
#        assert self.group.InitBenchmark(), "failed to initialize benchmark"
        self.group.StartBenchmark(["RealTime", "Mul", "Exp", "Pair"])
        for attribute in attributes:
            uk[attribute] = self.keygen(gp, sk, gid, attribute)
        self.group.EndBenchmark()
        msmtDict = self.group.GetGeneralBenchmarks()
        f.write("\nTotal Keygen Benchmarks:")
        json.dump(msmtDict, f)
        f.close()
        return uk

    def encrypt(self, gp, pks, message, policy_str):
        """
        Encrypt a message under an access policy
        :param gp: The global parameters.
        :param pks: The public keys of the relevant attribute authorities, as dict from authority name to public key.
        :param message: The message to encrypt.
        :param policy_str: The access policy to use.
        :return: The encrypted message.
        """
        f = open('Benchmarks.txt','a+')
        s = self.group.random()  # secret to be shared
        w = self.group.init(ZR, 0)  # 0 to be shared
        policy = self.util.createPolicy(policy_str)
        attribute_list = self.util.getAttributeList(policy)
#        assert self.group.InitBenchmark(), "failed to initialize benchmark"
        self.group.StartBenchmark(["RealTime", "Mul", "Exp", "Pair"])
        secret_shares = self.util.calculateSharesDict(s, policy)  # These are correctly set to be exponents in Z_p
        zero_shares = self.util.calculateSharesDict(w, policy)
        C0 = message * (gp['egg'] ** s)
        C1, C2, C3, C4, C5 = {}, {}, {}, {}, {}
        for i in attribute_list:
            attribute_name, auth, _ = self.unpack_attribute(i)
            attr = "%s@%s" % (attribute_name, auth)
            tx = self.group.random()
            C1[i] = gp['egg'] ** secret_shares[i] * pks[auth]['egga'] ** tx
            C2[i] = gp['g1'] ** (-tx)
            C3[i] = pks[auth]['gy'] ** tx * gp['g1'] ** zero_shares[i]
            C4[i] = gp['F'](attr) ** tx
            C5[i] = pks[auth]['ga'] ** tx
        self.group.EndBenchmark()
        msmtDict = self.group.GetGeneralBenchmarks()
        f.write("\nEncryption Benchmarks:")
        json.dump(msmtDict, f)
#        granDict = self.group.GetGranularBenchmarks()
#        print("<=== General Benchmarks ===>")
#        print("Results  := ", msmtDict)
#        print("<=== Granular Benchmarks ===>")
#        print("G1 mul   := ", granDict["Mul"][G1])
        f.close()
        if debug:
            print("Encrypt")
            print(message)
            print({'policy': policy_str, 'C0': C0, 'C1': C1, 'C2': C2, 'C3': C3, 'C4': C4, 'C5': C5})
        return {'policy': policy_str, 'C0': C0, 'C1': C1, 'C2': C2, 'C3': C3, 'C4': C4, 'C5': C5}

    def decrypt(self, gp, sk, ct):
        """
        Decrypt the ciphertext using the secret keys of the user.
        :param gp: The global parameters.
        :param sk: The secret keys of the user.
        :param ct: The ciphertext to decrypt.
        :return: The decrypted message.
        :raise Exception: When the access policy can not be satisfied with the user's attributes.
        """
        f = open('Benchmarks.txt','a+')
        #        assert self.group.InitBenchmark(), "failed to initialize benchmark"
        self.group.StartBenchmark(["RealTime", "Mul", "Exp", "Pair"])
        policy = self.util.createPolicy(ct['policy'])
        coefficients = self.util.getCoefficients(policy)
        pruned_list = self.util.prune(policy, sk['keys'].keys())
        print(pruned_list)
        if not pruned_list:
            raise Exception("You don't have the required attributes for decryption!")
        B = self.group.init(GT, 1)        
        for i in range(len(pruned_list)):
            x = pruned_list[i].getAttribute()  # without the underscore
            y = pruned_list[i].getAttributeAndIndex()  # with the underscore
            K2_hash = self.group.hash(sk['keys'][x]['K2'], ZR)
            B *= (ct['C1'][y] * pair(ct['C2'][y], sk['keys'][x]['K1']) * pair(ct['C3'][y], gp['H'](sk['keys'][x]['K2'])) * pair(sk['keys'][x]['K5'], ct['C4'][y]) * pair(ct['C5'][y], sk['keys'][x]['K4'] * sk['keys'][x]['K3'] ** K2_hash)) ** coefficients[y]
        decrypted_message = ct['C0'] / B
        self.group.EndBenchmark()
        msmtDict = self.group.GetGeneralBenchmarks()
        f.write("\nDecryption Benchmarks:")
        json.dump(msmtDict, f)
        f.close()
        if debug:
            print("Decrypt")
            print("SK:")
            print(sk['keys'].keys())
            print(x)
            print(y)
            print("Decrypted Message:")
            print(decrypted_message)
        return decrypted_message
        
    def sanitycheck(self, gp, pks, sk, policy_ct):
        f = open('Benchmarks.txt','a+')
        #        assert self.group.InitBenchmark(), "failed to initialize benchmark"
        self.group.StartBenchmark(["RealTime", "Mul", "Exp", "Pair"])
        policy = self.util.createPolicy(policy_ct)
        pruned_list = self.util.prune(policy, sk['keys'].keys())
        if not pruned_list:
            raise Exception("You don't have the required attributes for decryption!")
        keySanityCheck = False
        for i in range(len(pruned_list)):
            x = pruned_list[i].getAttribute()
            attribute_name, auth, _ = self.unpack_attribute(x)
            K2_hash = self.group.hash(sk['keys'][x]['K2'], ZR)
            keySanityCheck1 = (pair(gp['g1'], sk['keys'][x]['K3']) == pair(pks[auth]['gb'], sk['keys'][x]['K4']))
            keySanityCheck2 = (pair(gp['g1'], sk['keys'][x]['K1']) == pks[auth]['egga'] * pair(pks[auth]['gy'], gp['H'](sk['keys'][x]['K2'])) * pair(sk['keys'][x]['K5'], gp['F'](x)) * pair(pks[auth]['ga'], sk['keys'][x]['K4'] * sk['keys'][x]['K3'] ** K2_hash))
            keySanityCheck = keySanityCheck1 and keySanityCheck2
            if keySanityCheck:
                break
        self.group.EndBenchmark()
        msmtDict = self.group.GetGeneralBenchmarks()
        f.write("\nSanity Check Benchmarks:")
        json.dump(msmtDict, f)
        f.close()
        if debug:
            print("Sanity Check")
            print("SanityCheck1:", keySanityCheck1)
            print("SanityCheck2:", keySanityCheck2)
        return keySanityCheck
                               
if __name__ == '__main__':
    debug = True

    import doctest

    doctest.testmod()
