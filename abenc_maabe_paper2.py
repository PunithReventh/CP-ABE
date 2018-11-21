# -*- coding: utf-8 -*-
"""
Created on Sun Nov  4 16:10:10 2018

@author: Punith R
"""

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
#import json
from KUNode import Tree
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
    >>> n_users = 8
    >>> height = 3
    >>> tree = Tree(n_users, height)
    >>> maabe = MaabeKPA(group, tree)
    >>> public_parameters = maabe.setup()

        Setup the attribute authorities
    >>> attributes1 = ['ONE', 'TWO', 'THREE']
    >>> attributes2 = ['FOUR', 'FIVE', 'SIX']
    >>> attributes3 = ['SEVEN', 'EIGHT', 'NINE']
    >>> attributes4 = ['TEN', 'ELEVEN', 'TWELVE']
    >>> (public_key1, secret_key1) = maabe.authsetup(public_parameters, 'AB')
    >>> (public_key2, secret_key2) = maabe.authsetup(public_parameters, 'CD')
    >>> (public_key3, secret_key3) = maabe.authsetup(public_parameters, 'EF')
    >>> (public_key4, secret_key4) = maabe.authsetup(public_parameters, 'GH')
    >>> public_keys = {'AB': public_key1, 'CD': public_key2, 'EF': public_key3, 'GH': public_key4}
    >>> secret_keys = {'AB': secret_key1, 'CD': secret_key2, 'EF': secret_key3, 'GH': secret_key4}
    
        Setup a user and give him some keys
    >>> gid = 2
    >>> user_attributes1 = ['A1@AB', 'B1@AB', 'C1@AB']
    >>> user_attributes2 = ['D1@CD', 'E1@CD', 'F1@CD']
    >>> user_attributes3 = ['A2@EF', 'B2@EF', 'C2@EF']
    >>> user_attributes4 = ['D2@GH', 'E2@GH', 'F2@GH']
    >>> path = tree.Path(2)
    >>> user_keys1 = maabe.multiple_attributes_keygen(public_parameters, secret_key1, gid, path, user_attributes1)
    >>> user_keys2 = maabe.multiple_attributes_keygen(public_parameters, secret_key2, gid, path, user_attributes2)
    >>> user_keys3 = maabe.multiple_attributes_keygen(public_parameters, secret_key3, gid, path, user_attributes3)
    >>> user_keys4 = maabe.multiple_attributes_keygen(public_parameters, secret_key4, gid, path, user_attributes4)
    >>> user_keys = {'GID': gid, 'keys': merge_dicts(user_keys1, user_keys2, user_keys3, user_keys4)}
    >>> update_key1 = maabe.update_keygen(public_parameters, gid, public_key1, secret_key1, user_keys1, user_attributes1, 20)
    >>> update_key2 = maabe.update_keygen(public_parameters, gid, public_key2, secret_key2, user_keys2, user_attributes2, 20)
    >>> update_key3 = maabe.update_keygen(public_parameters, gid, public_key3, secret_key3, user_keys3, user_attributes3, 20)
    >>> update_key4 = maabe.update_keygen(public_parameters, gid, public_key4, secret_key4, user_keys4, user_attributes4, 20)
    >>> decrypt_key1 = maabe.decrypt_keygen(public_parameters, public_key1, user_keys1, gid, update_key1, user_attributes1, True)
    >>> decrypt_key2 = maabe.decrypt_keygen(public_parameters, public_key2, user_keys2, gid, update_key2, user_attributes2, True)
    >>> decrypt_key3 = maabe.decrypt_keygen(public_parameters, public_key3, user_keys3, gid, update_key3, user_attributes3, True)
    >>> decrypt_key4 = maabe.decrypt_keygen(public_parameters, public_key4, user_keys4, gid, update_key4, user_attributes4, True)
    >>> decrypt_keys = {'GID': gid, 'keys': merge_dicts(decrypt_key1, decrypt_key2, decrypt_key3, decrypt_key4)}
 
    Create a random message
    >>> message = group.random(GT)

        Encrypt the message
    >>> access_policy = '(A1@AB or E1@CD) and (C2@EF or D2@GH)'
    >>> cipher_text = maabe.encrypt(public_parameters, public_keys, message, access_policy, 20)

    print("Decryption key")
    print(decrypt_keys['keys'].keys())
    
    print("User key")
    print(user_keys['keys'].keys())
    
        Decrypt the message
    >>> decrypted_message = maabe.decrypt(gid, public_parameters, user_keys, decrypt_keys, cipher_text)
    >>> decrypted_message == message
    True
    
    Check for key sanity
    >>> sanityCheck = maabe.sanitycheck(public_parameters, secret_keys, public_keys, user_keys)
    Sanity Check
    SanityCheck1: True
    SanityCheck2: True
    
    >>> sanityCheck == True
    True
    """

    def __init__(self, group, tree, verbose=False):
        ABEncMultiAuth.__init__(self)
        self.group = group
        self.tree = tree
        self.util = SecretUtil(group, verbose)
        
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
        >>> n_users = 8
        >>> height = 3
        >>> tree = Tree(n_users, height)
        >>> maabe = MaabeKPA(group, tree)
        >>> maabe.unpack_attribute('STUDENT@UT')
        ('STUDENT', 'UT', None)
        >>> maabe.unpack_attribute('STUDENT@UT_2')
        ('STUDENT', 'UT', '2')
        """
        parts = re.split(r"[@_]", attribute)
        assert len(parts) > 1, "No @ char in [attribute@authority] name"
        return parts[0], parts[1], None if len(parts) < 3 else parts[2]

    def authsetup(self, gp, name):
        N, d = 8, 5
        alpha, y = self.group.random(), self.group.random()
        a, b = self.group.random(), self.group.random()
        egga = gp['egg'] ** alpha
        gy = gp['g1'] ** y
        ga = gp['g1'] ** a
        gb = gp['g1'] ** b
        g2a = gp['g2'] ** a
        g2b = gp['g2'] ** b
        f_list = list()
        r_list = dict()
        for i in range(0, d+1):
            f_list.append(self.group.random(G2))
        for i in range(1, 2*N):
            r_list[i] = self.group.random()
        pk = {'name': name, 'egga': egga, 'gy': gy, 'ga': ga, 'gb': gb, 'f_list': f_list, 'g2a': g2a, 'g2b': g2b}
        sk = {'name': name, 'alpha': alpha, 'y': y, 'a':a, 'b':b, 'r_list': r_list}
        if debug:
            print("Authsetup: %s" % name)
            print(pk)
            print(sk)
        return pk, sk
    
    def J(self, f_list, d, t):
        t_binary = bin(t)[2:]
        prod = self.group.init(G2, 1)
        prod *= f_list[0]
        for i in range(1, d+1):
            if t_binary[i-1] == '1':
                prod *= f_list[i]
        return prod
    
    def keygen(self, gp, sk, gid, attribute, w):
        """
        Generate a user secret key for the attribute.
        :param gp: The global parameters.
        :param sk: The secret key of the attribute authority.
        :param gid: The global user identifier.
        :param attribute: The attribute.
        :param w: The node in the path
        :return: The secret key for the attribute for the user with identifier gid.
        """
        _, auth, _ = self.unpack_attribute(attribute)
        assert sk['name'] == auth, "Attribute %s does not belong to authority %s" % (attribute, sk['name'])

        tt = self.group.random()
        r = self.group.random()
        j = (sk['a'] + sk['b'] * r)
        K1 = gp['g2'] ** ((sk['alpha'] - sk['r_list'][w]) / (j + gid))
        K1 *= gp['H'](str(gid)) ** (sk['y'] / (j + gid)) 
        K1 *= gp['F'](attribute) ** tt
        K2 = gid
        K3 = r
        K4 = gp['g1'] ** tt
        K5 = gp['g1'] ** (j * tt)
        if debug:
            print("Keygen")
            print("User, Attribute, Node")
            print(gid) 
            print(attribute) 
            print(w)
            print({'K1': K1, 'K2': K2, 'K3': K3, 'K4': K4, 'K5': K5})
        return {'K1': K1, 'K2': K2, 'K3': K3, 'K4': K4, 'K5': K5}

    def multiple_attributes_keygen(self, gp, sk, gid, path, attributes):
        """
        Generate a dictionary of secret keys for a user for a list of attributes.
        :param gp: The global parameters.
        :param sk: The secret key of the attribute authority.
        :param gid: The global user identifier.
        :param attributes: The list of attributes.
        :return: A dictionary with attribute names as keys, and secret keys for the attributes as values.
        """
        usk = {}
        for attribute in attributes:
            usk[attribute] = {}
            for w in path:
                usk[attribute][w] = self.keygen(gp, sk, gid, attribute, w)
        return usk
    
    def update_keygen(self, gp, gid, pks, sk, user_key, attributes, t):
        X, Y = self.tree.get_sets()
        gid_hash = gid
        uk = {}
        for attribute in attributes:
            uk[attribute] = {}
            for w in Y:
                m = self.group.random()
                r = user_key[attribute][w]['K3']
                j = (sk['a'] + sk['b'] * r)
                uk1 = (gp['g2'] ** ((sk['r_list'][w]) / (j + gid_hash))) * (self.J(pks['f_list'], 5, t) ** (m / (j + gid_hash)))
                uk2 = gp['g1'] ** m
                uk3 = self.J(pks['f_list'], 5, t) ** (1 / (j + gid_hash))
                uk[attribute][w] = {'U1': uk1, 'U2': uk2, 'U3': uk3}
        if debug:
            print("Update keygen")
            print(uk)
        return uk
    
    def decrypt_keygen(self, gp, pks, usk, gid, uk, attributes, first_iter):
        X, Y = self.tree.get_sets()
        path = set(self.tree.Path(gid))
        common = path.intersection(set(Y))
        dsk = {}
        for w in common:
            if first_iter:
                m = 0
            else:
                m = self.group.random()
            for attribute in attributes:
                D1 = usk[attribute][w]['K1'] * uk[attribute][w]['U1'] * (uk[attribute][w]['U3'] ** m)
                D2 = usk[attribute][w]['K4']
                Dt = uk[attribute][w]['U2'] * gp['g1'] ** m 
                dsk[attribute] = {'D1': D1, 'D2': D2, 'Dt': Dt}
            if debug:
                print("Decrypt keygen")
                print(dsk)
        return dsk
            
    def encrypt(self, gp, pks, message, policy_str, t):
        """
        Encrypt a message under an access policy
        :param gp: The global parameters.
        :param pks: The public keys of the relevant attribute authorities, as dict from authority name to public key.
        :param message: The message to encrypt.
        :param policy_str: The access policy to use.
        :return: The encrypted message.
        """
        s = self.group.random()  # secret to be shared
        w = self.group.init(ZR, 0)  # 0 to be shared
        policy = self.util.createPolicy(policy_str)
        attribute_list = self.util.getAttributeList(policy)
        secret_shares = self.util.calculateSharesDict(s, policy)  # These are correctly set to be exponents in Z_p
        zero_shares = self.util.calculateSharesDict(w, policy)
        C0 = message * (gp['egg'] ** s)
        C1, C2, C3, C4, C5, C6, Ct = {}, {}, {}, {}, {}, {}, {}
        b = bin(t)[2:]
        testing = list()
        rx_list = {}
        for i in attribute_list:
            attribute_name, auth, _ = self.unpack_attribute(i)
            attr = "%s@%s" % (attribute_name, auth)
            rx = self.group.random()
            rx_list[i] = rx
            C1[i] = gp['egg'] ** secret_shares[i] * pks[auth]['egga'] ** rx
            C2[i] = gp['g1'] ** (-rx)
            C3[i] = pks[auth]['gy'] ** rx * gp['g1'] ** zero_shares[i]
            C4[i] = gp['F'](attr) ** rx
            C5[i] = pks[auth]['ga'] ** (-rx)
            C6[i] = pks[auth]['gb'] ** (-rx)
            Ct[i] = self.group.init(G2, 1)
            Ct[i] *= pks[auth]['f_list'][0]
            for k in range(0, len(b)):
                if b[k] == '1': 
                    Ct[i] *= pks[auth]['f_list'][k+1]
            Ct[i] = Ct[i] ** rx
 
        if debug:
            print("Encrypt")
            print(message)
            print({'policy': policy_str, 'C0': C0, 'C1': C1, 'C2': C2, 'C3': C3, 'C4': C4, 'C5': C5, 'C6': C6, 'Ct': Ct})
            print("Testing value")
            print(testing)
        return {'policy': policy_str, 'C0': C0, 'C1': C1, 'C2': C2, 'C3': C3, 'C4': C4, 'C5': C5, 'C6': C6, 'Ct': Ct, 'secret_shares': secret_shares, 'zero_shares': zero_shares, 'rx':rx_list}

#    def update_encrypt(self, gp, pks, ct):
#        """
#        Encrypt a message under an access policy
#        :param gp: The global parameters.
#        :param pks: The public keys of the relevant attribute authorities, as dict from authority name to public key.
#        :param message: The message to encrypt.
#        :param policy_str: The access policy to use.
#        :return: The encrypted message.
#        """
#        s_new = self.group.random()  # secret to be shared
#        w_new = self.group.init(ZR, 0)  # 0 to be shared
#        policy = self.util.createPolicy(ct['policy'])
#        attribute_list = self.util.getAttributeList(policy)
#        secret_shares = self.util.calculateSharesDict(s, policy)  # These are correctly set to be exponents in Z_p
#        zero_shares = self.util.calculateSharesDict(w, policy)
#        C0_new = ct['C0'] * (gp['egg'] ** s_new)
#        C1_new, C2_new, C3_new, C4_new, C5_new, C6_new = {}, {}, {}, {}, {}, {}
#        for i in attribute_list:
#            attribute_name, auth, _ = self.unpack_attribute(i)
#            attr = "%s@%s" % (attribute_name, auth)
#            rx_new = self.group.random()
#            C1_new[i] = ct['C1'][i] * gp['egg'] ** secret_shares[i] * pks[auth]['egga'] ** rx_new
#            C2_new[i] = ct['C2'][i] * gp['g1'] ** (-rx_new)
#            C3_new[i] = ct['C3'][i] * pks[auth]['gy'] ** rx_new * gp['g1'] ** zero_shares[i]
#            C4_new[i] = ct['C4'][i] * gp['F'](attr) ** rx_new
#            C5_new[i] = ct['C5'][i] * pks[auth]['ga'] ** (-rx_new)
#            C6_new[i] = ct['C6'][i] * pks[auth]['gb'] ** (-rx_new)
#        if debug:
#            print("Update Encrypt")
#            print(message)
#            print({'policy': policy_str, 'C0_new': C0_new, 'C1_new': C1_new, 'C2_new': C2_new, 'C3_new': C3_new, 'C4_new': C4_new, 'C5_new': C5_new, 'C6_new': C6_new})
#        return {'policy': policy_str, 'C0_new': C0_new, 'C1_new': C1_new, 'C2_new': C2_new, 'C3_new': C3_new, 'C4_new': C4_new, 'C5_new': C5_new, 'C6_new': C6_new}
    
    def decrypt(self, gi, gp, usk, dsk, ct):
        """
        Decrypt the ciphertext using the secret keys of the user.
        :param gp: The global parameters.
        :param sk: The secret keys of the user.
        :param ct: The ciphertext to decrypt.
        :return: The decrypted message.
        :raise Exception: When the access policy can not be satisfied with the user's attributes.
        """
        X, Y = self.tree.get_sets()
        path = set(self.tree.Path(gi))
        common = path.intersection(set(Y))
        gid = list(common)[0]
        policy = self.util.createPolicy(ct['policy'])
        coefficients = self.util.getCoefficients(policy)
        pruned_list = self.util.prune(policy, usk['keys'].keys())
        if not pruned_list:
            raise Exception("You don't have the required attributes for decryption!")
        B = self.group.init(GT, 1)  
        for i in range(len(pruned_list)):
            x = pruned_list[i].getAttribute()  # without the underscore
#            y = pruned_list[i].getAttributeAndIndex()  # with the underscore
            t1 = ct['C2'][x] ** usk['keys'][x][gid]['K2']
            t1 *= ct['C5'][x]
            t1 *= ct['C6'][x] ** usk['keys'][x][gid]['K3']
            result1 = pair(t1, dsk['keys'][x]['D1'])
            result2 = ct['C1'][x]
            result3 = pair(dsk['keys'][x]['Dt'], ct['Ct'][x])
            result4 = pair((dsk['keys'][x]['D2'] ** usk['keys'][x][gid]['K2']) * usk['keys'][x][gid]['K5'] , ct['C4'][x])
            result5 = pair(ct['C3'][x], gp['H'](str(usk['keys'][x][gid]['K2'])))
            B *= (result1 * result2 * result3 * result4 * result5) ** coefficients[x]
        decrypted_message = ct['C0'] / B
        if debug:
            print("Decrypt")
            print("DSK:")
            print(dsk)
            print("Decrypted Message:")
            print(decrypted_message)
        return decrypted_message
        
    def sanitycheck(self, gp, sks, pks, usk):
#        self.group.StartBenchmark(["RealTime", "Mul", "Exp", "Pair"])
#        policy = self.util.createPolicy(policy_ct)
#        pruned_list = self.util.prune(policy, sk['keys'].keys())
#        if not pruned_list:
#            raise Exception("You don't have the required attributes for decryption!")
        attributes = usk['keys'].keys()
        keySanityCheck = False
        for x in attributes:
#            x = pruned_list[i].getAttribute()
#            keySanityCheck = True
            keySanityCheck1 = False
            keySanityCheck2 = False
            attribute_name, auth, _ = self.unpack_attribute(x)
            for w in usk['keys'][x].keys():
                keySanityCheck1 = keySanityCheck1 or (pair(usk['keys'][x][w]['K5'], gp['g2']) == pair(usk['keys'][x][w]['K4'], pks[auth]['g2a'] * (pks[auth]['g2b'] ** usk['keys'][x][w]['K3'])))
                keySanityCheck2 = keySanityCheck2 or (pair(pks[auth]['ga'] * (pks[auth]['gb'] ** usk['keys'][x][w]['K3']) * (gp['g1'] ** usk['keys'][x][w]['K2']), usk['keys'][x][w]['K1']) == (gp['egg'] ** (sks[auth]['alpha'] - sks[auth]['r_list'][w])) * pair(pks[auth]['gy'], gp['H'](str(usk['keys'][x][w]['K2']))) * pair(usk['keys'][x][w]['K5'] * (usk['keys'][x][w]['K4'] ** usk['keys'][x][w]['K2']), gp['F'](x)))
            keySanityCheck = (keySanityCheck1 and keySanityCheck2)
            if keySanityCheck:
                break 
        if debug:
            print("Sanity Check")
            print("SanityCheck1:", keySanityCheck1)
            print("SanityCheck2:", keySanityCheck2)
        return keySanityCheck
                               
if __name__ == '__main__':
    debug = True
    import doctest
    doctest.testmod()
