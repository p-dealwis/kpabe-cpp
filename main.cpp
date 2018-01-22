#include <vector>
#include <iostream>

#include "pbc.h"

#include "kpabe.hpp"

using namespace std;

int main() {
   // Setup the scheme
    PrivateParams priv;
    PublicParams pub;
    vector<int> attributeUniverse {1, 2, 3, 4, 5};
    setup(attributeUniverse, pub, priv);

    // Create an access policy and derive a key for it.
    // (1 OR 2) AND (3 OR 4)
    Node orNodeLeft(Node::Type::OR, {1, 2});
    Node orNodeRight(Node::Type::OR, {3, 4});
    Node root(Node::Type::AND, {orNodeLeft, orNodeRight});

    auto key = keyGeneration(priv, root);

    // Create an attribute-based secret (attributes 1 and 3).
    element_s secret;
    vector<int> encryptionAttributes {1, 3};
    auto Cw = createSecret(pub, encryptionAttributes, secret); // Decryption parameters

    // Recover secret
    element_s recovered;
    recoverSecret(key, Cw, attributes, recovered);
    element_cmp(&secret, &recovered); // should be ==0

    for(auto& attrCiPair: Cw) { //clean up
        element_clear(&attrCiPair.second);
    }

    // Secret cannot be recovered if the policy is not satisfied by the encryption attributes.
    encryptionAttributes = {1};
    Cw = createSecret(pub, encryptionAttributes, secret);
    try {
        recoverSecret(key, Cw, encryptionAttributes, recovered);
    } catch(const UnsatError& e) {
        cout << "Unsatisfied" << endl;
    }

    // Clean up (this should happen as part of destruction, so my bad)
    for(auto& attrDiPair: key.Di) {
        element_clear(&attrDiPair.second);
    }

    for(auto& attrCiPair: Cw) {
        element_clear(&attrCiPair.second);
    }
}

