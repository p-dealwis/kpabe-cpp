#include <vector>
#include <iostream>

#include "pbc.h"

#include "kpabe.hpp"

using namespace std;

int main() {
    // Setup the scheme
    PrivateParams priv;
    PublicParams pub;
    vector <int> attributeUniverse {0, 1, 2, 3, 4};
    setup(attributeUniverse, pub, priv);

    // Create an access policy and derive a key for it.
    // (1 OR 2) AND (3 OR 4)
    Node AND1(Node::Type::AND, {1, 2});
    Node OR1(Node::Type::OR, {AND1, 0});
    Node OR2(Node::Type::OR, {3, 4});
    Node root(Node::Type::AND, {OR1, OR2});

    auto key = keyGeneration(priv, root);

    // Create an attribute-based secret (attributes 1 and 3).
    element_s secret;
    vector<int> encryptionAttributes {0,1,2};
    auto Cw = createSecret(pub, encryptionAttributes, secret);

    // Recover secret
    element_s recovered;
    recoverSecret(key, Cw, encryptionAttributes, recovered);
    cout << element_cmp(&secret, &recovered) << endl; // should be ==0

    for(auto& attrCiPair: Cw) {
        element_clear(&attrCiPair.second);
    }
    Cw.clear();

    // Secret cannto be recovered if the encryption attributes do not satisfy the policy.
    encryptionAttributes = {0,2};
    try {
    Cw = createSecret(pub, encryptionAttributes, secret);
        recoverSecret(key, Cw, encryptionAttributes, recovered);
    } catch(const UnsatError& e) {
        cout << "Unsatisfied" << endl;
    }

    // Clean up (this should happen as part of destruction, so my bad)
    // for(auto& attrDiPair: key.Di) {
    //     element_clear(&attrDiPair.second);
    // }

    // for(auto& attrCiPair: Cw) {
    //     element_clear(&attrCiPair.second);
    // }
}

