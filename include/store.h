// store.h
#ifndef ENCRYPTED_STORE_H
#define ENCRYPTED_STORE_H

#include "config.h"
#include <iostream>
#include <memory>
#include <openfhe.h>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace lbcrypto;

struct UserSession {
  // joint public key (user + server)
  PublicKey<DCRTPoly> jointPublic;
  // server's secret share (server keeps only this)
  PrivateKey<DCRTPoly> serverSecret;
  // encrypted DB vectors stored under jointPublic (one ciphertext per DB
  // vector)
  Ciphertext<DCRTPoly> encryptedVector;
  // encrypted 1
  Ciphertext<DCRTPoly> encryptedOne;

  PrivateKey<DCRTPoly> clientSecret;
};

//
// Crypto + store combined helpers
//

// Initialize CKKS CryptoContext with parameters tuned for ciphertext×ciphertext
// inner products. You can adjust multiplicative depth & scaling size as
// required.
inline CryptoContext<DCRTPoly>
InitCKKSContext(usint multiplicativeDepth = MULT_DEPTH,
                usint scalingModSize = SCALE_MOD) {
  CCParams<CryptoContextCKKSRNS> parameters;
  parameters.SetSecurityLevel(HEStd_128_classic);
  parameters.SetMultiplicativeDepth(multiplicativeDepth);
  parameters.SetScalingModSize(scalingModSize);

  CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
  cc->Enable(PKE);
  cc->Enable(KEYSWITCH);
  cc->Enable(LEVELEDSHE);
  cc->Enable(ADVANCEDSHE);
  cc->Enable(MULTIPARTY);

  return cc;
}

class InMemoryStore {
public:
  std::unordered_map<std::string, UserSession> sessions_;
  InMemoryStore(const CryptoContext<DCRTPoly> &cc = InitCKKSContext())
      : cc_(cc) {}

  std::pair<bool, PrivateKey<DCRTPoly>>
  CreateUserSession(const std::string &userId) {

    if (sessions_.count(userId)) {
      std::cerr << "[store] userId already exists: " << userId << "\n";
      return {false, PrivateKey<DCRTPoly>()};
    }

    // Generates rotation evaluation keys for a list of indices.
    std::vector<int> binaryRotationFactors;
    for (int i = 1; i < int(VECTOR_DIM); i *= 2) {
      binaryRotationFactors.push_back(i);
      binaryRotationFactors.push_back(-i);
    }

    KeyPair<DCRTPoly> kp1;
    KeyPair<DCRTPoly> kp2;

    KeyPair<DCRTPoly> kpMultiparty;
    kp1 = cc_->KeyGen();

    // Generate evalmult key part for A
    auto evalMultKey = cc_->KeySwitchGen(kp1.secretKey, kp1.secretKey);

    // Generate evalsum key part for A
    cc_->EvalSumKeyGen(kp1.secretKey);
    auto evalSumKeys = std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(
        cc_->GetEvalSumKeyMap(kp1.secretKey->GetKeyTag()));

    // Round 2 (party B)
    kp2 = cc_->MultipartyKeyGen(kp1.publicKey);

    auto evalMultKey2 =
        cc_->MultiKeySwitchGen(kp2.secretKey, kp2.secretKey, evalMultKey);
    auto evalMultAB = cc_->MultiAddEvalKeys(evalMultKey, evalMultKey2,
                                            kp2.publicKey->GetKeyTag());

    auto evalMultBAB = cc_->MultiMultEvalKey(kp2.secretKey, evalMultAB,
                                             kp2.publicKey->GetKeyTag());

    auto evalSumKeysB = cc_->MultiEvalSumKeyGen(kp2.secretKey, evalSumKeys,
                                                kp2.publicKey->GetKeyTag());

    auto evalSumKeysJoin = cc_->MultiAddEvalSumKeys(evalSumKeys, evalSumKeysB,
                                                    kp2.publicKey->GetKeyTag());

    cc_->InsertEvalSumKey(evalSumKeysJoin);

    auto evalMultAAB = cc_->MultiMultEvalKey(kp1.secretKey, evalMultAB,
                                             kp2.publicKey->GetKeyTag());

    auto evalMultFinal = cc_->MultiAddEvalMultKeys(evalMultAAB, evalMultBAB,
                                                   evalMultAB->GetKeyTag());

    cc_->InsertEvalMultKey({evalMultFinal});

    UserSession s;
    s.jointPublic = kp2.publicKey;
    s.serverSecret = kp2.secretKey;
    s.clientSecret = kp1.secretKey;

    // create a plain text with VECTOR_DIM {}
    Plaintext p =
        cc_->MakeCKKSPackedPlaintext(std::vector<double>(VECTOR_DIM, 1));
    s.encryptedOne = cc_->Encrypt(kp2.publicKey, p);
    sessions_[userId] = std::move(s);
    // Return user secret to the caller (simulate handing to user).
    return {true, kp1.secretKey};
  }

  // Encrypt and store DB vectors under the joint public key for userId.
  // Input: vectors (each of dim VECTOR_DIM). They will be normalized
  // internally.
  bool EncryptAndStoreDBVector(const std::string &userId,
                               const std::vector<double> &v) {
    auto it = sessions_.find(userId);
    if (it == sessions_.end()) {
      return false;
    }
    UserSession &sess = it->second;

    if (v.size() != VECTOR_DIM) {
      return false;
    }

    std::vector<double> tmp = v;
    NormalizePlaintext(tmp);

    Plaintext p = cc_->MakeCKKSPackedPlaintext(tmp);
    Ciphertext<DCRTPoly> ct = cc_->Encrypt(sess.jointPublic, p);
    sess.encryptedVector = ct;
    return true;
  }

  // Utility: expose joint public key for a user (so the real user can encrypt
  // under it)
  std::pair<bool, PublicKey<DCRTPoly>>
  GetJointPublic(const std::string &userId, PublicKey<DCRTPoly> &outPub) const {
    auto it = sessions_.find(userId);
    if (it == sessions_.end()) {
      return {false, PublicKey<DCRTPoly>()};
    }
    outPub = it->second.jointPublic;
    return {true, outPub};
  }

private:
  // Normalize to unit vector for inner product -> cosine similarity
  static void NormalizePlaintext(std::vector<double> &v) {
    double mag = 0.0;
    for (double x : v) {
      mag += x * x;
    }
    mag = sqrt(mag);
    if (mag > 0) {
      for (double &x : v) {
        x /= mag;
      }
    }
  }

  const CryptoContext<DCRTPoly> cc_;
};

//
// High-level helpers intended to be used by client/main code
//

// Encrypt a vector under a given joint public key (client-side).
inline Ciphertext<DCRTPoly>
EncryptVectorForUser(const CryptoContext<DCRTPoly> &cc,
                     const PublicKey<DCRTPoly> &jointPub,
                     const std::vector<double> &vec) {
  std::vector<double> tmp = vec;
  // normalize
  double mag = 0.0;
  for (double x : tmp) {
    mag += x * x;
  }
  mag = sqrt(mag);
  if (mag > 0) {
    for (double &x : tmp) {
      x /= mag;
    }
  }

  Plaintext p = cc->MakeCKKSPackedPlaintext(tmp);
  return cc->Encrypt(jointPub, p);
}

// User-side: produce lead partial for inner-product ciphertexts given user's
// secret share. Returns vector of ciphertext partials (one per ciphertext).
Ciphertext<DCRTPoly> UserLeadPartial(const CryptoContext<DCRTPoly> &cc,
                                     const PrivateKey<DCRTPoly> &userSecret,
                                     Ciphertext<DCRTPoly> &innerCt) {

  return cc->MultipartyDecryptLead({innerCt}, userSecret)[0];
}

// Fuse user + server partials to produce plaintexts (user performs this
// locally). Assumes userPartials and serverPartials are same length and
// aligned.
inline Plaintext FusePartials(const CryptoContext<DCRTPoly> &cc,
                              Ciphertext<DCRTPoly> &userPartial,
                              Ciphertext<DCRTPoly> &serverPartial) {

  std::vector<Ciphertext<DCRTPoly>> parts;
  parts.push_back(userPartial);
  parts.push_back(serverPartial);
  Plaintext out;
  cc->MultipartyDecryptFusion(parts, &out);
  // Make sure length is 1 (inner product placed in first slot)
  out->SetLength(1);
  return out;
}

#endif // ENCRYPTED_STORE_H
