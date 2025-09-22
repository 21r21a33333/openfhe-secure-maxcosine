// store.h
#ifndef ENCRYPTED_STORE_H
#define ENCRYPTED_STORE_H

#include "config.h"
#include <cmath>
#include <iostream>
#include <memory>
#include <openfhe.h>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace lbcrypto;

// Updated UserSession structure for 8-party protocol
struct UserSession {
  // Joint public key shared among all 8 parties
  PublicKey<DCRTPoly> jointPublic;

  // Server's secret key share (server retains this)
  PrivateKey<DCRTPoly> serverSecret;

  // Multiple encrypted database vectors stored under joint public key
  std::vector<Ciphertext<DCRTPoly>> encryptedVectors;

  // All party secret keys (for testing/PoC only - normally only server key
  // stored)
  std::vector<PrivateKey<DCRTPoly>> partySecrets;
};

//
// Cryptographic Context Setup
//

/**
 * Initializes CKKS cryptographic context optimized for ciphertext operations
 * and inner product computations with multiparty support
 *
 * @param multiplicativeDepth Maximum depth of multiplicative operations
 * @param scalingModSize Size of scaling modulus for precision control
 * @return Configured CKKS crypto context
 */
inline CryptoContext<DCRTPoly>
InitCKKSContext(usint multiplicativeDepth = MULT_DEPTH,
                usint scalingModSize = SCALE_MOD) {
  CCParams<CryptoContextCKKSRNS> parameters;
  parameters.SetSecurityLevel(HEStd_128_classic);
  parameters.SetMultiplicativeDepth(multiplicativeDepth);
  parameters.SetScalingModSize(scalingModSize);

  auto cryptoContext = GenCryptoContext(parameters);

  // Enable required homomorphic encryption features
  cryptoContext->Enable(PKE);         // Public key encryption
  cryptoContext->Enable(KEYSWITCH);   // Key switching operations
  cryptoContext->Enable(LEVELEDSHE);  // Leveled somewhat homomorphic encryption
  cryptoContext->Enable(ADVANCEDSHE); // Advanced operations (rotation, etc.)
  cryptoContext->Enable(MULTIPARTY);  // Multiparty computation support

  return cryptoContext;
}

//
// Utility Functions
//

/**
 * Normalizes a vector to unit length for cosine similarity computation
 *
 * @param vector Vector to normalize (modified in-place)
 */
inline void NormalizeVector(std::vector<double> &vector) {
  double magnitude = 0.0;

  // Calculate magnitude (L2 norm)
  for (const double &value : vector) {
    magnitude += value * value;
  }
  magnitude = std::sqrt(magnitude);

  // Normalize if magnitude is non-zero
  if (magnitude > 0.0) {
    for (double &value : vector) {
      value /= magnitude;
    }
  }
}

/**
 * Generates binary rotation factors for efficient vector operations
 * Used for log(n) rotation-based summation in dot product computation
 *
 * @param vectorDimension Dimension of vectors being processed
 * @return Vector of rotation indices for binary tree summation
 */
inline std::vector<int> GenerateBinaryRotationFactors(size_t vectorDimension) {
  std::vector<int> rotationFactors;

  for (int i = 1; i < static_cast<int>(vectorDimension); i *= 2) {
    rotationFactors.push_back(i);
    rotationFactors.push_back(-i);
  }

  return rotationFactors;
}

//
// In-Memory Encrypted Store
//

/**
 * In-memory store for managing encrypted user sessions and database vectors
 * Supports multiparty homomorphic encryption with joint key generation
 */
class InMemoryStore {
public:
  // Public access to user sessions (for compatibility with existing code)
  std::unordered_map<std::string, UserSession> sessions_;
  const CryptoContext<DCRTPoly> cryptoContext_;
  /**
   * Constructs store with given cryptographic context
   *
   * @param cryptoContext CKKS context for encryption operations
   */
  explicit InMemoryStore(
      const CryptoContext<DCRTPoly> &cryptoContext = InitCKKSContext())
      : cryptoContext_(cryptoContext) {}

  /**
   * Creates a new 8-party user session with joint key generation
   * Implements multi-party key generation protocol among 8 parties
   *
   * @param userId Unique identifier for the user
   * @return Pair of (success status, vector of all party secret keys)
   */
  std::pair<bool, std::vector<PrivateKey<DCRTPoly>>>
  CreateUserSession(const std::string &userId) {
    // Check if user already exists
    if (sessions_.count(userId)) {
      std::cerr << "[Store] User ID already exists: " << userId << "\n";
      return {false, std::vector<PrivateKey<DCRTPoly>>()};
    }

    try {
      const usint numParties = 8;

      // Generate rotation keys for efficient vector operations
      auto rotationFactors = GenerateBinaryRotationFactors(VECTOR_DIM);

      // Initialize key pairs for all 8 parties
      std::vector<KeyPair<DCRTPoly>> partyKeyPairs(numParties);

      // ============================================================
      // ROUND 1: Party 0 (Lead party) generates initial key pair
      // ============================================================
      partyKeyPairs[0] = cryptoContext_->KeyGen();

      // Generate evaluation keys for Party 0
      auto evalMultKey = cryptoContext_->KeySwitchGen(
          partyKeyPairs[0].secretKey, partyKeyPairs[0].secretKey);

      // Generate sum evaluation keys for Party 0
      cryptoContext_->EvalSumKeyGen(partyKeyPairs[0].secretKey);
      auto evalSumKeys = std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(
          cryptoContext_->GetEvalSumKeyMap(
              partyKeyPairs[0].secretKey->GetKeyTag()));

      // Current accumulated keys (will be updated in each round)
      auto currentEvalMultKey = evalMultKey;
      auto currentEvalSumKeys = evalSumKeys;
      auto currentPublicKey = partyKeyPairs[0].publicKey;

      // ============================================================
      // ROUNDS 2-8: Sequential multi-party key generation
      // ============================================================
      for (usint party = 1; party < numParties; party++) {
        std::cout << "[Store] Processing party " << party + 1 << " of "
                  << numParties << "\n";

        // Generate key pair for current party
        partyKeyPairs[party] =
            cryptoContext_->MultipartyKeyGen(currentPublicKey);

        // Generate evaluation keys for current party
        auto partyEvalMultKey = cryptoContext_->MultiKeySwitchGen(
            partyKeyPairs[party].secretKey, partyKeyPairs[party].secretKey,
            currentEvalMultKey);

        // Combine evaluation mult keys
        auto combinedEvalMultKey = cryptoContext_->MultiAddEvalKeys(
            currentEvalMultKey, partyEvalMultKey,
            partyKeyPairs[party].publicKey->GetKeyTag());

        // Generate multiplication evaluation keys for all previous parties
        std::vector<EvalKey<DCRTPoly>> multKeys;

        // Add mult keys for all previous parties (including current)
        for (usint prevParty = 0; prevParty <= party; prevParty++) {
          auto multKey = cryptoContext_->MultiMultEvalKey(
              partyKeyPairs[prevParty].secretKey, combinedEvalMultKey,
              partyKeyPairs[party].publicKey->GetKeyTag());
          multKeys.push_back(multKey);
        }

        // Combine all multiplication keys
        auto finalMultKey = multKeys[0];
        for (usint i = 1; i < multKeys.size(); i++) {
          finalMultKey = cryptoContext_->MultiAddEvalMultKeys(
              finalMultKey, multKeys[i], multKeys[i]->GetKeyTag());
        }

        // Generate and combine sum evaluation keys
        auto partyEvalSumKeys = cryptoContext_->MultiEvalSumKeyGen(
            partyKeyPairs[party].secretKey, currentEvalSumKeys,
            partyKeyPairs[party].publicKey->GetKeyTag());

        auto combinedEvalSumKeys = cryptoContext_->MultiAddEvalSumKeys(
            currentEvalSumKeys, partyEvalSumKeys,
            partyKeyPairs[party].publicKey->GetKeyTag());

        // Install combined keys in context (for final party only)
        if (party == numParties - 1) {
          cryptoContext_->InsertEvalSumKey(combinedEvalSumKeys);
          cryptoContext_->InsertEvalMultKey({finalMultKey});
        }

        // Update current keys for next iteration
        currentEvalMultKey = combinedEvalMultKey;
        currentEvalSumKeys = combinedEvalSumKeys;
        currentPublicKey = partyKeyPairs[party].publicKey;
      }

      // ============================================================
      // Create and store user session
      // ============================================================
      UserSession session;
      session.jointPublic =
          currentPublicKey; // Final public key from last party
      session.serverSecret = partyKeyPairs[numParties - 1]
                                 .secretKey; // Server holds last party's secret

      // Store all party secrets (for testing/PoC)
      session.partySecrets.reserve(numParties);
      for (const auto &kp : partyKeyPairs) {
        session.partySecrets.push_back(kp.secretKey);
      }

      sessions_[userId] = std::move(session);

      // Return all secret keys
      std::vector<PrivateKey<DCRTPoly>> allSecrets;
      allSecrets.reserve(numParties);
      for (const auto &kp : partyKeyPairs) {
        allSecrets.push_back(kp.secretKey);
      }

      std::cout << "[Store] Successfully created 8-party session for " << userId
                << "\n";
      return {true, allSecrets};

    } catch (const std::exception &e) {
      std::cerr << "[Store] Failed to create 8-party session for " << userId
                << ": " << e.what() << "\n";
      return {false, std::vector<PrivateKey<DCRTPoly>>()};
    }
  }

  /**
   * Enhanced multi-party decryption for 8 parties
   *
   * @param userId User identifier
   * @param ciphertext Ciphertext to decrypt
   * @return Decrypted plaintext
   */
  Plaintext MultiPartyDecrypt8(const std::string &userId,
                               Ciphertext<DCRTPoly> &ciphertext) {
    auto sessionIt = sessions_.find(userId);
    if (sessionIt == sessions_.end()) {
      throw std::runtime_error("User session not found: " + userId);
    }

    const auto &partySecrets = sessionIt->second.partySecrets;
    const usint numParties = partySecrets.size();

    if (numParties != 8) {
      throw std::runtime_error("Expected 8 parties, found: " +
                               std::to_string(numParties));
    }

    try {
      // Perform partial decryption for parties 0 to 6
      std::vector<Ciphertext<DCRTPoly>> partialCiphertexts;
      partialCiphertexts.reserve(numParties);

      for (usint party = 0; party < numParties - 1; party++) {
        auto partial = cryptoContext_->MultipartyDecryptMain(
            {ciphertext}, partySecrets[party]);
        partialCiphertexts.push_back(partial[0]);
      }

      // Final party (party 7) performs lead decryption
      auto leadPartial = cryptoContext_->MultipartyDecryptLead(
          {ciphertext}, partySecrets[numParties - 1]);
      partialCiphertexts.push_back(leadPartial[0]);

      // Fuse all partial decryptions
      Plaintext result;
      cryptoContext_->MultipartyDecryptFusion(partialCiphertexts, &result);

      return result;

    } catch (const std::exception &e) {
      throw std::runtime_error("Multi-party decryption failed: " +
                               std::string(e.what()));
    }
  }

  /**
   * Encrypts and stores a database vector for a specific user
   * Vector is normalized before encryption for cosine similarity computation
   *
   * @param userId User identifier
   * @param vector Database vector to encrypt and store
   * @return Success status
   */
  bool EncryptAndStoreDBVector(const std::string &userId,
                               const std::vector<double> &vector) {
    auto sessionIt = sessions_.find(userId);
    if (sessionIt == sessions_.end()) {
      std::cerr << "[Store] User session not found: " << userId << "\n";
      return false;
    }

    if (vector.size() != VECTOR_DIM) {
      std::cerr << "[Store] Vector dimension mismatch. Expected: " << VECTOR_DIM
                << ", Got: " << vector.size() << "\n";
      return false;
    }

    try {
      // Normalize vector for cosine similarity
      std::vector<double> normalizedVector = vector;
      NormalizeVector(normalizedVector);

      // Create plaintext and encrypt under joint public key
      auto plaintext =
          cryptoContext_->MakeCKKSPackedPlaintext(normalizedVector);
      auto ciphertext =
          cryptoContext_->Encrypt(sessionIt->second.jointPublic, plaintext);

      // Store encrypted vector in session's vector collection
      sessionIt->second.encryptedVectors.push_back(ciphertext);
      return true;

    } catch (const std::exception &e) {
      std::cerr << "[Store] Failed to encrypt vector for " << userId << ": "
                << e.what() << "\n";
      return false;
    }
  }

  /**
   * Encrypts and stores multiple database vectors for a specific user
   * Vectors are normalized before encryption for cosine similarity computation
   *
   * @param userId User identifier
   * @param vectors Vector of database vectors to encrypt and store
   * @return Success status
   */
  bool
  EncryptAndStoreDBVectors(const std::string &userId,
                           const std::vector<std::vector<double>> &vectors) {
    auto sessionIt = sessions_.find(userId);
    if (sessionIt == sessions_.end()) {
      std::cerr << "[Store] User session not found: " << userId << "\n";
      return false;
    }

    try {
      // Reserve space for efficiency
      sessionIt->second.encryptedVectors.reserve(
          sessionIt->second.encryptedVectors.size() + vectors.size());

      for (const auto &vector : vectors) {
        if (vector.size() != VECTOR_DIM) {
          std::cerr << "[Store] Vector dimension mismatch. Expected: "
                    << VECTOR_DIM << ", Got: " << vector.size() << "\n";
          return false;
        }

        // Normalize vector for cosine similarity
        std::vector<double> normalizedVector = vector;
        NormalizeVector(normalizedVector);

        // Create plaintext and encrypt under joint public key
        auto plaintext =
            cryptoContext_->MakeCKKSPackedPlaintext(normalizedVector);
        auto ciphertext =
            cryptoContext_->Encrypt(sessionIt->second.jointPublic, plaintext);

        // Store encrypted vector in session's vector collection
        sessionIt->second.encryptedVectors.push_back(ciphertext);
      }

      return true;

    } catch (const std::exception &e) {
      std::cerr << "[Store] Failed to encrypt vectors for " << userId << ": "
                << e.what() << "\n";
      return false;
    }
  }

  /**
   * Retrieves the joint public key for a user (for client-side encryption)
   *
   * @param userId User identifier
   * @param[out] publicKey Output parameter for the joint public key
   * @return Pair of (success status, joint public key)
   */
  std::pair<bool, PublicKey<DCRTPoly>>
  GetJointPublic(const std::string &userId,
                 PublicKey<DCRTPoly> &publicKey) const {
    auto sessionIt = sessions_.find(userId);
    if (sessionIt == sessions_.end()) {
      return {false, PublicKey<DCRTPoly>()};
    }

    publicKey = sessionIt->second.jointPublic;
    return {true, publicKey};
  }

  /**
   * Retrieves the encrypted vectors for a user
   *
   * @param userId User identifier
   * @return Pair of (success status, reference to encrypted vectors)
   */
  std::pair<bool, const std::vector<Ciphertext<DCRTPoly>> *>
  GetEncryptedVectors(const std::string &userId) const {
    auto sessionIt = sessions_.find(userId);
    if (sessionIt == sessions_.end()) {
      return {false, nullptr};
    }

    return {true, &sessionIt->second.encryptedVectors};
  }

  /**
   * Gets the number of active user sessions
   *
   * @return Number of sessions
   */
  size_t GetSessionCount() const { return sessions_.size(); }

  /**
   * Checks if a user session exists
   *
   * @param userId User identifier to check
   * @return True if session exists
   */
  bool HasSession(const std::string &userId) const {
    return sessions_.find(userId) != sessions_.end();
  }
};

//
// Client-Side Helper Functions
//

/**
 * Encrypts a vector under a joint public key (client-side operation)
 * Vector is automatically normalized for cosine similarity computation
 *
 * @param cryptoContext CKKS crypto context
 * @param jointPublicKey Joint public key obtained from server
 * @param vector Vector to encrypt
 * @return Encrypted vector ciphertext
 */
inline Ciphertext<DCRTPoly>
EncryptVectorForUser(const CryptoContext<DCRTPoly> &cryptoContext,
                     const PublicKey<DCRTPoly> &jointPublicKey,
                     const std::vector<double> &vector) {
  // Normalize vector for cosine similarity
  std::vector<double> normalizedVector = vector;
  NormalizeVector(normalizedVector);

  // Create plaintext and encrypt
  auto plaintext = cryptoContext->MakeCKKSPackedPlaintext(normalizedVector);
  return cryptoContext->Encrypt(jointPublicKey, plaintext);
}

/**
 * Generates user's partial decryption for multiparty computation
 * Used in the first phase of two-party decryption protocol
 *
 * @param cryptoContext CKKS crypto context
 * @param userSecret User's secret key share
 * @param ciphertext Ciphertext to partially decrypt
 * @return User's partial decryption
 */
inline Ciphertext<DCRTPoly>
UserLeadPartial(const CryptoContext<DCRTPoly> &cryptoContext,
                const PrivateKey<DCRTPoly> &userSecret,
                Ciphertext<DCRTPoly> &ciphertext) {
  return cryptoContext->MultipartyDecryptLead({ciphertext}, userSecret)[0];
}

/**
 * Fuses user and server partial decryptions to recover plaintext
 * Final step in two-party decryption protocol
 *
 * @param cryptoContext CKKS crypto context
 * @param userPartial User's partial decryption
 * @param serverPartial Server's partial decryption
 * @return Recovered plaintext
 */
inline Plaintext FusePartials(const CryptoContext<DCRTPoly> &cryptoContext,
                              Ciphertext<DCRTPoly> &userPartial,
                              Ciphertext<DCRTPoly> &serverPartial) {
  std::vector<Ciphertext<DCRTPoly>> partials{userPartial, serverPartial};

  Plaintext result;
  cryptoContext->MultipartyDecryptFusion(partials, &result);

  // Set length to 1 (inner product result is in first slot)
  result->SetLength(1);

  return result;
}

#endif // ENCRYPTED_STORE_H