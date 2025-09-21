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

/**
 * Represents a user session with multiparty homomorphic encryption keys
 */
struct UserSession {
  // Joint public key shared between user and server
  PublicKey<DCRTPoly> jointPublic;

  // Server's secret key share (server retains this)
  PrivateKey<DCRTPoly> serverSecret;

  // Multiple encrypted database vectors stored under joint public key
  std::vector<Ciphertext<DCRTPoly>> encryptedVectors;

  // Client's secret key share (for testing/PoC only - normally not stored
  // server-side)
  PrivateKey<DCRTPoly> clientSecret;
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
  cryptoContext->Enable(FHE); // Fully homomorphic encryption (bootstrapping)

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

  /**
   * Constructs store with given cryptographic context
   *
   * @param cryptoContext CKKS context for encryption operations
   */
  explicit InMemoryStore(
      const CryptoContext<DCRTPoly> &cryptoContext = InitCKKSContext())
      : cryptoContext_(cryptoContext) {}

  /**
   * Creates a new multiparty user session with joint key generation
   * Implements two-party key generation protocol between client and server
   *
   * @param userId Unique identifier for the user
   * @return Pair of (success status, client's secret key to return to user)
   */
  std::pair<bool, PrivateKey<DCRTPoly>>
  CreateUserSession(const std::string &userId) {
    // Check if user already exists
    if (sessions_.count(userId)) {
      std::cerr << "[Store] User ID already exists: " << userId << "\n";
      return {false, PrivateKey<DCRTPoly>()};
    }

    try {
      // Generate rotation keys for efficient vector operations
      auto rotationFactors = GenerateBinaryRotationFactors(VECTOR_DIM);

      // Step 1: Client generates initial key pair
      auto clientKeyPair = cryptoContext_->KeyGen();

      // Step 2: Generate evaluation keys for client
      auto clientEvalMultKey = cryptoContext_->KeySwitchGen(
          clientKeyPair.secretKey, clientKeyPair.secretKey);

      // Generate sum evaluation keys for client
      cryptoContext_->EvalSumKeyGen(clientKeyPair.secretKey);
      auto clientEvalSumKeys =
          std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(
              cryptoContext_->GetEvalSumKeyMap(
                  clientKeyPair.secretKey->GetKeyTag()));

      // Step 3: Server generates multiparty keys
      auto serverKeyPair =
          cryptoContext_->MultipartyKeyGen(clientKeyPair.publicKey);

      // Generate server's evaluation keys
      auto serverEvalMultKey = cryptoContext_->MultiKeySwitchGen(
          serverKeyPair.secretKey, serverKeyPair.secretKey, clientEvalMultKey);

      // Step 4: Combine evaluation keys
      auto jointEvalMultKey = cryptoContext_->MultiAddEvalKeys(
          clientEvalMultKey, serverEvalMultKey,
          serverKeyPair.publicKey->GetKeyTag());

      auto serverMultKey = cryptoContext_->MultiMultEvalKey(
          serverKeyPair.secretKey, jointEvalMultKey,
          serverKeyPair.publicKey->GetKeyTag());

      // Generate and combine sum evaluation keys
      auto serverEvalSumKeys = cryptoContext_->MultiEvalSumKeyGen(
          serverKeyPair.secretKey, clientEvalSumKeys,
          serverKeyPair.publicKey->GetKeyTag());

      auto jointEvalSumKeys = cryptoContext_->MultiAddEvalSumKeys(
          clientEvalSumKeys, serverEvalSumKeys,
          serverKeyPair.publicKey->GetKeyTag());

      // Install combined evaluation keys in context
      cryptoContext_->InsertEvalSumKey(jointEvalSumKeys);

      auto clientMultKey = cryptoContext_->MultiMultEvalKey(
          clientKeyPair.secretKey, jointEvalMultKey,
          serverKeyPair.publicKey->GetKeyTag());

      auto finalEvalMultKey = cryptoContext_->MultiAddEvalMultKeys(
          clientMultKey, serverMultKey, jointEvalMultKey->GetKeyTag());

      cryptoContext_->InsertEvalMultKey({finalEvalMultKey});

      // Step 5: Create and store user session
      UserSession session;
      session.jointPublic = serverKeyPair.publicKey;
      session.serverSecret = serverKeyPair.secretKey;
      session.clientSecret = clientKeyPair.secretKey;

      sessions_[userId] = std::move(session);

      // Return client's secret key (to be sent to user)
      return {true, clientKeyPair.secretKey};

    } catch (const std::exception &e) {
      std::cerr << "[Store] Failed to create session for " << userId << ": "
                << e.what() << "\n";
      return {false, PrivateKey<DCRTPoly>()};
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
    std::cout << "[DEBUG][Store] EncryptAndStoreDBVectors called for user: "
              << userId << " with " << vectors.size() << " vectors.\n";
    auto sessionIt = sessions_.find(userId);
    if (sessionIt == sessions_.end()) {
      std::cerr << "[Store] User session not found: " << userId << "\n";
      return false;
    }

    try {
      // Reserve space for efficiency
      std::cout << "[DEBUG][Store] Reserving space for " << vectors.size()
                << " new encrypted vectors (current size: "
                << sessionIt->second.encryptedVectors.size() << ").\n";
      sessionIt->second.encryptedVectors.reserve(
          sessionIt->second.encryptedVectors.size() + vectors.size());

      size_t idx = 0;
      for (const auto &vector : vectors) {
        std::cout << "[DEBUG][Store] Processing vector " << idx << "...\n";
        if (vector.size() != VECTOR_DIM) {
          std::cerr << "[Store] Vector dimension mismatch. Expected: "
                    << VECTOR_DIM << ", Got: " << vector.size() << "\n";
          return false;
        }

        // Normalize vector for cosine similarity
        std::vector<double> normalizedVector = vector;
        std::cout << "[DEBUG][Store] Normalizing vector " << idx << ".\n";
        NormalizeVector(normalizedVector);

        // Create plaintext and encrypt under joint public key
        std::cout << "[DEBUG][Store] Creating plaintext for vector " << idx
                  << ".\n";
        auto plaintext =
            cryptoContext_->MakeCKKSPackedPlaintext(normalizedVector);
        std::cout << "[DEBUG][Store] Encrypting plaintext for vector " << idx
                  << ".\n";
        auto ciphertext =
            cryptoContext_->Encrypt(sessionIt->second.jointPublic, plaintext);

        // Store encrypted vector in session's vector collection
        sessionIt->second.encryptedVectors.push_back(ciphertext);
        std::cout << "[DEBUG][Store] Encrypted vector " << idx << " stored.\n";
        ++idx;
      }

      std::cout << "[DEBUG][Store] Successfully encrypted and stored "
                << vectors.size() << " vectors for user: " << userId << ".\n";
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

private:
  const CryptoContext<DCRTPoly> cryptoContext_;
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