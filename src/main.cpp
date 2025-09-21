#include "../include/config.h"
#include "../include/openFHE_lib.h"
#include "../include/store.h"
#include "oneapi/tbb/blocked_range.h"
#include <chrono>
#include <fstream>
#include <iostream>
#include <tbb/blocked_range.h>
#include <tbb/parallel_for.h>

using namespace lbcrypto;
using namespace std;

// Constants for better readability
constexpr int EXIT_ERROR = 1;

/**
 * Validates command line arguments and opens input file
 */
pair<bool, ifstream> validateAndOpenFile(int argc, char *argv[]) {
  if (argc <= 1) {
    cerr << "Error: no input file specified\n";
    return {false, ifstream{}};
  }

  ifstream fileStream(argv[1]);
  if (!fileStream) {
    cerr << "Error: input file not found\n";
    return {false, ifstream{}};
  }

  return {true, std::move(fileStream)};
}

/**
 * Reads query vector from file stream and normalizes it
 */
vector<double> readAndNormalizeQueryVector(ifstream &fileStream) {
  vector<double> queryVector(VECTOR_DIM);
  for (auto &value : queryVector) {
    fileStream >> value;
  }
  OpenFHEImpl::plaintextNormalize(queryVector, VECTOR_DIM);
  return queryVector;
}

/**
 * Reads database vectors from file stream
 */
vector<vector<double>> readDatabaseVectors(ifstream &fileStream,
                                           size_t numVectors) {
  vector<vector<double>> dbVectors(numVectors, vector<double>(VECTOR_DIM));
  for (auto &vec : dbVectors) {
    for (auto &value : vec) {
      fileStream >> value;
    }
  }
  return dbVectors;
}

/**
 * Creates user sessions and encrypts database vectors
 */
bool setupUserSessions(InMemoryStore &store,
                       const vector<vector<double>> &dbVectors) {
  for (size_t i = 0; i < dbVectors.size(); ++i) {
    string userId = "user_" + to_string(i);
    cout << "Creating session for " << userId << "...\n";

    auto [success, userSk] = store.CreateUserSession(userId);
    if (!success) {
      cerr << "[ERROR] Failed to create session for " << userId << "\n";
      return false;
    }

    store.EncryptAndStoreDBVector(userId, dbVectors[i]);
  }
  return true;
}

/**
 * Computes encrypted dot products in parallel using rotation-based summation
 */
vector<Ciphertext<DCRTPoly>> computeEncryptedDotProducts(
    CryptoContext<DCRTPoly> cc, const Plaintext &encQuery,
    const vector<pair<string, UserSession>> &sessionVec) {
  vector<Ciphertext<DCRTPoly>> encProducts(sessionVec.size());

  tbb::parallel_for(
      tbb::blocked_range<size_t>(0, sessionVec.size()),
      [&](const tbb::blocked_range<size_t> &range) {
        for (size_t i = range.begin(); i < range.end(); ++i) {
          const auto &session = sessionVec[i].second;

          // Multiply query with encrypted database vector
          auto product = cc->EvalMult(encQuery, session.encryptedVector);

          // Sum all elements using rotation (log(n) rotations for n elements)
          for (int rotationStep = 1;
               rotationStep < static_cast<int>(VECTOR_DIM); rotationStep *= 2) {
            auto rotated = cc->EvalRotate(product, rotationStep);
            product = cc->EvalAdd(product, rotated);
          }

          encProducts[i] = product;
        }
      });

  return encProducts;
}

/**
 * Attempts to decrypt similarity scores and find the best match
 */
pair<double, string>
findBestMatch(CryptoContext<DCRTPoly> cc,
              const vector<Ciphertext<DCRTPoly>> &encProducts,
              const vector<pair<string, UserSession>> &sessionVec,
              const PrivateKey<DCRTPoly> &userSecret,
              const PrivateKey<DCRTPoly> &serverSecret) {
  double bestSimilarity = -1.0;
  string bestUserId;

  for (size_t i = 0; i < encProducts.size(); ++i) {
    try {
      // Perform multi-party decryption
      auto userPartial =
          cc->MultipartyDecryptLead({encProducts[i]}, userSecret);
      auto serverPartial =
          cc->MultipartyDecryptMain({encProducts[i]}, serverSecret);

      // Fuse partial decryptions and extract result
      auto fusedResult = FusePartials(cc, userPartial[0], serverPartial[0]);
      auto values = fusedResult->GetRealPackedValue();

      if (!values.empty()) {
        bestSimilarity = values[0];
        bestUserId = sessionVec[i].first;
        break; // Found first valid result
      }
    } catch (const exception &e) {
      // Continue to next encrypted product if decryption fails
      continue;
    }
  }

  return {bestSimilarity, bestUserId};
}

int main(int argc, char *argv[]) {
  // Validate input and open file
  auto [fileValid, fileStream] = validateAndOpenFile(argc, argv);
  if (!fileValid) {
    return EXIT_ERROR;
  }

  cout << "Setting up cryptographic parameters...\n";
  CryptoContext<DCRTPoly> cryptoContext = InitCKKSContext();
  InMemoryStore store(cryptoContext);

  // Read input parameters
  size_t numVectors;
  size_t userSecretIndex;
  fileStream >> numVectors >> userSecretIndex;

  // Read and process input data
  cout << "Reading query vector...\n";
  auto queryVector = readAndNormalizeQueryVector(fileStream);

  cout << "Reading database vectors...\n";
  auto dbVectors = readDatabaseVectors(fileStream, numVectors);
  fileStream.close();

  // Setup encrypted sessions
  cout << "Setting up user sessions and encrypting vectors...\n";
  if (!setupUserSessions(store, dbVectors)) {
    return EXIT_ERROR;
  }

  // Prepare encrypted query
  auto encryptedQuery = cryptoContext->MakeCKKSPackedPlaintext(queryVector);

  cout << "Beginning similarity search...\n";
  vector<pair<string, UserSession>> sessionVector(store.sessions_.begin(),
                                                  store.sessions_.end());

  // Time the search operation
  auto searchStartTime = chrono::high_resolution_clock::now();

  // Compute encrypted dot products in parallel
  auto encryptedProducts =
      computeEncryptedDotProducts(cryptoContext, encryptedQuery, sessionVector);

  // Get decryption keys for the specified user
  string targetUserId = "user_" + to_string(userSecretIndex);
  auto targetUserSession = store.sessions_[targetUserId];
  auto userSecret = targetUserSession.clientSecret;
  auto serverSecret = targetUserSession.serverSecret;

  // Find the best matching vector
  auto [bestSimilarity, bestUserId] =
      findBestMatch(cryptoContext, encryptedProducts, sessionVector, userSecret,
                    serverSecret);

  auto searchEndTime = chrono::high_resolution_clock::now();
  auto searchDuration =
      chrono::duration<double, milli>(searchEndTime - searchStartTime);

  // Output results
  cout << "Maximum cosine similarity: " << bestSimilarity
       << " (User: " << bestUserId << ")\n";
  cout << "Search completed in: " << searchDuration.count() << " ms\n";
}