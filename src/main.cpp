#include "../include/config.h"
#include "../include/openFHE_lib.h"
#include "../include/store.h"
#include "oneapi/tbb/blocked_range.h"
#include <chrono>
#include <cstddef>
#include <fstream>
#include <iostream>
#include <tbb/blocked_range.h>
#include <tbb/parallel_for.h>
#include <tbb/parallel_reduce.h>

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
                       const vector<vector<double>> &dbVectors,
                       size_t userSecretIndex) {
  string userId = "user_" + to_string(userSecretIndex);
  cout << "Creating session for " << userId << "...\n";
  auto [success, userSk] = store.CreateUserSession(userId);
  if (!success) {
    cerr << "[ERROR] Failed to create session for " << userId << "\n";
    return false;
  }
  store.EncryptAndStoreDBVectors(userId, dbVectors);

  return true;
}

/**
 * Computes encrypted dot products in parallel using rotation-based summation
 */
vector<Ciphertext<DCRTPoly>> computeEncryptedDotProducts(
    CryptoContext<DCRTPoly> cc, const Plaintext &encQuery,
    const std::vector<Ciphertext<DCRTPoly>> &sessionVec) {
  vector<Ciphertext<DCRTPoly>> encProducts(sessionVec.size());

  tbb::parallel_for(tbb::blocked_range<size_t>(0, sessionVec.size()),
                    [&](const tbb::blocked_range<size_t> &range) {
                      for (size_t i = range.begin(); i < range.end(); ++i) {
                        const auto &session = sessionVec[i];

                        // Multiply query with encrypted database vector
                        auto product = cc->EvalMult(encQuery, session);

                        // Sum all elements using rotation (log(n) rotations for
                        // n elements)
                        for (int rotationStep = 1;
                             rotationStep < static_cast<int>(VECTOR_DIM);
                             rotationStep *= 2) {
                          auto rotated = cc->EvalRotate(product, rotationStep);
                          product = cc->EvalAdd(product, rotated);
                        }

                        encProducts[i] = product;
                      }
                    });

  return encProducts;
}

/**
 * Attempts to decrypt similarity scores and find the best match using 8-party
 * decryption
 */
pair<double, string>
findBestMatch(InMemoryStore &store,
              const vector<Ciphertext<DCRTPoly>> &encProducts,
              const string &userId) {
  std::vector<double> similarities(encProducts.size());

  // Parallel decryption and extraction using oneTBB
  tbb::parallel_for(
      tbb::blocked_range<size_t>(0, encProducts.size()),
      [&](const tbb::blocked_range<size_t> &range) {
        for (size_t i = range.begin(); i < range.end(); ++i) {
          try {
            // Perform 8-party decryption using the store's MultiPartyDecrypt8
            // method
            auto decryptedResult = store.MultiPartyDecrypt8(
                userId, const_cast<Ciphertext<DCRTPoly> &>(encProducts[i]));
            auto values = decryptedResult->GetRealPackedValue();
            similarities[i] = values.empty() ? -1.0 : values[0];
          } catch (const std::exception &e) {
            std::cerr << "[ERROR] Decryption failed for vector " << i << ": "
                      << e.what() << "\n";
            similarities[i] = -1.0;
          }
        }
      });

  // Use oneTBB to find the max similarity and its index
  struct MaxResult {
    double value;
    size_t index;
  };

  MaxResult maxRes = tbb::parallel_reduce(
      tbb::blocked_range<size_t>(0, similarities.size()), MaxResult{-1.0, 0},
      [&](const tbb::blocked_range<size_t> &range,
          MaxResult init) -> MaxResult {
        for (size_t i = range.begin(); i < range.end(); ++i) {
          if (similarities[i] > init.value) {
            init.value = similarities[i];
            init.index = i;
          }
        }
        return init;
      },
      [](const MaxResult &a, const MaxResult &b) -> MaxResult {
        return (a.value > b.value) ? a : b;
      });

  return {maxRes.value, std::to_string(maxRes.index)};
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
  if (!setupUserSessions(store, dbVectors, userSecretIndex)) {
    return EXIT_ERROR;
  }

  // Prepare encrypted query
  auto encryptedQuery = cryptoContext->MakeCKKSPackedPlaintext(queryVector);
  string targetUserId = "user_" + to_string(userSecretIndex);

  cout << "Beginning similarity search...\n";
  auto [success, sessionVectors] = store.GetEncryptedVectors(targetUserId);
  if (!success) {
    cerr << "[ERROR] Failed to get encrypted vectors for " << targetUserId
         << "\n";
    return EXIT_ERROR;
  }

  // Time the search operation
  auto searchStartTime = chrono::high_resolution_clock::now();

  // Compute encrypted dot products in parallel
  auto encryptedProducts = computeEncryptedDotProducts(
      cryptoContext, encryptedQuery, *sessionVectors);

  // Find the best matching vector using 8-party decryption
  auto [bestSimilarity, bestUserId] =
      findBestMatch(store, encryptedProducts, targetUserId);

  auto searchEndTime = chrono::high_resolution_clock::now();
  auto searchDuration =
      chrono::duration<double, milli>(searchEndTime - searchStartTime);

  // Output results
  cout << "Maximum cosine similarity: " << bestSimilarity
       << " (User: " << bestUserId << ")\n";
  cout << "Search completed in: " << searchDuration.count() << " ms\n";
}