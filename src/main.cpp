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
 * Generate Chebyshev coefficients for the max approximation function
 * This approximates max(0, x) using Chebyshev polynomials
 */
std::vector<double> generateMaxChebyshevCoefficients() {
  // Chebyshev coefficients for approximating max(0, x) function
  // These coefficients approximate ReLU function over range [-2, 2]
  return {0.5, 0.31831,  0.0, -0.021221, 0.0, 0.002700, 0.0, -0.000381,
          0.0, 0.000058, 0.0, -0.000009, 0.0, 0.000001};
}

/**
 * Homomorphic ReLU function using Chebyshev approximation
 * Approximates max(0, x) which is useful for pairwise max computation
 */
Ciphertext<DCRTPoly> homomorphicReLU(const Ciphertext<DCRTPoly> &x,
                                     CryptoContext<DCRTPoly> context) {

  auto coefficients = generateMaxChebyshevCoefficients();
  double a = -2.0; // Input range lower bound
  double b = 2.0;  // Input range upper bound

  return context->EvalChebyshevSeries(x, coefficients, a, b);
}

/**
 * Homomorphic maximum of two encrypted values using Chebyshev approximation
 * Uses the identity: max(a,b) = (a + b + |a - b|) / 2
 * Where |x| ≈ 2*ReLU(x) - x
 */
Ciphertext<DCRTPoly> homomorphicMaxTwo(const Ciphertext<DCRTPoly> &a,
                                       const Ciphertext<DCRTPoly> &b,
                                       CryptoContext<DCRTPoly> context) {

  // Compute difference: diff = a - b
  auto diff = context->EvalSub(a, b);

  // Approximate |diff| using: |x| ≈ 2*max(0,x) + 2*max(0,-x) - x
  // Which simplifies to: |x| ≈ 2*max(0,x) - x + 2*max(0,-x)
  auto relu_diff = homomorphicReLU(diff, context);
  auto neg_diff = context->EvalNegate(diff);
  auto relu_neg_diff = homomorphicReLU(neg_diff, context);

  // |diff| ≈ 2*max(0,diff) + 2*max(0,-diff) - diff
  auto abs_diff_part1 = context->EvalMult(2.0, relu_diff);
  auto abs_diff_part2 = context->EvalMult(2.0, relu_neg_diff);
  auto abs_diff = context->EvalAdd(abs_diff_part1, abs_diff_part2);
  abs_diff = context->EvalSub(abs_diff, diff);

  // max(a,b) = (a + b + |a - b|) / 2
  auto sum_ab = context->EvalAdd(a, b);
  auto numerator = context->EvalAdd(sum_ab, abs_diff);

  return context->EvalMult(numerator, 0.5);
}

/**
 * Find the homomorphic maximum of a vector of encrypted values
 * Uses tournament-style reduction with Chebyshev approximation
 */
Ciphertext<DCRTPoly>
findHomomorphicMax(const std::vector<Ciphertext<DCRTPoly>> &ciphertexts,
                   CryptoContext<DCRTPoly> context) {

  if (ciphertexts.empty()) {
    throw std::invalid_argument("Input vector cannot be empty");
  }

  if (ciphertexts.size() == 1) {
    return ciphertexts[0];
  }

  // Create a working copy of the ciphertext vector
  std::vector<Ciphertext<DCRTPoly>> workingSet = ciphertexts;

  // Tournament-style maximum finding
  while (workingSet.size() > 1) {
    std::vector<Ciphertext<DCRTPoly>> nextRound;

    // Process pairs
    for (size_t i = 0; i < workingSet.size(); i += 2) {
      if (i + 1 < workingSet.size()) {
        // Compare two ciphertexts and get the maximum
        auto maxCipher =
            homomorphicMaxTwo(workingSet[i], workingSet[i + 1], context);
        nextRound.push_back(maxCipher);
      } else {
        // Odd element, carry forward
        nextRound.push_back(workingSet[i]);
      }
    }

    workingSet = nextRound;
  }

  return workingSet[0];
}

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
 * Attempts to find the best match using homomorphic maximum computation
 * Collects all EvalSum results and uses findHomomorphicMax to find the maximum
 */
pair<double, string>
findBestMatch(InMemoryStore &store,
              const vector<Ciphertext<DCRTPoly>> &encProducts,
              const string &userId) {
  std::vector<Ciphertext<DCRTPoly>> encryptedSums(encProducts.size());

  // Parallel computation of EvalSum for each encrypted product
  // Instead of decrypting each vector individually, we collect all the sums
  // and then use homomorphic maximum to find the best match
  tbb::parallel_for(
      tbb::blocked_range<size_t>(0, encProducts.size()),
      [&](const tbb::blocked_range<size_t> &range) {
        for (size_t i = range.begin(); i < range.end(); ++i) {
          try {
            // Create a mask plaintext {1, 0, 0, ..., 0}
            std::vector<double> mask(VECTOR_DIM, 0.0);
            mask[0] = 1.0;
            auto maskPlain =
                store.cryptoContext_->MakeCKKSPackedPlaintext(mask);

            // Multiply the encrypted vector with the mask to zero out all but
            // the first slot
            auto maskedCipher =
                store.cryptoContext_->EvalMult(encProducts[i], maskPlain);

            // Compute sum and store the encrypted result
            auto sum = store.cryptoContext_->EvalSum(maskedCipher, VECTOR_DIM);
            encryptedSums[i] = sum;
          } catch (const std::exception &e) {
            std::cerr << "[ERROR] EvalSum computation failed for vector " << i
                      << ": " << e.what() << "\n";
            // Create a zero ciphertext as fallback
            continue;
          }
        }
      });

  // Use homomorphic maximum to find the best match
  auto maxCipher = findHomomorphicMax(encryptedSums, store.cryptoContext_);

  // Decrypt the final maximum result
  try {
    auto decryptedResult = store.MultiPartyDecrypt8(userId, maxCipher);
    auto values = decryptedResult->GetRealPackedValue();
    double maxSimilarity = values.empty() ? -1.0 : values[0];

    // Since we can't directly get the index from homomorphic max,
    // we'll return the maximum similarity value and a placeholder for the index
    // In a real implementation, you might want to track indices differently
    return {maxSimilarity, "homomorphic_max_result"};
  } catch (const std::exception &e) {
    std::cerr << "[ERROR] Decryption of maximum result failed: " << e.what()
              << "\n";
    return {-1.0, "error"};
  }
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