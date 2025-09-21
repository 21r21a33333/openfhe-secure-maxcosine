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

// Helper function to check if bootstrapping is needed and perform it
Ciphertext<DCRTPoly> ensureValidLevel(const CryptoContext<DCRTPoly> &cc,
                                      const Ciphertext<DCRTPoly> &ciphertext) {
  cout << "[DEBUG] Checking ciphertext level: " << ciphertext->GetLevel()
       << endl;
  // If ciphertext level is too low (less than 2), bootstrap it
  if (ciphertext->GetLevel() < 2) {
    cout << "[DEBUG] Bootstrapping ciphertext..." << endl;
    return cc->EvalBootstrap(ciphertext);
  }
  cout << "[DEBUG] Ciphertext level sufficient, no bootstrapping needed."
       << endl;
  return ciphertext;
}

// Polynomial approximation for absolute value (optimized for depth)
Ciphertext<DCRTPoly> ApproximateAbs(const CryptoContext<DCRTPoly> &cc,
                                    const Ciphertext<DCRTPoly> &x) {
  cout << "[DEBUG] Starting ApproximateAbs..." << endl;
  // Use a simpler polynomial approximation for |x| on [-1, 1]
  // P(x) = a0 + a1*x^2 (reduced from 3 terms to 2 terms)

  cout << "[DEBUG] Computing x^2..." << endl;
  auto x2 = cc->EvalMult(x, x);

  // Coefficients for simplified approximation of |x|
  std::vector<double> coeffs(VECTOR_DIM);

  // First term: 0.6366 * x^2
  cout << "[DEBUG] Computing first term: 0.6366 * x^2..." << endl;
  std::fill(coeffs.begin(), coeffs.end(), 0.6366);
  auto term0 = cc->EvalMult(x2, cc->MakeCKKSPackedPlaintext(coeffs));

  // Second term: -0.2122 * x^4 (computed as x^2 * x^2)
  cout << "[DEBUG] Computing second term: -0.2122 * x^4..." << endl;
  std::fill(coeffs.begin(), coeffs.end(), -0.2122);
  auto x4 = cc->EvalMult(x2, x2);
  auto term1 = cc->EvalMult(x4, cc->MakeCKKSPackedPlaintext(coeffs));

  cout << "[DEBUG] Adding terms for final result..." << endl;
  auto result = cc->EvalAdd(term0, term1);

  cout << "[DEBUG] ApproximateAbs complete." << endl;
  return result;
}

// Approximate max function using polynomial approximation
Ciphertext<DCRTPoly> ApproximateMax(const CryptoContext<DCRTPoly> &cc,
                                    const Ciphertext<DCRTPoly> &a,
                                    const Ciphertext<DCRTPoly> &b) {
  cout << "[DEBUG] Starting ApproximateMax..." << endl;
  // max(a,b) ≈ (a + b + |a - b|) / 2
  cout << "[DEBUG] Computing sum = a + b..." << endl;
  auto sum = cc->EvalAdd(a, b);
  cout << "[DEBUG] Computing diff = a - b..." << endl;
  auto diff = cc->EvalSub(a, b);

  // Approximate |diff| using polynomial approximation
  cout << "[DEBUG] Approximating |diff|..." << endl;
  auto absDiff = ApproximateAbs(cc, diff);

  cout << "[DEBUG] Adding sum and absDiff for numerator..." << endl;
  auto numerator = cc->EvalAdd(sum, absDiff);

  // Ensure we have enough levels before the final multiplication
  cout << "[DEBUG] Ensuring valid level before division by 2..." << endl;
  numerator = ensureValidLevel(cc, numerator);

  // Divide by 2 (multiply by 0.5)
  std::vector<double> halfVec(VECTOR_DIM, 0.5);
  auto halfPlaintext = cc->MakeCKKSPackedPlaintext(halfVec);

  cout
      << "[DEBUG] Multiplying numerator by 0.5 to complete max approximation..."
      << endl;
  auto result = cc->EvalMult(numerator, halfPlaintext);

  cout << "[DEBUG] ApproximateMax complete." << endl;
  return result;
}

// Compute homomorphic maximum across multiple encrypted similarities
Ciphertext<DCRTPoly>
ComputeEncryptedMax(const CryptoContext<DCRTPoly> &cc,
                    const std::vector<Ciphertext<DCRTPoly>> &similarities) {
  cout << "[DEBUG] Starting ComputeEncryptedMax..." << endl;
  if (similarities.empty()) {
    cerr << "[ERROR] Cannot compute max of empty vector" << endl;
    throw std::invalid_argument("Cannot compute max of empty vector");
  }

  if (similarities.size() == 1) {
    cout << "[DEBUG] Only one similarity value, returning it directly." << endl;
    return similarities[0];
  }

  // Use tree reduction to compute maximum
  auto result = similarities[0];
  for (size_t i = 1; i < similarities.size(); i++) {
    cout << "[DEBUG] Computing max for element " << i << "..." << endl;
    // Ensure result has enough levels before each comparison
    result = ensureValidLevel(cc, result);
    result = ApproximateMax(cc, result, similarities[i]);
    cout << "[DEBUG] Max after element " << i << " computed." << endl;
  }

  cout << "[DEBUG] ComputeEncryptedMax complete." << endl;
  return result;
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

  std::cout << "[DEBUG] Starting computeEncryptedDotProducts for "
            << sessionVec.size() << " database vectors.\n";

  tbb::parallel_for(
      tbb::blocked_range<size_t>(0, sessionVec.size()),
      [&](const tbb::blocked_range<size_t> &range) {
        for (size_t i = range.begin(); i < range.end(); ++i) {
          const auto &session = sessionVec[i];

          std::cout << "[DEBUG] [Thread "
                    << tbb::this_task_arena::current_thread_index()
                    << "] Processing vector " << i << "...\n";

          // Multiply query with encrypted database vector
          std::cout << "[DEBUG] [Thread "
                    << tbb::this_task_arena::current_thread_index()
                    << "] EvalMult for vector " << i << ".\n";
          auto product = cc->EvalMult(encQuery, session);

          // Sum all elements using rotation (log(n) rotations for n elements)
          for (int rotationStep = 1;
               rotationStep < static_cast<int>(VECTOR_DIM); rotationStep *= 2) {
            std::cout << "[DEBUG] [Thread "
                      << tbb::this_task_arena::current_thread_index()
                      << "] EvalRotate by " << rotationStep << " for vector "
                      << i << ".\n";
            auto rotated = cc->EvalRotate(product, rotationStep);
            product = cc->EvalAdd(product, rotated);
          }

          encProducts[i] = product;
          std::cout << "[DEBUG] [Thread "
                    << tbb::this_task_arena::current_thread_index()
                    << "] Finished encrypted dot product for vector " << i
                    << ".\n";
        }
      });

  std::cout << "[DEBUG] Finished computeEncryptedDotProducts.\n";
  return encProducts;
}

/**
 * Attempts to decrypt similarity scores and find the best match
 */
pair<double, string>
findBestMatch(CryptoContext<DCRTPoly> cc,
              const vector<Ciphertext<DCRTPoly>> &encProducts,
              const PrivateKey<DCRTPoly> &userSecret,
              const PrivateKey<DCRTPoly> &serverSecret) {
  std::vector<double> similarities(encProducts.size());

  // Parallel decryption and extraction using oneTBB
  tbb::parallel_for(
      tbb::blocked_range<size_t>(0, encProducts.size()),
      [&](const tbb::blocked_range<size_t> &range) {
        for (size_t i = range.begin(); i < range.end(); ++i) {
          // Perform multi-party decryption
          auto userPartial =
              cc->MultipartyDecryptLead({encProducts[i]}, userSecret);
          auto serverPartial =
              cc->MultipartyDecryptMain({encProducts[i]}, serverSecret);

          // Fuse partial decryptions and extract result
          auto fusedResult = FusePartials(cc, userPartial[0], serverPartial[0]);
          auto values = fusedResult->GetRealPackedValue();
          similarities[i] = values.empty() ? -1.0 : values[0];
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

  cout << "Got encrypted vectors for " << targetUserId << "\n";
  // Time the search operation
  auto searchStartTime = chrono::high_resolution_clock::now();

  // Compute encrypted dot products in parallel
  auto encryptedProducts = computeEncryptedDotProducts(
      cryptoContext, encryptedQuery, *sessionVectors);

  // Compute Min of the encrypted products
  auto encryptedMin = ComputeEncryptedMax(cryptoContext, encryptedProducts);

  // Get decryption keys for the specified user
  auto targetUserSession = store.sessions_[targetUserId];
  auto userSecret = targetUserSession.clientSecret;
  auto serverSecret = targetUserSession.serverSecret;

  auto userPartial =
      cryptoContext->MultipartyDecryptLead({encryptedMin}, userSecret);
  auto serverPartial =
      cryptoContext->MultipartyDecryptMain({encryptedMin}, serverSecret);

  // Fuse partial decryptions and extract result
  auto fusedResult =
      FusePartials(cryptoContext, userPartial[0], serverPartial[0]);
  auto values = fusedResult->GetRealPackedValue();
  auto bestSimilarity = values[0];

  auto searchEndTime = chrono::high_resolution_clock::now();
  auto searchDuration =
      chrono::duration<double, milli>(searchEndTime - searchStartTime);
  // Output results
  cout << "Maximum cosine similarity: " << bestSimilarity << "\n";
  cout << "Search completed in: " << searchDuration.count() << " ms\n";
}