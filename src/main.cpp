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
       << "\n";

  // Check if ciphertext level is valid for bootstrapping
  if (ciphertext->GetLevel() <= 0) {
    cout << "[ERROR] Ciphertext level is " << ciphertext->GetLevel()
         << " which is too low for bootstrapping. Cannot proceed.\n";
    throw std::runtime_error("Ciphertext level too low for bootstrapping");
  }

  // If ciphertext level is too low (less than 2), bootstrap it
  if (ciphertext->GetLevel() < 2) {
    cout << "[DEBUG] Bootstrapping ciphertext from level "
         << ciphertext->GetLevel() << "...\n";
    try {
      auto bootstrapped = cc->EvalBootstrap(ciphertext);
      cout << "[DEBUG] Bootstrap successful, new level: "
           << bootstrapped->GetLevel() << "\n";
      return bootstrapped;
    } catch (const std::exception &e) {
      cout << "[ERROR] Bootstrap failed: " << e.what() << "\n";
      throw;
    }
  }

  cout << "[DEBUG] Ciphertext level sufficient (" << ciphertext->GetLevel()
       << "), no bootstrapping needed.\n";
  return ciphertext;
}

// Helper function to ensure minimum level before operations
Ciphertext<DCRTPoly> ensureMinimumLevel(const CryptoContext<DCRTPoly> &cc,
                                        const Ciphertext<DCRTPoly> &ciphertext,
                                        size_t requiredLevel = 2) {
  cout << "[DEBUG] Ensuring minimum level " << requiredLevel
       << " for ciphertext with level " << ciphertext->GetLevel() << "\n";

  if (ciphertext->GetLevel() >= requiredLevel) {
    cout << "[DEBUG] Ciphertext already has sufficient level.\n";
    return ciphertext;
  }

  return ensureValidLevel(cc, ciphertext);
}

// Polynomial approximation for absolute value (optimized for depth)
Ciphertext<DCRTPoly> ApproximateAbs(const CryptoContext<DCRTPoly> &cc,
                                    const Ciphertext<DCRTPoly> &x) {
  cout << "[DEBUG] Starting ApproximateAbs with input level: " << x->GetLevel()
       << "\n";

  // Ensure input has sufficient level for computation
  auto input = ensureMinimumLevel(cc, x, 1);

  // Use a simpler polynomial approximation for |x| on [-1, 1]
  // P(x) = a0 + a1*x^2 (reduced from 3 terms to 2 terms)

  cout << "[DEBUG] Computing x^2...\n";
  auto x2 = cc->EvalMult(input, input);
  cout << "[DEBUG] x^2 level: " << x2->GetLevel() << "\n";

  // Coefficients for simplified approximation of |x|
  std::vector<double> coeffs(VECTOR_DIM);

  // First term: 0.6366 * x^2
  cout << "[DEBUG] Computing first term: 0.6366 * x^2...\n";
  std::fill(coeffs.begin(), coeffs.end(), 0.6366);
  auto term0 = cc->EvalMult(x2, cc->MakeCKKSPackedPlaintext(coeffs));
  cout << "[DEBUG] term0 level: " << term0->GetLevel() << "\n";

  // Second term: -0.2122 * x^4 (computed as x^2 * x^2)
  cout << "[DEBUG] Computing second term: -0.2122 * x^4...\n";
  std::fill(coeffs.begin(), coeffs.end(), -0.2122);
  auto x4 = cc->EvalMult(x2, x2);
  cout << "[DEBUG] x^4 level: " << x4->GetLevel() << "\n";

  // Ensure x4 has enough level before multiplying by coefficient
  x4 = ensureMinimumLevel(cc, x4, 1);

  auto term1 = cc->EvalMult(x4, cc->MakeCKKSPackedPlaintext(coeffs));
  cout << "[DEBUG] term1 level: " << term1->GetLevel() << "\n";

  cout << "[DEBUG] Adding terms for final result...\n";
  auto result = cc->EvalAdd(term0, term1);
  cout << "[DEBUG] ApproximateAbs result level: " << result->GetLevel() << "\n";

  cout << "[DEBUG] ApproximateAbs complete.\n";
  return result;
}

// Approximate max function using polynomial approximation
Ciphertext<DCRTPoly> ApproximateMax(const CryptoContext<DCRTPoly> &cc,
                                    const Ciphertext<DCRTPoly> &a,
                                    const Ciphertext<DCRTPoly> &b) {
  cout << "[DEBUG] Starting ApproximateMax with a level: " << a->GetLevel()
       << ", b level: " << b->GetLevel() << "\n";

  // Ensure inputs have sufficient levels
  auto inputA = ensureMinimumLevel(cc, a, 1);
  auto inputB = ensureMinimumLevel(cc, b, 1);

  // max(a,b) ≈ (a + b + |a - b|) / 2
  cout << "[DEBUG] Computing sum = a + b...\n";
  auto sum = cc->EvalAdd(inputA, inputB);
  cout << "[DEBUG] sum level: " << sum->GetLevel() << "\n";

  cout << "[DEBUG] Computing diff = a - b...\n";
  auto diff = cc->EvalSub(inputA, inputB);
  cout << "[DEBUG] diff level: " << diff->GetLevel() << "\n";

  // Approximate |diff| using polynomial approximation
  cout << "[DEBUG] Approximating |diff|...\n";
  auto absDiff = ApproximateAbs(cc, diff);
  cout << "[DEBUG] absDiff level: " << absDiff->GetLevel() << "\n";

  cout << "[DEBUG] Adding sum and absDiff for numerator...\n";
  auto numerator = cc->EvalAdd(sum, absDiff);
  cout << "[DEBUG] numerator level: " << numerator->GetLevel() << "\n";

  // Ensure we have enough levels before the final multiplication
  cout << "[DEBUG] Ensuring valid level before division by 2...\n";
  numerator = ensureMinimumLevel(cc, numerator, 1);
  cout << "[DEBUG] numerator level after ensureMinimumLevel: "
       << numerator->GetLevel() << "\n";

  // Divide by 2 (multiply by 0.5)
  std::vector<double> halfVec(VECTOR_DIM, 0.5);
  auto halfPlaintext = cc->MakeCKKSPackedPlaintext(halfVec);

  cout << "[DEBUG] Multiplying numerator by 0.5 to complete max "
          "approximation...\n";
  auto result = cc->EvalMult(numerator, halfPlaintext);
  cout << "[DEBUG] ApproximateMax result level: " << result->GetLevel() << "\n";

  cout << "[DEBUG] ApproximateMax complete.\n";
  return result;
}

// Compute homomorphic maximum across multiple encrypted similarities
Ciphertext<DCRTPoly>
ComputeEncryptedMax(const CryptoContext<DCRTPoly> &cc,
                    const std::vector<Ciphertext<DCRTPoly>> &similarities) {
  cout << "[DEBUG] Starting ComputeEncryptedMax with " << similarities.size()
       << " similarities...\n";
  if (similarities.empty()) {
    cerr << "[ERROR] Cannot compute max of empty vector\n";
    throw std::invalid_argument("Cannot compute max of empty vector");
  }

  if (similarities.size() == 1) {
    cout << "[DEBUG] Only one similarity value, returning it directly. Level: "
         << similarities[0]->GetLevel() << "\n";
    return similarities[0];
  }

  // Check initial levels of all similarities
  cout << "[DEBUG] Checking initial similarity levels...\n";
  for (size_t i = 0; i < similarities.size(); i++) {
    cout << "[DEBUG] Similarity[" << i
         << "] level: " << similarities[i]->GetLevel() << "\n";
    if (similarities[i]->GetLevel() <= 0) {
      cout << "[ERROR] Similarity[" << i
           << "] has invalid level: " << similarities[i]->GetLevel() << "\n";
      throw std::runtime_error("Similarity ciphertext has invalid level");
    }
  }

  // Use tree reduction to compute maximum
  auto result = similarities[0];
  cout << "[DEBUG] Starting with result level: " << result->GetLevel() << "\n";

  for (size_t i = 1; i < similarities.size(); i++) {
    cout << "[DEBUG] Computing max for element " << i
         << " (level: " << similarities[i]->GetLevel() << ")...\n";
    // Ensure result has enough levels before each comparison
    cout << "[DEBUG] Ensuring valid level for result before comparison...\n";
    result = ensureMinimumLevel(cc, result, 1);
    cout << "[DEBUG] Result level after ensureMinimumLevel: "
         << result->GetLevel() << "\n";

    result = ApproximateMax(cc, result, similarities[i]);
    cout << "[DEBUG] Max after element " << i
         << " computed. Result level: " << result->GetLevel() << "\n";
  }

  cout << "[DEBUG] ComputeEncryptedMax complete. Final result level: "
       << result->GetLevel() << "\n";
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
                      << i << " (current level: " << product->GetLevel()
                      << ").\n";
            auto rotated = cc->EvalRotate(product, rotationStep);
            product = cc->EvalAdd(product, rotated);
            std::cout << "[DEBUG] [Thread "
                      << tbb::this_task_arena::current_thread_index()
                      << "] After rotation, product level: "
                      << product->GetLevel() << ".\n";
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
              const PrivateKey<DCRTPoly> &serverSecretKey,
              const PrivateKey<DCRTPoly> &userSecretKey) {
  std::vector<double> similarities(encProducts.size());

  // Parallel decryption and extraction using oneTBB
  tbb::parallel_for(
      tbb::blocked_range<size_t>(0, encProducts.size()),
      [&](const tbb::blocked_range<size_t> &range) {
        for (size_t i = range.begin(); i < range.end(); ++i) {
          // Perform multi-party decryption
          auto userPartial =
              cc->MultipartyDecryptLead({encProducts[i]}, userSecretKey);
          auto serverPartial =
              cc->MultipartyDecryptMain({encProducts[i]}, serverSecretKey);

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
  try {
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

    return 0;
  } catch (const std::exception &e) {
    cerr << "[ERROR] Exception in main: " << e.what() << "\n";
    return EXIT_ERROR;
  }
}