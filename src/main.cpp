#include "../include/config.h"
#include "../include/openFHE_lib.h"
#include "../include/store.h"
#include <chrono>
#include <cmath>
#include <fstream>
#include <iostream>
#include <tbb/blocked_range.h>
#include <tbb/parallel_reduce.h>

using namespace lbcrypto;
using namespace std;

// Entry point of the application that orchestrates the flow

int main(int argc, char *argv[]) {
  cout << "Setting up parameters..." << "\n";
  CryptoContext<DCRTPoly> cc = InitCKKSContext();
  InMemoryStore store(cc);

  // Begin reading in vectors from input file
  cout << "Reading in vectors..." << "\n";
  ifstream fileStream;
  if (argc > 1) {
    fileStream.open(argv[1], ios::in);
  } else {
    cerr << "Error: no input file specified" << "\n";
    return 1;
  }

  if (!fileStream.is_open()) {
    cerr << "Error: input file not found" << "\n";
    return 1;
  }

  size_t numVectors;
  fileStream >> numVectors;

  vector<double> queryVector(VECTOR_DIM);
  for (size_t i = 0; i < VECTOR_DIM; i++) {
    fileStream >> queryVector[i];
  }
  OpenFHEImpl::plaintextNormalize(queryVector, VECTOR_DIM);

  vector<vector<double>> dbVectors(numVectors, vector<double>(VECTOR_DIM));
  for (size_t i = 0; i < numVectors; i++) {
    for (size_t j = 0; j < VECTOR_DIM; j++) {
      fileStream >> dbVectors[i][j];
    }
  }
  fileStream.close();
  // End reading in vectors from input file

  // Diagonal MVM implementation goes below
  // queryVector is 1-D of length 512, already normalized
  // Compute the matrix-vector product of dbVectors times queryVector in the
  // encrypted domain
  cout << "Beginning implementation..." << "\n";
  // ----- Create sessions and store vectors -----
  vector<PrivateKey<DCRTPoly>> userSecrets(numVectors);
  for (size_t i = 0; i < numVectors; i++) {
    string userId = "user_" + to_string(i);
    auto [ok, userSk] = store.CreateUserSession(userId);
    if (!ok) {
      cerr << "Failed to create session for " << userId << "\n";
      return 1;
    }
    userSecrets[i] = userSk;
    store.EncryptAndStoreDBVector(userId, dbVectors[i]);
  }

  auto encQuery = cc->MakeCKKSPackedPlaintext(queryVector);
  auto searchStart = std::chrono::high_resolution_clock::now();
  struct Result {
    double similarity;
    string userId;
  };

  std::vector<std::pair<string, UserSession>> sessionVec(
      store.sessions_.begin(), store.sessions_.end());

  Result best = tbb::parallel_reduce(
      tbb::blocked_range<size_t>(0, sessionVec.size()), Result{-MAXFLOAT, ""},
      [&](const tbb::blocked_range<size_t> &r, Result localBest) -> Result {
        for (size_t i = r.begin(); i < r.end(); ++i) {
          const auto &[userId, sess] = sessionVec[i];
          // Homomorphic elementwise multiplication
          Ciphertext<DCRTPoly> encProduct =
              cc->EvalMult(encQuery, sess.encryptedVector);

          // Sum all slots (this gives the dot product)
          for (int j = 1; j < int(VECTOR_DIM); j *= 2) {
            encProduct = cc->EvalAdd(encProduct, cc->EvalRotate(encProduct, j));
          }

          if (sess.encryptedOne == encProduct) {
            localBest.similarity = 1.0;
            localBest.userId = userId;
            break;
          }
        }
        return localBest;
      },
      [](const Result &a, const Result &b) -> Result {
        return (a.similarity > b.similarity) ? a : b;
      });
  auto searchEnd = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double, std::milli> searchDuration =
      searchEnd - searchStart;

  std::cout << "Maximum cosine similarity is " << best.similarity
            << " at index " << best.userId << "\n";
  std::cout << "Search time: " << searchDuration.count() << " ms" << "\n";

  return 0;
}
