#include "../include/config.h"
#include "../include/openFHE_lib.h"
#include <chrono>
#include <fstream>
#include <iostream>
#include <numeric>
#include <tbb/blocked_range.h>
#include <tbb/parallel_reduce.h>

using namespace lbcrypto;
using namespace std;

// Entry point of the application that orchestrates the flow

int main(int argc, char *argv[]) {

  // The only parameter you will need to modify is multiplicative depth
  // Which is located in ../include/config.h

  // ----- Don't touch anything in the section below -----
  cout << "Setting up parameters..." << "\n";
  CCParams<CryptoContextCKKSRNS> parameters;
  parameters.SetSecurityLevel(HEStd_128_classic);
  parameters.SetMultiplicativeDepth(MULT_DEPTH);
  parameters.SetScalingModSize(45);

  CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
  cc->Enable(PKE);
  cc->Enable(KEYSWITCH);
  cc->Enable(LEVELEDSHE);
  cc->Enable(ADVANCEDSHE);

  size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
  // ----- Don't touch anything in the section above -----

  // Begin key generation operations
  cout << "Generating keys..." << "\n";
  auto keyPair = cc->KeyGen();
  auto pk = keyPair.publicKey;
  auto sk = keyPair.secretKey;
  cc->EvalMultKeyGen(sk);
  vector<int> binaryRotationFactors;
  for (int i = 1; i < int(batchSize); i *= 2) {
    binaryRotationFactors.push_back(i);
    binaryRotationFactors.push_back(-i);
  }
  cc->EvalRotateKeyGen(sk, binaryRotationFactors);
  // End key generation operations

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
    OpenFHEImpl::plaintextNormalize(dbVectors[i], VECTOR_DIM);
  }
  fileStream.close();
  // End reading in vectors from input file

  // Diagonal MVM implementation goes below
  // queryVector is 1-D of length 512, already normalized
  // Compute the matrix-vector product of dbVectors times queryVector in the
  // encrypted domain
  cout << "Beginning implementation..." << "\n";

  auto searchStart = std::chrono::high_resolution_clock::now();

  struct Result {
    double similarity;
    size_t index;
  };

  Result best = tbb::parallel_reduce(
      tbb::blocked_range<size_t>(0, dbVectors.size()),
      Result{-1.0, 0}, // initial value
      [&](const tbb::blocked_range<size_t> &r, Result localBest) -> Result {
        for (size_t i = r.begin(); i < r.end(); i++) {
          double similarity =
              std::inner_product(queryVector.begin(), queryVector.end(),
                                 dbVectors[i].begin(), 0.0);
          if (similarity > localBest.similarity) {
            localBest.similarity = similarity;
            localBest.index = i;
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
            << " at index " << best.index << "\n";
  std::cout << "Search time: " << searchDuration.count() << " ms" << "\n";

  return 0;
}
