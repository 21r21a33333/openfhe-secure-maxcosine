#include "../include/openFHE_lib.h"
#include <cmath>
#include <iomanip>
#include <iostream>
#include <vector>

using namespace std;

namespace OpenFHEImpl {

/**
 * Computes the L2 norm (Euclidean magnitude) of a vector
 *
 * @param vector Input vector
 * @return L2 norm of the vector
 */
double calculateL2Norm(const vector<double> &vector) {
  double sumOfSquares = 0.0;

  for (const double &value : vector) {
    sumOfSquares += value * value;
  }

  return sqrt(sumOfSquares);
}

/**
 * Validates that a vector has the expected dimension
 *
 * @param vector Vector to validate
 * @param expectedDimension Expected size
 * @return True if vector has correct dimension
 */
bool validateVectorDimension(const vector<double> &vector,
                             size_t expectedDimension) {
  return vector.size() == expectedDimension;
}

//
// Private Helper Functions
//

/**
 * Decomposes a rotation factor into binary components for efficient rotation
 * Uses binary representation to minimize the number of rotation operations
 *
 * @param rotationFactor Target rotation amount
 * @param batchSize Size of the batch (for modular arithmetic)
 * @return Vector of binary rotation steps
 */
vector<int> decomposeToBinaryRotations(int rotationFactor, int batchSize) {
  vector<int> binaryRotations;

  while (rotationFactor != 0) {
    // Determine sign of current rotation
    int sign = (rotationFactor > 0) ? 1 : -1;

    // Find largest power of 2 that fits in the remaining rotation
    int powerOf2 = static_cast<int>(pow(2, floor(log2(abs(rotationFactor)))));
    int currentRotation = (sign * powerOf2) % batchSize;

    if (currentRotation != 0) {
      binaryRotations.push_back(currentRotation);
    }

    // Subtract the processed rotation component
    rotationFactor -= sign * powerOf2;
  }

  return binaryRotations;
}

//
// Debug and Information Functions
//

/**
 * Prints comprehensive details about a CKKS cryptographic context
 * Useful for debugging and parameter verification
 *
 * @param parameters CKKS-RNS parameter configuration
 * @param cryptoContext The initialized crypto context
 */
void printSchemeDetails(const CCParams<CryptoContextCKKSRNS> &parameters,
                        const CryptoContext<DCRTPoly> &cryptoContext) {
  cout << string(50, '=') << endl;
  cout << "         CKKS CRYPTOGRAPHIC CONTEXT DETAILS" << endl;
  cout << string(50, '=') << endl;

  // Encoding parameters
  cout << "Encoding Parameters:" << endl;
  cout << "  Batch Size: " << cryptoContext->GetEncodingParams()->GetBatchSize()
       << endl;
  cout << "  Ring Dimension: " << cryptoContext->GetRingDimension() << endl;
  cout << endl;

  // Security and precision parameters
  cout << "Security & Precision:" << endl;
  cout << "  Scaling Modulus Size: " << parameters.GetScalingModSize()
       << " bits" << endl;
  cout << "  Multiplicative Depth: " << parameters.GetMultiplicativeDepth()
       << endl;
  cout << "  Noise Estimate: " << fixed << setprecision(2)
       << parameters.GetNoiseEstimate() << endl;
  cout << endl;

  // Full parameter dump for advanced debugging
  cout << "Complete Parameter Configuration:" << endl;
  cout << parameters << endl;
  cout << string(50, '=') << endl;
}

/**
 * Prints detailed information about a ciphertext's internal state
 * Helpful for debugging encryption operations and parameter tracking
 *
 * @param ciphertext The ciphertext to analyze
 */
void printCipherDetails(const Ciphertext<DCRTPoly> &ciphertext) {
  cout << string(40, '-') << endl;
  cout << "       CIPHERTEXT ANALYSIS" << endl;
  cout << string(40, '-') << endl;

  cout << "Capacity & Structure:" << endl;
  cout << "  Slots Available: " << ciphertext->GetSlots() << endl;
  cout << "  Current Level: " << ciphertext->GetLevel() << endl;
  cout << endl;

  cout << "Noise & Precision:" << endl;
  cout << "  Noise Scale Degree: " << ciphertext->GetNoiseScaleDeg() << endl;
  cout << "  Scaling Factor (δ): " << scientific << setprecision(3)
       << ciphertext->GetScalingFactor() << endl;
  cout << endl;

  cout << "Encoding Information:" << endl;
  cout << "  Encoding Parameters: " << ciphertext->GetEncodingParameters()
       << endl;
  cout << string(40, '-') << endl;
  cout << defaultfloat; // Reset formatting
}

//
// Core Encryption/Decryption Operations
//

/**
 * Encrypts a vector of double values into a CKKS ciphertext
 *
 * @param cryptoContext CKKS crypto context
 * @param publicKey Public key for encryption
 * @param values Vector of double values to encrypt
 * @return Encrypted ciphertext containing the vector
 */
Ciphertext<DCRTPoly>
encryptFromVector(const CryptoContext<DCRTPoly> &cryptoContext,
                  const PublicKey<DCRTPoly> &publicKey,
                  const vector<double> &values) {
  if (values.empty()) {
    throw invalid_argument("Cannot encrypt empty vector");
  }

  // Pack values into CKKS plaintext
  auto plaintext = cryptoContext->MakeCKKSPackedPlaintext(values);

  // Encrypt and return ciphertext
  return cryptoContext->Encrypt(publicKey, plaintext);
}

/**
 * Decrypts a CKKS ciphertext and extracts the vector of double values
 *
 * @param cryptoContext CKKS crypto context
 * @param privateKey Private key for decryption
 * @param ciphertext Ciphertext to decrypt
 * @return Vector of decrypted double values
 */
vector<double> decryptToVector(const CryptoContext<DCRTPoly> &cryptoContext,
                               const PrivateKey<DCRTPoly> &privateKey,
                               const Ciphertext<DCRTPoly> &ciphertext) {
  if (!ciphertext) {
    throw invalid_argument("Cannot decrypt null ciphertext");
  }

  Plaintext decryptedPlaintext;
  cryptoContext->Decrypt(privateKey, ciphertext, &decryptedPlaintext);

  return decryptedPlaintext->GetRealPackedValue();
}

//
// Advanced Ciphertext Operations
//

/**
 * Performs arbitrary rotation on a ciphertext using binary decomposition
 * Optimizes rotation by using powers of 2, requiring only O(log n) operations
 * instead of n sequential rotations
 *
 * @param cryptoContext CKKS crypto context with rotation keys
 * @param ciphertext Input ciphertext to rotate
 * @param rotationFactor Number of positions to rotate (can be negative)
 * @return Rotated ciphertext
 */
Ciphertext<DCRTPoly> binaryRotate(const CryptoContext<DCRTPoly> &cryptoContext,
                                  Ciphertext<DCRTPoly> ciphertext,
                                  int rotationFactor) {
  if (!ciphertext) {
    throw invalid_argument("Cannot rotate null ciphertext");
  }

  const int batchSize = cryptoContext->GetEncodingParams()->GetBatchSize();

  // Normalize rotation factor to valid range
  rotationFactor = rotationFactor % batchSize;
  if (rotationFactor == 0) {
    return ciphertext; // No rotation needed
  }

  // Decompose rotation into binary components
  vector<int> binaryRotations =
      decomposeToBinaryRotations(rotationFactor, batchSize);

  // Apply each binary rotation
  for (int rotation : binaryRotations) {
    ciphertext = cryptoContext->EvalRotate(ciphertext, rotation);
  }

  return ciphertext;
}

//
// Vector Utility Functions
//

/**
 * Normalizes a vector to unit length (L2 norm = 1)
 * Essential for cosine similarity computations in encrypted domain
 *
 * @param vector Vector to normalize (modified in-place)
 * @param dimension Expected dimension of the vector (for validation)
 */
void plaintextNormalize(vector<double> &vector, const size_t dimension) {
  if (vector.size() != dimension) {
    throw invalid_argument("Vector size (" + to_string(vector.size()) +
                           ") does not match expected dimension (" +
                           to_string(dimension) + ")");
  }

  if (vector.empty()) {
    return; // Nothing to normalize
  }

  // Calculate L2 norm (magnitude)
  double magnitude = calculateL2Norm(vector);

  // Normalize if magnitude is non-zero
  if (magnitude > 1e-10) { // Use small epsilon for numerical stability
    for (double &value : vector) {
      value /= magnitude;
    }
  } else {
    // Handle zero vector case - could throw exception or set to zero
    fill(vector.begin(), vector.end(), 0.0);
  }
}

} // namespace OpenFHEImpl