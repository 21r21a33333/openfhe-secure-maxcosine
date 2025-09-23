// config.h - Optimized configuration for homomorphic maximum computation
#ifndef CONFIG_H
#define CONFIG_H

#include "openfhe.h"
using namespace lbcrypto;

// ========================
// CRYPTOGRAPHIC PARAMETERS
// ========================

// Increased multiplicative depth to support bootstrapping and deep computations
constexpr int MULT_DEPTH =
    16;                       // Increased from 48 to handle deeper computations
constexpr int SCALE_MOD = 40; // Scale modulus size in bits
constexpr int FIRST_MOD_SIZE = 60; // First modulus size in bits
constexpr int VECTOR_DIM = 512;    // Vector dimension
constexpr int BATCH_SIZE = 10;     // Processing batch size

// ========================
// BOOTSTRAPPING PARAMETERS
// ========================

// Bootstrapping specific parameters
constexpr int BOOTSTRAP_DEPTH = 8;  // Depth budget for bootstrapping
constexpr int NUM_LARGE_DIGITS = 3; // Number of large digits for bootstrapping
constexpr int BOOTSTRAP_ITERATIONS = 2; // Iterations for bootstrap precision

// Level management thresholds
constexpr int BOOTSTRAP_THRESHOLD = 45;    // Level at which to bootstrap
constexpr int SAFE_COMPUTATION_LEVELS = 8; // Levels to reserve for computations

// ========================
// ALGORITHM PARAMETERS
// ========================

// Maximum computation specific
constexpr double APPROXIMATION_RANGE_A =
    -2.0; // Lower bound for polynomial approximation
constexpr double APPROXIMATION_RANGE_B =
    2.0; // Upper bound for polynomial approximation

// Chebyshev polynomial degrees (reduced for efficiency)
constexpr int RELU_POLY_DEGREE = 7; // Degree for ReLU approximation
constexpr int SIGN_POLY_DEGREE = 5; // Degree for sign function approximation

// ========================
// OPTIMIZATION FLAGS
// ========================

// Algorithm selection
#define USE_SIGN_BASED_MAX true // Use sign-based max (more efficient)
#define USE_RELU_BASED_MAX                                                     \
  false // Use ReLU-based max (more accurate but expensive)
#define ENABLE_BOOTSTRAPPING true    // Enable automatic bootstrapping
#define ENABLE_LEVEL_MONITORING true // Enable level monitoring and reporting

// Performance tuning
#define USE_PARALLEL_PROCESSING true // Enable TBB parallelization
#define USE_BATCH_PROCESSING true    // Enable batch processing
#define OPTIMIZE_MEMORY_USAGE true   // Enable memory optimization

// ========================
// HELPER FUNCTIONS
// ========================

/**
 * Initialize optimized CKKS context with bootstrapping support
 */
inline CryptoContext<DCRTPoly> InitOptimizedCKKSContext() {
  CCParams<CryptoContextCKKSRNS> parameters;

  // Secret key distribution
  SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
  parameters.SetSecretKeyDist(secretKeyDist);

  // Security settings
  parameters.SetSecurityLevel(HEStd_128_classic);
  parameters.SetRingDim(131072); // Sufficient for security and performance

  // Key switching parameters
  parameters.SetNumLargeDigits(NUM_LARGE_DIGITS);
  parameters.SetKeySwitchTechnique(HYBRID);

  // Scaling parameters
  parameters.SetScalingModSize(SCALE_MOD);
  parameters.SetScalingTechnique(FLEXIBLEAUTO);
  parameters.SetFirstModSize(FIRST_MOD_SIZE);

  // Bootstrapping parameters - increased to handle higher degrees
  std::vector<uint32_t> levelBudget = {8, 8}; // Increased from {3, 3}
  std::vector<uint32_t> bsgsDim = {0, 0};

  // Multiplicative depth calculation for bootstrapping
  uint32_t levelsAvailableAfterBootstrap = 10;
  usint depth = levelsAvailableAfterBootstrap +
                FHECKKSRNS::GetBootstrapDepth(levelBudget, secretKeyDist);
  parameters.SetMultiplicativeDepth(depth);

  // Generate context
  auto cryptoContext = GenCryptoContext(parameters);

  // Enable required functionalities
  cryptoContext->Enable(PKE);
  cryptoContext->Enable(KEYSWITCH);
  cryptoContext->Enable(LEVELEDSHE);
  cryptoContext->Enable(ADVANCEDSHE);
  cryptoContext->Enable(MULTIPARTY); // Required for multiparty computation
  cryptoContext->Enable(FHE);        // Required for bootstrapping

  return cryptoContext;
}

/**
 * Check if a ciphertext needs bootstrapping
 */
inline bool needsBootstrap(const Ciphertext<DCRTPoly> &cipher,
                           int reserveLevels = SAFE_COMPUTATION_LEVELS) {
  return cipher->GetLevel() > (MULT_DEPTH - reserveLevels);
}

/**
 * Safe bootstrap operation with error handling
 */
inline Ciphertext<DCRTPoly>
safeBootstrap(const CryptoContext<DCRTPoly> &context,
              const Ciphertext<DCRTPoly> &cipher) {
#if ENABLE_BOOTSTRAPPING
  try {
    if (needsBootstrap(cipher)) {
      auto bootstrapped = context->EvalBootstrap(cipher);
      return bootstrapped;
    }
    return cipher;
  } catch (const std::exception &e) {
    std::cerr << "[ERROR] Bootstrap failed: " << e.what() << std::endl;
    return cipher;
  }
#else
  return cipher;
#endif
}

#endif // CONFIG_H