# Merkel - Vector Similarity Search Algorithm

## Algorithm Overview

This project implements a **linear search algorithm** for finding the most similar vector in a database using **cosine similarity**. The algorithm is designed to work with homomorphic encryption (OpenFHE/CKKS) for privacy-preserving computations.

## Core Algorithm

### 1. Vector Normalization

```cpp
void plaintextNormalize(vector<double> &vec, const size_t dim) {
    double magnitude = sqrt(sum(vec[i] * vec[i] for i in [0, dim))
    vec[i] = vec[i] / magnitude  // Normalize each component
}
```

- **Purpose**: Converts vectors to unit vectors for cosine similarity
- **Mathematical**: ||v|| = 1 ensures cosine similarity = dot product

### 2. Linear Search with Inner Product

```cpp
for (size_t i = 0; i < dbVectors.size(); ++i) {
    double similarity = inner_product(queryVector.begin(), queryVector.end(),
                                      dbVectors[i].begin(), 0.0);
    if (similarity > maxSimilarity) {
        maxSimilarity = similarity;
        maxIndex = i;
    }
}
```

### 3. Similarity Metric: Cosine Similarity

- **Formula**: cos(θ) = (A · B) / (||A|| × ||B||)
- **Normalized vectors**: cos(θ) = A · B (since ||A|| = ||B|| = 1)
- **Range**: [-1, 1], where 1 = identical, -1 = opposite

## Algorithm Complexity

- **Time Complexity**: O(N × D)
  - N = number of database vectors
  - D = vector dimension (512 for facial templates)
- **Space Complexity**: O(N × D) for storing database vectors
- **Search Pattern**: Brute force linear scan through all vectors

## Homomorphic Encryption Context

### CKKS-RNS Parameters

- **Security Level**: 128-bit
- **Multiplicative Depth**: 3 (configurable)
- **Batch Size**: Automatically determined by ring dimension
- **Scaling Mod Size**: 45 bits

### Key Operations Supported

1. **Encryption/Decryption**: Standard public-key operations
2. **Addition**: Homomorphic vector addition
3. **Multiplication**: Homomorphic element-wise multiplication
4. **Rotation**: Circular shifts using binary rotation factors
5. **Key Switching**: Efficient key management

## Current Implementation Status

**Phase 1 (Implemented)**:

- Homomorphic encryption setup and key generation
- Vector normalization and preprocessing
- Plaintext linear search algorithm

**Phase 2 (Planned)**:

- Encrypted query vector processing
- Homomorphic similarity computation
- Secure result extraction

## Mathematical Foundation

The algorithm relies on the property that for normalized vectors:

```
similarity(q, d_i) = q · d_i = Σ(q[j] × d_i[j])
```

This inner product can be computed homomorphically using:

1. Element-wise multiplication: `q[j] × d_i[j]`
2. Sum reduction: `Σ(products)`

The homomorphic version would maintain this mathematical equivalence while keeping all computations encrypted.
