# Mercle SDE Assignment: Privacy-First Encrypted Similarity Search

## Overview

This project implements a privacy-first encrypted similarity search system using OpenFHE's CKKS homomorphic encryption scheme. The system computes the maximum cosine similarity between an encrypted query vector and a database of encrypted vectors without ever decrypting the individual vectors, ensuring complete privacy protection.

## Key Features

- **Multiparty CKKS Encryption**: No single party holds the complete private key
- **Encrypted Cosine Similarity**: Computes dot products homomorphically using rotation-based summation
- **Privacy-Preserving Maximum**: Finds the maximum similarity without revealing individual scores
- **High Precision**: Maintains numerical accuracy with error < 1e-4
- **Parallel Processing**: Uses Intel TBB for efficient computation

## System Architecture

### Privacy Model

The system implements an 8-party multiparty computation protocol:

- **8-Party Key Generation**: Sequential multiparty key generation across 8 parties
- **Joint Public Key**: Generated collaboratively, used for encryption operations
- **Distributed Secret Keys**: Each party holds their own secret key share
- **Server Role**: Holds the final party's secret key and performs encrypted computations
- **No Single Point of Failure**: No single party can decrypt data independently

### Current Implementation Flow

#### 1. **Initialization Phase**

```
- Load input data (number of vectors, user secret index, query vector, database vectors)
- Initialize CKKS cryptographic context with optimized parameters
- Create InMemoryStore instance for session management
```

#### 2. **8-Party Session Setup**

```
- Create user session with ID "user_{userSecretIndex}"
- Generate 8-party key pairs sequentially:
  * Party 0: Initial key generation
  * Parties 1-7: Sequential multiparty key generation
- Generate evaluation keys (multiplication, rotation, sum)
- Store joint public key and server secret key
```

#### 3. **Database Encryption**

```
- Normalize all database vectors for cosine similarity
- Encrypt vectors under joint public key
- Store encrypted vectors in user session
```

#### 4. **Encrypted Similarity Computation**

```
- Normalize query vector
- Compute encrypted dot products in batches (BATCH_SIZE = 10):
  * Multiply query with each encrypted database vector
  * Use rotation-based summation (log(n) rotations for n elements)
  * Process vectors in parallel using Intel TBB
```

#### 5. **Homomorphic Maximum Finding**

```
- Process dot products in batches to find batch maxima
- Use Chebyshev polynomial approximation for ReLU function
- Implement tournament-style maximum reduction:
  * max(a,b) = (a + b + |a-b|) / 2
  * |x| ≈ 2*ReLU(x) + 2*ReLU(-x) - x
- Find global maximum across all batch maxima
```

#### 6. **8-Party Decryption**

```
- Perform partial decryption for parties 0-6
- Party 7 performs lead decryption
- Fuse all partial decryptions to reveal final result
- Extract maximum cosine similarity value
```

### Key Technical Components

#### **Batch Processing Architecture**

- **BATCH_SIZE**: 10 vectors per batch (configurable in `config.h`)
- **Memory Management**: Prevents memory overflow for large datasets
- **Parallel Processing**: Intel TBB for concurrent vector operations

#### **Homomorphic Operations**

- **Chebyshev Approximation**: ReLU function for maximum computation
- **Rotation-Based Summation**: O(log n) complexity for dot products
- **Scale Management**: Automatic rescaling with `IntMPBootAdjustScale`

#### **Privacy Guarantees**

- **8-Party Protocol**: No single party can decrypt independently
- **Joint Key Generation**: Collaborative key creation prevents key compromise
- **Encrypted Computation**: All operations performed on encrypted data

## Build Instructions

### Prerequisites

- **Operating System**: macOS (tested on Darwin 24.6.0)
- **Compiler**: Clang 17.0+ with C++17 support
- **Dependencies**:
  - OpenFHE library (installed via package manager)
  - Intel TBB (Threading Building Blocks) v1.0+
  - CMake 3.16.3+
  - Node.js (for data generation and testing scripts)

### Installation Steps

1. **Install OpenFHE**:

   ```bash
   # Install OpenFHE using your preferred method
   # Ensure it's installed with CKKS support and multiparty features
   # Version compatibility: OpenFHE v1.1.0+
   ```

2. **Install Intel TBB**:

   ```bash
   # Download and build Intel TBB v1.0+
   # Or use package manager: brew install tbb
   ```

3. **Configure TBB Paths** (if needed):

   Update `CMakeLists.txt` with your TBB installation paths:

   ```cmake
   set(TBB_INCLUDE_DIR "/path/to/your/tbb/include")
   set(TBB_LIB_DIR "/path/to/your/tbb/lib")
   ```

4. **Build the Project**:
   ```bash
   mkdir build
   cd build
   cmake ..
   make
   ```

### Current Environment Configuration

The project is configured for macOS with the following paths:

- **TBB Include**: `/Users/diwakarmatsaa/oneTBB/include`
- **TBB Library**: `/Users/diwakarmatsaa/oneTBB/build/appleclang_17.0_cxx11_64_relwithdebinfo`
- **OpenFHE**: Auto-detected via CMake `find_package(OpenFHE)`

### Build Configuration

The CMake configuration automatically:

- Links against OpenFHE shared libraries
- Enables C++17 standard
- Configures compiler flags from OpenFHE
- Links Intel TBB for parallel processing

## Usage

### Quick Start

1. **Generate Test Data**:

   ```bash
   node ./scripts/generate_data.js test_data.dat 1000 64
   ```

   This creates a dataset with 1000 vectors, where vector 64 matches the query.

2. **Build and Run the Program**:

   ```bash
   # Build (if not already built)
   mkdir -p build && cd build
   cmake .. && make

   # Run the program
   ./Main ../test_data.dat
   ```

3. **Run Comprehensive Performance Tests**:
   ```bash
   node scripts/metrics_test.js
   ```

### Input Format

The input file format is:

```
<number_of_vectors>
<user_secret_index>
<query_vector_512_dimensions>
<database_vector_1_512_dimensions>
<database_vector_2_512_dimensions>
...
```

**Example**:

```
1000
64
1 1 1 1 1 1 1 1 ... (512 ones)
-45 23 -12 67 ... (512 random values)
...
```

### Output

The program outputs:

- **Maximum cosine similarity score**: The highest similarity found
- **User ID**: Identifier for the best match (currently shows batch processing info)
- **Execution time**: Total search time in milliseconds
- **Debug information**: Batch processing details, party generation status

**Example Output**:

```
Setting up cryptographic parameters...
Creating session for user_64...
[Store] Processing party 2 of 8
[Store] Processing party 3 of 8
...
[Store] Successfully created 8-party session for user_64
Reading query vector...
Reading database vectors...
Setting up user sessions and encrypting vectors...
Beginning similarity search...
[computeEncryptedDotProducts] Processing 1000 vectors in 100 batches of size 10
[findBestMatch] Processing 1000 vectors in 100 batches for maximum computation
[findHomomorphicMax] Round 1: workingSet size = 100
...
Maximum cosine similarity: 0.999999 (User: batched_homomorphic_max_result)
Search completed in: 1234.56 ms
```

## CKKS Parameters

### Current Cryptographic Configuration

The system uses the following CKKS parameters optimized for homomorphic maximum computation:

```cpp
// From include/config.h
const size_t MULT_DEPTH = 48;       // Multiplicative depth (increased for complex operations)
const size_t VECTOR_DIM = 512;      // Vector dimension
const size_t SCALE_MOD = 40;        // Scaling modulus size (bits)
const size_t FIRST_MOD_SIZE = 60;   // First modulus size for parameter balance
const size_t BATCH_SIZE = 10;       // Batch size for processing vectors
```

### Detailed Parameters

- **Security Level**: HEStd_128_classic (128-bit security)
- **Ring Dimension**: Auto-selected by OpenFHE based on security requirements
- **Scaling Modulus Size**: 40 bits (reduced for better tower compatibility)
- **First Modulus Size**: 60 bits
- **Multiplicative Depth**: 48 levels (increased for Chebyshev approximations)
- **Batch Size**: 10 vectors per batch (memory management)
- **Scaling Technique**: FLEXIBLEAUTOEXT
- **Key Switch Technique**: HYBRID
- **Secret Key Distribution**: UNIFORM_TERNARY

### Parameter Justification

- **Multiplicative Depth (48)**: Required for Chebyshev polynomial approximations and complex homomorphic operations
- **Scaling Modulus (40 bits)**: Reduced for better compatibility with available polynomial towers
- **First Modulus Size (60 bits)**: Provides better parameter balance for multiparty operations
- **Batch Size (10)**: Prevents memory overflow during large dataset processing
- **Vector Dimension (512)**: Matches the assignment requirements
- **8-Party Protocol**: Enhanced security through distributed key generation

## Accuracy and Precision

### Target Accuracy

The system maintains absolute error < 1e-4 compared to plaintext computation.

### Reproducing Accuracy Tests

1. **Generate Test Data with Known Similarity**:

   ```bash
   node ./scripts/generate_data.js accuracy_test.dat 1000 0
   ```

2. **Run with Debug Output**:

   ```bash
   cd build
   ./Main ../accuracy_test.dat
   ```

3. **Compare with Plaintext Baseline**:
   The system includes built-in accuracy verification that compares encrypted results with plaintext computation.

### Error Sources and Mitigation

- **CKKS Noise**: Managed through proper rescaling and parameter selection
- **Numerical Precision**: 32-bit floats with careful normalization
- **Rotation Errors**: Minimized using binary rotation decomposition

## Privacy Verification

### Key Management Verification

The system includes built-in privacy checks:

1. **No Full Secret Key Storage**: Server never stores complete private keys
2. **Multiparty Decryption**: Requires both client and server participation
3. **Audit Logs**: Tracks key generation and usage

### Privacy Assertions

```cpp
// Server never loads full secret key
assert(!serverHasFullSecretKey);

// All decryptions require multiparty participation
assert(requiresMultipartyDecryption);
```

## Scaling to Million-Scale

### Conceptual Scaling Plan

While the current prototype handles 1,000 vectors, here's the approach for 1M+ vectors:

#### 1. **Batching and Packing**

- Pack multiple vectors into single ciphertext slots
- Use SIMD operations for parallel processing
- Implement vectorized dot product computation

#### 2. **Hierarchical Maximum Finding**

- Divide database into blocks (e.g., 10K vectors per block)
- Compute block-wise maxima using tree reduction
- Use encrypted comparison for maximum selection

#### 3. **Rotation-Based Operations**

- Implement efficient rotation for large-scale summation
- Use binary tree reduction for log(n) complexity
- Optimize rotation key management

#### 4. **Memory and I/O Optimization**

- Implement streaming processing for large datasets
- Use memory-mapped files for efficient I/O
- Cache frequently accessed rotation keys

#### 5. **Precision Stability**

- Implement dynamic rescaling based on noise levels
- Use bootstrapping for deep computations
- Monitor and adjust scaling factors

### Implementation Strategy

```cpp
// Conceptual scaling approach
class ScalableSimilaritySearch {
    // Block-wise processing
    vector<Ciphertext> computeBlockMaxima(vector<Ciphertext> block);

    // Hierarchical reduction
    Ciphertext findGlobalMaximum(vector<Ciphertext> blockMaxima);

    // Streaming I/O
    void processStreamingDatabase(istream& dataStream);
};
```

## File Structure

```
merkel/
├── src/
│   ├── main.cpp              # Main application with 8-party similarity search
│   └── openFHE_impl.cpp      # OpenFHE utility functions and vector operations
├── include/
│   ├── config.h              # Configuration constants (MULT_DEPTH=48, BATCH_SIZE=10)
│   ├── openFHE_lib.h         # OpenFHE interface declarations
│   └── store.h               # 8-party encrypted storage and session management
├── scripts/
│   ├── generate_data.js      # Streaming test data generation (supports large datasets)
│   └── metrics_test.js       # Comprehensive performance testing (1K to 1M vectors)
├── build/                    # Build directory with CMake artifacts
├── CMakeLists.txt           # Build configuration with OpenFHE and TBB linking
├── test_data.dat            # Sample test dataset (1000 vectors)
├── test_large.dat           # Large test dataset
├── test_results.log         # Performance test results
└── README.md                # This documentation file
```

### Key Implementation Files

- **`main.cpp`**: Implements the complete 8-party similarity search workflow including Chebyshev approximation for homomorphic maximum computation
- **`store.h`**: Contains the 8-party key generation protocol and encrypted vector management
- **`openFHE_impl.cpp`**: Provides utility functions for vector normalization, binary rotation, and CKKS operations
- **`config.h`**: Centralized configuration with optimized parameters for homomorphic maximum computation

## Testing and Validation

### Test Suite

The project includes comprehensive testing with streaming support for large datasets:

1. **Performance Tests**: Automated testing from 1K to 1M vectors
2. **Data Generation Tests**: Streaming data generation for large datasets
3. **Integration Tests**: End-to-end 8-party similarity search workflow
4. **Accuracy Tests**: Built-in precision verification with plaintext comparison

### Running Tests

```bash
# Run comprehensive performance tests (1K, 10K, 100K, 1M vectors)
node scripts/metrics_test.js

# Run specific test with custom parameters
node ./scripts/generate_data.js test_data.dat 10000 42
cd build && ./Main ../test_data.dat

# Test large dataset generation (supports up to 1M vectors)
node ./scripts/generate_data.js large_test.dat 100000 1234
```

### Test Output

Tests generate detailed logs in `test_results.log` including:

- Batch processing performance metrics
- 8-party key generation timing
- Homomorphic maximum computation details
- Memory usage and execution times

## Troubleshooting

### Common Issues

1. **Build Errors**:

   - Ensure OpenFHE is properly installed
   - Check TBB library paths in CMakeLists.txt
   - Verify C++17 compiler support

2. **Runtime Errors**:

   - Check input file format
   - Verify vector dimensions (must be 512)
   - Ensure sufficient memory for large datasets

3. **Precision Issues**:
   - Adjust scaling modulus size
   - Check vector normalization
   - Verify CKKS parameter selection

### Debug Mode

Enable debug output by setting environment variable:

```bash
export DEBUG=1
./Main test_data.dat
```

## License

This project is part of the Mercle SDE hiring assignment and is for evaluation purposes only.

## Contact

For questions about this implementation, please contact the development team.

---

**Note**: This implementation demonstrates the core concepts of privacy-preserving similarity search using homomorphic encryption. While optimized for the 1K vector prototype, it provides a solid foundation for scaling to production requirements.
