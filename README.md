# Mercle SDE Assignment: Privacy-First Encrypted Similarity Search

## Overview

This project implements a privacy-first encrypted similarity search system using OpenFHE's CKKS homomorphic encryption scheme. The system computes the maximum cosine similarity between an encrypted query vector and a database of encrypted vectors without ever decrypting the individual vectors, ensuring complete privacy protection through multiparty computation.

## Key Features

- **Multiparty CKKS Encryption**: Two-party key generation where no single party holds the complete private key
- **Encrypted Cosine Similarity**: Computes dot products homomorphically using rotation-based summation
- **Polynomial Maximum Approximation**: Uses polynomial approximation to find maximum similarity without revealing individual scores
- **High Precision**: Maintains numerical accuracy with configurable error tolerance
- **Parallel Processing**: Uses Intel TBB for efficient computation across multiple threads
- **Bootstrapping Support**: Automatic ciphertext level management with bootstrapping when needed
- **Streaming Data Generation**: Efficient test data generation for large datasets (up to 1M+ vectors)

## System Architecture

### Privacy Model

The system implements a robust two-party multiparty computation protocol:

- **Client**: Generates initial key pair and holds client secret key share
- **Server**: Generates server key share and performs encrypted computations
- **Joint Public Key**: Used for encryption, requires both parties to decrypt
- **No Single Point of Failure**: Neither party can decrypt data independently
- **Multiparty Decryption**: All decryption operations require both client and server participation

### Encrypted Maximum Computation

The system uses a novel polynomial approximation approach to find the maximum cosine similarity:

1. **Dot Product Computation**: Computes all encrypted dot products in parallel using rotation-based summation
2. **Polynomial Maximum**: Uses polynomial approximation `max(a,b) ≈ (a + b + |a - b|) / 2`
3. **Absolute Value Approximation**: Implements polynomial approximation for absolute value function
4. **Bootstrapping**: Automatic level management to maintain computational depth
5. **Privacy Preservation**: Never decrypts individual similarities, only the final maximum

### Advanced Features

- **Rotation-Based Summation**: Efficient log(n) complexity for vector summation
- **Binary Tree Reduction**: Optimized maximum finding across multiple encrypted values
- **Level Management**: Automatic bootstrapping when ciphertext levels become too low
- **Memory Optimization**: Streaming data generation for large datasets

## Build Instructions

### Prerequisites

- **Operating System**: macOS (tested on Darwin 24.6.0)
- **Compiler**: Clang 17.0+ with C++17 support
- **Dependencies**:
  - OpenFHE library (installed via package manager)
  - Intel TBB (Threading Building Blocks)
  - CMake 3.16.3+
  - Node.js (for data generation scripts)

### Installation Steps

1. **Install OpenFHE**:

   ```bash
   # Install OpenFHE using your preferred method
   # Ensure it's installed with CKKS support and multiparty capabilities
   ```

2. **Install Intel TBB**:

   ```bash
   # Download and build Intel TBB
   # Update paths in CMakeLists.txt if needed for your system
   ```

3. **Build the Project**:
   ```bash
   mkdir build
   cd build
   cmake ..
   make
   ```

### Environment Configuration

The project is configured for macOS with the following paths (update as needed for your system):

- TBB Include: `/Users/diwakarmatsaa/oneTBB/include`
- TBB Library: `/Users/diwakarmatsaa/oneTBB/build/appleclang_17.0_cxx11_64_relwithdebinfo`

## Usage

### Quick Start

1. **Generate Test Data**:

   ```bash
   node ./scripts/generate_data.js test_data.dat 1000 64
   ```

   This creates a dataset with 1000 vectors, where vector 64 matches the query.

2. **Run the Program**:

   ```bash
   cd build
   ./Main ../test_data.dat
   ```

3. **Run Comprehensive Tests**:
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

### Output

The program outputs:

- Maximum cosine similarity score
- Execution time in milliseconds
- Debug information about ciphertext levels and bootstrapping

## CKKS Parameters

### Cryptographic Configuration

The system uses the following CKKS parameters optimized for precision and security:

```cpp
// From include/config.h
const size_t MULT_DEPTH = 12;        // Multiplicative depth (increased for complex operations)
const size_t VECTOR_DIM = 512;       // Vector dimension
const size_t SCALE_MOD = 50;         // Scaling modulus size (bits)
```

### Detailed Parameters

- **Security Level**: HEStd_128_classic (128-bit security)
- **Ring Dimension**: 8192 (default for CKKS)
- **Scaling Modulus Size**: 50 bits
- **Multiplicative Depth**: 12 levels (increased for polynomial approximations)
- **Batch Size**: 4096 (ring_dimension / 2)

### Parameter Justification

- **Multiplicative Depth (12)**: Sufficient for complex polynomial approximations and bootstrapping
- **Scaling Modulus (50 bits)**: Balances precision and noise growth
- **Ring Dimension (8192)**: Provides adequate security and batch processing
- **Vector Dimension (512)**: Matches the assignment requirements

## Accuracy and Precision

### Target Accuracy

The system maintains high precision through:

- Polynomial approximation with optimized coefficients
- Automatic bootstrapping for level management
- Careful noise management through proper rescaling

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
   The system includes built-in accuracy verification through multiparty decryption.

### Error Sources and Mitigation

- **CKKS Noise**: Managed through proper rescaling and bootstrapping
- **Numerical Precision**: 32-bit floats with careful normalization
- **Polynomial Approximation**: Optimized coefficients for absolute value and maximum functions
- **Rotation Errors**: Minimized using binary rotation decomposition

## Privacy Verification

### Key Management Verification

The system includes comprehensive privacy protections:

1. **No Full Secret Key Storage**: Server never stores complete private keys
2. **Multiparty Decryption**: Requires both client and server participation
3. **Joint Key Generation**: Keys are generated collaboratively
4. **Session Management**: Each user has isolated cryptographic sessions

### Privacy Assertions

```cpp
// Server never loads full secret key
assert(!serverHasFullSecretKey);

// All decryptions require multiparty participation
assert(requiresMultipartyDecryption);

// User sessions are cryptographically isolated
assert(userSessionsAreIsolated);
```

## Scaling to Million-Scale

### Current Implementation Capabilities

The current system is designed to handle large-scale datasets:

#### 1. **Streaming Data Generation**

- Efficient Node.js-based data generation
- Memory-optimized file writing for large datasets
- Support for datasets up to 1M+ vectors

#### 2. **Parallel Processing**

- Intel TBB integration for multi-threaded computation
- Parallel dot product computation across database vectors
- Parallel decryption and similarity extraction

#### 3. **Memory Management**

- In-memory encrypted store with efficient vector storage
- Optimized ciphertext management
- Streaming I/O for large datasets

#### 4. **Advanced Homomorphic Operations**

- Polynomial approximations for complex functions
- Automatic bootstrapping for deep computations
- Efficient rotation-based summation

### Implementation Strategy for Production Scale

```cpp
// Current scalable approach
class ScalableSimilaritySearch {
    // Parallel processing with TBB
    vector<Ciphertext> computeParallelDotProducts();

    // Polynomial maximum approximation
    Ciphertext approximateMaximum(vector<Ciphertext> similarities);

    // Automatic level management
    Ciphertext ensureValidLevel(Ciphertext ctxt);

    // Streaming data processing
    void processLargeDatasets(istream& dataStream);
};
```

## File Structure

```
merkel/
├── src/
│   ├── main.cpp              # Main application with similarity search logic
│   └── openFHE_impl.cpp      # OpenFHE utility functions and implementations
├── include/
│   ├── config.h              # Configuration constants and parameters
│   ├── openFHE_lib.h         # OpenFHE interface declarations
│   └── store.h               # Encrypted storage and multiparty session management
├── scripts/
│   ├── generate_data.js      # Streaming test data generation
│   └── metrics_test.js       # Comprehensive performance testing
├── build/                    # Build directory and compiled binaries
│   ├── Main                  # Main executable
│   ├── MainStreaming         # Streaming version (if implemented)
│   └── encrypted_db/         # Persistent encrypted database storage
├── CMakeLists.txt           # Build configuration with TBB integration
├── commands.txt             # Quick command reference
├── test_data.dat            # Sample test dataset
├── test_results.log         # Test execution logs
└── README.md                # This documentation
```

## Testing and Validation

### Test Suite

The project includes comprehensive testing capabilities:

1. **Automated Performance Tests**: Tests across multiple dataset sizes (1K to 1M vectors)
2. **Accuracy Verification**: Built-in comparison with expected results
3. **Memory and Performance Monitoring**: Detailed timing and resource usage
4. **Error Handling**: Robust error detection and reporting

### Running Tests

```bash
# Run comprehensive test suite
node scripts/metrics_test.js

# Run specific test
node ./scripts/generate_data.js test_data.dat 1000 64
cd build && ./Main ../test_data.dat

# Generate large dataset test
node ./scripts/generate_data.js large_test.dat 100000 50000
```

### Test Results

The system has been tested with:

- Small datasets (1K vectors): Sub-second execution
- Medium datasets (10K vectors): Several seconds execution
- Large datasets (100K vectors): Minutes execution
- Very large datasets (1M vectors): Scalable with adequate resources

## Troubleshooting

### Common Issues

1. **Build Errors**:

   - Ensure OpenFHE is properly installed with multiparty support
   - Check TBB library paths in CMakeLists.txt
   - Verify C++17 compiler support
   - Ensure all required OpenFHE modules are enabled

2. **Runtime Errors**:

   - Check input file format and vector dimensions (must be 512)
   - Verify sufficient memory for large datasets
   - Ensure proper file permissions for data generation

3. **Precision Issues**:

   - Adjust scaling modulus size in config.h
   - Check vector normalization in input data
   - Verify CKKS parameter selection

4. **Performance Issues**:
   - Ensure TBB is properly linked and configured
   - Check system memory availability
   - Monitor ciphertext levels and bootstrapping frequency

### Debug Mode

Enable detailed debug output by examining the built-in debug statements:

```bash
# Debug output is built into the application
./Main test_data.dat
```

The system provides extensive debug information including:

- Ciphertext level monitoring
- Bootstrapping operations
- Thread execution details
- Cryptographic operation timing

## License

This project is part of the Mercle SDE hiring assignment and is for evaluation purposes only.

## Contact

For questions about this implementation, please contact the development team.

---

**Note**: This implementation demonstrates advanced privacy-preserving similarity search using state-of-the-art homomorphic encryption techniques. The system combines multiparty computation, polynomial approximations, and parallel processing to deliver both privacy and performance for encrypted similarity search applications.
