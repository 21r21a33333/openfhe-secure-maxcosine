#pragma once
#include <cstddef>

// The maximum depth of multiplications that can be performed on a ciphertext
// Increased to handle complex homomorphic operations with scale adjustments
const size_t MULT_DEPTH = 48;

// The length of template vectors included in the dataset
const size_t VECTOR_DIM = 512;

// Reduced scale modulus size for better compatibility with available towers
const size_t SCALE_MOD = 40;

// First modulus size for better parameter balance
const size_t FIRST_MOD_SIZE = 60;

// Batch size for processing encrypted dot products to avoid memory issues
const size_t BATCH_SIZE = 10;
