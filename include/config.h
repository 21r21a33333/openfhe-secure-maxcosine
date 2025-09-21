#pragma once
#include <cstddef>

// The maximum depth of multiplications that can be performed on a ciphertext
// Increased to handle complex polynomial approximations in max computation
const size_t MULT_DEPTH = 64;

// The length of template vectors included in the dataset
const size_t VECTOR_DIM = 512;

const size_t SCALE_MOD = 50;