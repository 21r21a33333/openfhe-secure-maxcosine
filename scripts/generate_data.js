#!/usr/bin/env node

const fs = require('fs').promises;
const path = require('path');

// Constants
const DIM = 512;

// Utility functions
const validateArgs = (args) => {
    if (args.length < 5) {
        throw new Error('Missing required arguments');
    }

    const size = parseInt(args[3]);
    if (isNaN(size) || size <= 0) {
        throw new Error('SIZE must be a positive integer');
    }

    const similarityIndex = parseInt(args[4]);
    if (isNaN(similarityIndex) || similarityIndex < 0 || similarityIndex >= size) {
        throw new Error(`SIMILARITY_VECTOR_INDEX must be between 0 and ${size - 1}`);
    }

    return { filepath: args[2], size, similarityIndex };
};

const printUsage = () => {
    console.log('generate_data.js [FILENAME] [SIZE] [SIMILARITY_VECTOR_INDEX]');
    console.log('\nParameters:');
    console.log('\tFILENAME\tFilename to create dataset within');
    console.log('\tSIZE    \tInteger number of backend vectors');
    console.log('\tSIMILARITY_VECTOR_INDEX\tInteger index of the vector that should match the query vector');
    console.log('\nThe script will prompt you to specify which vectors should match the query vector.');
};

// Vector generation functions
const generateQueryVector = () => Array(DIM).fill(1).join(' ');

const generateRandomVector = () =>
    Array(DIM)
        .fill(0)
        .map(() => Math.floor(Math.random() * 199) - 99)
        .join(' ');

const generateMatchingVector = () =>
    Array(DIM)
        .fill(0)
        .map(() => Math.floor(Math.random() * 2) + 1)
        .join(' ');

// Dataset generation
const generateDataset = async ({ filepath, size, similarityIndex }) => {
    const vectors = [];

    // Add query vector
    vectors.push(generateQueryVector());

    // Generate database vectors
    for (let i = 0; i < size; i++) {
        vectors.push(i === similarityIndex ? generateMatchingVector() : generateRandomVector());
    }

    // Write to file
    await fs.writeFile(filepath, `${size}\n${vectors.join('\n')}\n`);

    return { totalVectors: size, similarityIndex, randomVectors: size - 1 };
};

// Main execution
const main = async () => {
    try {
        const { filepath, size, similarityIndex } = validateArgs(process.argv);

        console.log(`Generating dataset with ${size} vectors...`);
        console.log(`Similarity vector at index: ${similarityIndex}`);

        const { totalVectors, similarityIndex: index, randomVectors } = await generateDataset({
            filepath,
            size,
            similarityIndex
        });

        console.log(`\nDataset successfully written to: ${filepath}`);
        console.log(`Total vectors: ${totalVectors}`);
        console.log(`Similarity vector: is at index ${index}`);
        console.log(`Random vectors: ${randomVectors}`);

    } catch (error) {
        console.error('Error:', error.message);
        printUsage();
        process.exit(1);

    }
};

// Run main if script is executed directly
if (require.main === module) {
    main();
}

// Exports for testing
module.exports = {
    generateQueryVector,
    generateRandomVector,
    generateMatchingVector,
    generateDataset,
    validateArgs
};