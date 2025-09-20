#!/usr/bin/env node

const fs = require('fs').promises;
const path = require('path');

// Constants
const DIM = 512;

/**
 * WHY IS THIS FAILING FOR LARGE SIZES?
 * 
 * The error "Invalid string length" occurs because the code tries to create a single massive string
 * by joining all vectors (each of length 512) into one string before writing to disk.
 * For very large sizes (e.g., 1,000,000 vectors), this string can exceed V8's maximum string length
 * (which is around 512MB to 1GB, depending on the Node.js version and platform).
 * 
 * Solution: Write vectors to the file incrementally (streaming), not all at once.
 */

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


// Dataset generation (streaming version for large files)
const generateDataset = async ({ filepath, size, similarityIndex }) => {
    // Use a write stream to avoid building a huge string in memory
    const fsSync = require('fs');
    const stream = fsSync.createWriteStream(filepath, { encoding: 'utf8' });

    // Write the size as the first line
    stream.write(`${size}\n`);

    // Write the query vector
    stream.write(generateQueryVector() + '\n');

    // Write each database vector, one per line
    for (let i = 0; i < size; i++) {
        const vec = (i === similarityIndex) ? generateQueryVector() : generateRandomVector();
        stream.write(vec + '\n');
    }

    // Return a promise that resolves when the stream is finished
    await new Promise((resolve, reject) => {
        stream.end(resolve);
        stream.on('error', reject);
    });

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
    generateDataset,
    validateArgs
};