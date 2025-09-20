#!/usr/bin/env node

const { spawn } = require('child_process');
const fs = require('fs').promises;
const path = require('path');

// Test configuration
const TEST_SIZES = [1000, 10000, 100000, 1000000]; // Adjusted INT_MAX to 1,000,000
const OUTPUT_FILE = 'test_results.log';
const BASE_DIR = path.resolve(__dirname, '..');

class CommandRunner {
    constructor() {
        this.results = [];
        this.baseDir = BASE_DIR;
    }

    async runCommand(command, args = [], cwd = this.baseDir) {
        return new Promise((resolve, reject) => {
            console.log(`Running: ${command} ${args.join(' ')}`);
            const process = spawn(command, args, {
                cwd,
                stdio: ['pipe', 'pipe', 'pipe']
            });

            let stdout = '';
            let stderr = '';

            process.stdout.on('data', (data) => {
                stdout += data.toString();
            });

            process.stderr.on('data', (data) => {
                stderr += data.toString();
            });

            process.on('close', (code) => {
                if (code === 0) {
                    resolve({ stdout, stderr });
                } else {
                    reject(new Error(`Command failed with code ${code}: ${stderr}`));
                }
            });
        });
    }

    async runTest(size) {
        const testDataFile = `test_data_${size}.dat`;
        const testDataPath = path.join(this.baseDir, testDataFile);
        const similarityIndex = Math.floor(Math.random() * size);
        let resultLog = `\n=== Test for ${size} elements ===\n`;

        try {
            // Step 1: Generate test data
            const generateResult = await this.runCommand('node', [
                './scripts/generate_data.js',
                testDataFile,
                size.toString(),
                similarityIndex.toString()
            ]);
            resultLog += `Generate Data Output:\n${generateResult.stdout}\n`;
            if (generateResult.stderr) {
                resultLog += `Generate Data Errors:\n${generateResult.stderr}\n`;
            }

            // Step 2: Build the project
            try {
                await fs.access(path.join(this.baseDir, 'build'));
            } catch {
                await this.runCommand('mkdir', ['build']);
            }

            await this.runCommand('cmake', ['..'], path.join(this.baseDir, 'build'));
            await this.runCommand('make', [], path.join(this.baseDir, 'build'));
            resultLog += `Build successful\n`;

            // Step 3: Run the main program
            const runResult = await this.runCommand('./Main', [("../" + testDataFile)], path.join(this.baseDir, 'build'));
            resultLog += `Main Program Output:\n${runResult.stdout}\n`;
            if (runResult.stderr) {
                resultLog += `Main Program Errors:\n${runResult.stderr}\n`;
            }

            // Clean up test data
            await fs.unlink(testDataPath).catch(() => { });

            // Store result
            this.results.push({
                vectorSize: size,
                output: runResult.stdout,
                errors: runResult.stderr,
                timestamp: new Date().toISOString()
            });

            // Append to log file
            await fs.appendFile(path.join(this.baseDir, OUTPUT_FILE), resultLog);

            console.log(`Completed test for size ${size}`);

        } catch (error) {
            resultLog += `Error: ${error.message}\n`;
            await fs.appendFile(path.join(this.baseDir, OUTPUT_FILE), resultLog);
            console.error(`Test failed for size ${size}: ${error.message}`);
            // Clean up test data on error
            await fs.unlink(testDataPath).catch(() => { });
        }
    }

    async runAllTests() {
        console.log('Starting tests...');
        console.log(`Test sizes: ${TEST_SIZES.join(', ')}`);

        // Clear or create the output file
        await fs.writeFile(path.join(this.baseDir, OUTPUT_FILE), '=== Test Results ===\n');

        // Run tests for each size
        for (const size of TEST_SIZES) {
            await this.runTest(size);
        }

        console.log(`\n=== Tests Complete ===`);
        console.log(`Results saved to: ${OUTPUT_FILE}`);
    }

    printSummary() {
        console.log('\n=== Test Summary ===');
        console.log('Vector Size\tTimestamp');
        console.log('-----------\t-------------------');
        this.results.forEach(r => {
            console.log(`${r.vectorSize.toLocaleString()}\t${r.timestamp}`);
        });
    }
}

// Main execution
async function main() {
    const runner = new CommandRunner();

    try {
        await runner.runAllTests();
        runner.printSummary();
    } catch (error) {
        console.error('Tests failed:', error.message);
        process.exit(1);
    }
}

// Run if executed directly
if (require.main === module) {
    main();
}

module.exports = CommandRunner;