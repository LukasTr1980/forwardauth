import argon2 from 'argon2';
import * as readline from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';

async function generateHash() {
    const rl = readline.createInterface({ input, output });

    try {
        const password = await rl.question('Enter password for hashing: ');

        if (!password) {
            console.error('\nError: password cannot be emtyp.');
            return;
        }

        console.log('\nHashing password... (may take a few seconds)');
        const hash = await argon2.hash(password);

        console.log('\n--- Your Argon2 hash ---');
        console.log(hash);
        console.log('-----------------------------------\nCopy this hash in your users.json file.');
    } catch (error) {
        console.error('\nError while hashing passwords:', error);
    } finally {
        rl.close();
    }
}

generateHash();