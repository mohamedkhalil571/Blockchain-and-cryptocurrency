"use strict";
// required npm install blind-signatures
const blindSignatures = require('blind-signatures');

const { Coin, COIN_RIS_LENGTH, IDENT_STR, BANK_STR } = require('./coin.js');
const utils = require('./utils.js');

// Details about the bank's key.
const BANK_KEY = blindSignatures.keyGeneration({ b: 2048 });
const N = BANK_KEY.keyPair.n.toString();
const E = BANK_KEY.keyPair.e.toString();

/**
 * Function signing the coin on behalf of the bank.
 * 
 * @param blindedCoinHash - the blinded hash of the coin.
 * 
 * @returns the signature of the bank for this coin.
 */
function signCoin(blindedCoinHash) {
  return blindSignatures.sign({
      blinded: blindedCoinHash,
      key: BANK_KEY,
  });
}

/**
 * Parses a string representing a coin, and returns the left/right identity string hashes.
 *
 * @param {string} s - string representation of a coin.
 * 
 * @returns {[[string]]} - two arrays of strings of hashes, commiting the owner's identity.
 */
function parseCoin(s) {
  let [cnst,amt,guid,leftHashes,rightHashes] = s.split('-');
  if (cnst !== BANK_STR) {
    throw new Error(`Invalid identity string: ${cnst} received, but ${BANK_STR} expected`);
  }
  //console.log(`Parsing ${guid}, valued at ${amt} coins.`);
  let lh = leftHashes.split(',');
  let rh = rightHashes.split(',');
  return [lh,rh];
}

/**
 * Procedure for a merchant accepting a token. The merchant randomly selects
 * the left or right halves of the identity string.
 * 
 * @param {Coin} - the coin that a purchaser wants to use.
 * 
 * @returns {[String]} - an array of strings, each holding half of the user's identity.
 */
function acceptCoin(coin) {
  // 1) Verify that the signature is valid
  const isValid = blindSignatures.verify({
    unblinded: coin.signature,
    N: N,
    E: E,
    message: coin.toString()
  });
  
  if (!isValid) {
    throw new Error("Invalid coin signature");
  }

  const [leftHashes, rightHashes] = parseCoin(coin.toString());
  const ris = [];
  
  for (let i = 0; i < COIN_RIS_LENGTH; i++) {
  
    const isLeft = utils.randInt(2) === 0;
    const risElement = coin.getRis(isLeft, i);
    const expectedHash = isLeft ? leftHashes[i] : rightHashes[i];
    
    
    if (utils.hash(risElement) !== expectedHash) {
      throw new Error(`RIS hash mismatch at position ${i}`);
    }
    
    ris.push(risElement.toString('hex'));
  }

 
  return ris;
  

}

/**
 * If a token has been double-spent, determine who is the cheater
 * and print the result to the screen.
 * 
 * If the coin purchaser double-spent their coin, their anonymity
 * will be broken, and their idenityt will be revealed.
 * 
 * @param guid - Globablly unique identifier for coin.
 * @param ris1 - Identity string reported by first merchant.
 * @param ris2 - Identity string reported by second merchant.
 */
function determineCheater(guid, ris1, ris2) {
   // Check if RIS strings are identical
   if (JSON.stringify(ris1) === JSON.stringify(ris2)) {
    console.log(`Coin ${guid}: Merchant is cheating!`);
    return;
  }

  // Try to reveal the purchaser's identity
  for (let i = 0; i < ris1.length; i++) {
    try {
      const buf1 = Buffer.from(ris1[i], 'hex');
      const buf2 = Buffer.from(ris2[i], 'hex');
      
      if (buf1.length !== buf2.length) continue;
      
      const decrypted = utils.decryptOTP({
        key: buf1,
        ciphertext: buf2,
        returnType: 'string'
      });
      
      if (decrypted.startsWith(IDENT_STR)) {
        const purchaser = decrypted.split(':')[1];
        console.log(`Coin ${guid}: Purchaser ${purchaser} is cheating!`);
        return;
      }
    } catch (e) {
    
      continue;
    }
  }
  
  console.log(`Coin ${guid}: Unable to determine who cheated`);

}

let coin = new Coin('alice', 20, N, E);

coin.signature = signCoin(coin.blinded);

coin.unblind();


// Merchant 1 accepts the coin.
let ris1 = acceptCoin(coin);


// Merchant 2 accepts the same coin.
let ris2 = acceptCoin(coin);


// The bank realizes that there is an issue and
// identifies Alice as the cheater.
determineCheater(coin.guid, ris1, ris2);

console.log();
// On the other hand, if the RIS strings are the same,
// the merchant is marked as the cheater.
determineCheater(coin.guid, ris1, ris1);
