"use strict";
const blindSignatures = require('blind-signatures');
const utils = require('./utils.js');

const COIN_RIS_LENGTH = 20;
const IDENT_STR = "IDENT";
const BANK_STR = "ELECTRONIC_PIGGYBANK";

class Coin {
  constructor(purchaser, amount, n, e) {
    if (!purchaser || !amount || !n || !e) {
      throw new Error("Missing required coin parameters");
    }
    
    this.amount = amount;
    this.n = n;
    this.e = e;
    this.guid = utils.makeGUID();
    this.leftIdent = [];
    this.rightIdent = [];

    try {
      let leftHashes = [];
      let rightHashes = [];

      for (let i = 0; i < COIN_RIS_LENGTH; i++) {
        const { key, ciphertext } = utils.makeOTP({string: `${IDENT_STR}:${purchaser}`});
        
        if (!key || !ciphertext) throw new Error("OTP generation failed");
        
        this.leftIdent.push(key);
        leftHashes.push(utils.hash(key));
        this.rightIdent.push(ciphertext);
        rightHashes.push(utils.hash(ciphertext));
      }

      this.coinString = `${BANK_STR}-${this.amount}-${this.guid}-${leftHashes.join(',')}-${rightHashes.join(',')}`;
      this.blind();
    } catch (err) {
      throw new Error(`Coin creation failed: ${err.message}`);
    }
  }

  blind() {
    try {
      const { blinded, r } = blindSignatures.blind({
        message: this.toString(),
        N: this.n,
        E: this.e,
      });
      
      if (!blinded || !r) throw new Error("Blinding returned invalid values");
      
      this.blinded = blinded;
      this.blindingFactor = r;
    } catch (err) {
      throw new Error(`Blinding failed: ${err.message}`);
    }
  }

  unblind() {
    try {
      if (!this.signature) throw new Error("No signature to unblind");
      
      this.signature = blindSignatures.unblind({
        signed: this.signature,
        N: this.n,
        r: this.blindingFactor,
      });
      
      if (!this.signature) throw new Error("Unblinding failed");
    } catch (err) {
      throw new Error(`Unblinding failed: ${err.message}`);
    }
  }

  toString() {
    return this.coinString;
  }

  getRis(isLeft, i) {
    if (i < 0 || i >= COIN_RIS_LENGTH) {
      throw new Error(`RIS index out of bounds: ${i}`);
    }
    
    return isLeft ? this.leftIdent[i] : this.rightIdent[i];
  }
}

exports.Coin = Coin;
exports.COIN_RIS_LENGTH = COIN_RIS_LENGTH;
exports.IDENT_STR = IDENT_STR;
exports.BANK_STR = BANK_STR;