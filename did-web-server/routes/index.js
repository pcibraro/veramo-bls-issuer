var express = require('express');
var router = express.Router();
const u8a = require("uint8arrays");
const { binary_to_base58 } = require('base58-js')

const contexts = [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/bls12381-2020/v1"
];

const publicKeyHex = '874b969345bce1a080582b92bfdd14930017b8ece4484974573d71307908a4c9a926ef16245411ea28277ca9e1c37b2108769a09e59d8df33517cefa722091fe2d5389b272c74a9f475ca31d7462d9ba59414a58aa7ffbaa5189f41b868d694c';
const publicKeyBase58 = binary_to_base58(u8a.fromString(publicKeyHex, 'base16'));

/* GET home page. */
router.get('/', function(req, res, next) {
  
  const did = {
    "@context": contexts,
    id: `did:web:${req.headers.host}`,
    verificationMethod: [
      {
        id: `did:web:${req.headers.host}#${publicKeyHex}`,
        type: 'Bls12381G2Key2020',
        controller: `did:web:${req.headers.host}`,
        publicKeyHex: publicKeyHex,
        publicKeyBase58: publicKeyBase58
      }
    ],
    assertionMethod: [
      `did:web:${req.headers.host}#${publicKeyHex}`
    ]
  }
  
  res.json(did);
});

module.exports = router;
