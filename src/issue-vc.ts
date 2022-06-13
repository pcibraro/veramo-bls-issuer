import { agent } from './veramo/setup'

async function main() {
  
    const expirationDate = new Date();
    expirationDate.setFullYear(expirationDate.getFullYear() + 3);

    const did = 'did:web:e554-181-31-123-153.ngrok.io';
    const key = '874b969345bce1a080582b92bfdd14930017b8ece4484974573d71307908a4c9a926ef16245411ea28277ca9e1c37b2108769a09e59d8df33517cefa722091fe2d5389b272c74a9f475ca31d7462d9ba59414a58aa7ffbaa5189f41b868d694c';

    const vc = await agent.createVerifiableCredential({
        credential: { 
            '@context': [
                'https://w3id.org/citizenship/v1',
                'https://w3id.org/security/suites/jws-2020/v1',
                'https://w3id.org/security/suites/bls12381-2020/v1'
            ],
            issuer: {
                id: did
            },
            type: ['VerifiableCredential'],
            credentialSubject: {
                type: ["PermanentResident"],
                id: did,
                givenName: 'Pablo',
                familyName: 'Cibraro'
            },
            expirationDate: expirationDate.toJSON(),
            id: did
        },
        
        save: true,
        proofFormat: 'lds',
        keyRef: `${did}#${key}`
    });

    console.log(JSON.stringify(vc));

    const verified = await agent.verifyCredential({
        credential: vc,
        fetchRemoteContexts: false
    });
  
    console.log(`verified ${verified}`);
}

main().catch(console.log)