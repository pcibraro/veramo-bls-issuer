import { agent } from './veramo/setup'

async function main() {
  
    const expirationDate = new Date();
    expirationDate.setFullYear(expirationDate.getFullYear() + 3);

    const did = 'did:web:d933-181-31-123-153.ngrok.io';
    const key = 'ae29846d958baf8b6d9cc2aff91f08741a6b4116a4f6b0802b28c1d2f2d1152fdd1dbaea754895f28af3f4cbb69cde2417541e678e39f8a4681f57a95863caea4dcd61dacba8dac7b0e5562a0123d0070d7b39baeb4cc698079ecefeb7509ea8';

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