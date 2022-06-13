import { agent } from './veramo/setup'

async function main() {

  const identity = await agent.didManagerCreate(
    {
      provider: 'did:web',
      alias: 'e554-181-31-123-153.ngrok.io',
      options: {
        keyType: 'Bls12381G2',
        meta: {
          verificationMethod: {
            type: "BbsBlsSignatureProof2020"
          }
        }
      },

    });

  console.log(`New identity created`)
  console.log(JSON.stringify(identity));
}

main().catch(console.log)