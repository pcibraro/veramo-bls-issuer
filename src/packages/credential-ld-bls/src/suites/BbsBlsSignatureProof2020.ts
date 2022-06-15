import { VeramoLdSignature } from '@veramo/credential-ld'
import {
    CredentialPayload,
    DIDDocument,
    IAgentContext,
    IKey,
    TKeyType
} from '@veramo/core'

import { AbstractPrivateKeyStore } from '@veramo/key-manager'

import * as u8a from 'uint8arrays'
import { RequiredAgentMethods } from '@veramo/credential-ld/build/ld-suites'

import { BbsBlsSignature2020 } from '@transmute/bbs-bls12381-signature-2020'

import { Bls12381G2KeyPair } from '@transmute/bls12381-key-pair';
import { sign } from 'crypto'

export class VeramoBbsBlsSignatureProof2020 extends VeramoLdSignature {

    private readonly keyStore: AbstractPrivateKeyStore

    //TODO: this is a bit hacky. The context should provide a way to get the private key. 
    //We can not delegate that to the kms set in the context as it is being done with the other suites as 
    // the BLS suite does not support that.
    constructor(keyStore: AbstractPrivateKeyStore) {
        super();

        this.keyStore = keyStore;
    }

    getSupportedVerificationType(): string {
        return 'Bls12381G2Key2020'
    }
    getSupportedVeramoKeyType(): TKeyType {
        return 'Bls12381G2'
    }

    getSuiteForSigning(key: IKey, issuerDid: string, verificationMethodId: string, context: IAgentContext<RequiredAgentMethods>) {

        //TODO: We should ideally use the context here to get the private key but this method is sync
        //context does not provide a way to get a private key

        const keyStore = this.keyStore;

        const publicKey = u8a.fromString(key.publicKeyHex, 'base16');

        const signer = {
            // returns a JWS detached
            sign: async (args: { data: any }): Promise<Uint8Array> => {
                
                const signature = await context.agent.keyManagerSign({
                    keyRef: key.kid,
                    algorithm: '',
                    data: '',
                    encoding: 'utf-8',
                    binaryData: args.data
                })

                return u8a.fromString(signature, 'base64')
            },
        }

        const keyPair = new Bls12381G2KeyPair({
            controller: issuerDid,
            id: `${issuerDid}#${key.kid}`,
            type: key.type,
            publicKey: publicKey
        });
        keyPair.signer = () => signer;

        return new BbsBlsSignature2020({
            key: keyPair
        });
    }

    getSuiteForVerification() {
        return new BbsBlsSignature2020();
    }

    preDidResolutionModification(didUrl: string, didDoc: DIDDocument): void {

    }

    preSigningCredModification(credential: CredentialPayload): void {

    }
}


