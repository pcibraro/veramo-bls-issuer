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

class SuiteWrapper {
    private readonly factory: () => Promise<any>;
    private innerSuite: any;
    public verificationMethod?: string;
 
    async createProof({ document, purpose, documentLoader, expansionMap, compactProof }: any): Promise<any>
    {
        if(!this.innerSuite) {
            this.innerSuite = await this.factory();
        }

        return await this.innerSuite.createProof({ document, purpose, documentLoader, expansionMap, compactProof });
    }
    
    ensureSuiteContext({ document }: any) {
        if(this.innerSuite) {
            this.innerSuite.ensureSuiteContext({ document });
        }
    }
    
    constructor(factory: () => Promise<any>, verificationMethod?: string) {
        this.factory = factory;
        this.verificationMethod = verificationMethod;
    }
}

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
        
        const factory : SuiteWrapper = new SuiteWrapper(async() => {
            const storeKey = await this.keyStore.get({ alias: key.kid });
            
            const publicKey = u8a.fromString(key.publicKeyHex, 'base16'); 
            const privateKey = storeKey.privateKeyHex ? u8a.fromString(storeKey.privateKeyHex, 'base16') : undefined;       
        
            const keyPair = new Bls12381G2KeyPair( { 
                controller: issuerDid,
                id: `${issuerDid}#${key.kid}`,
                type: key.type,
                publicKey: publicKey,
                privateKey: privateKey
            });

            return new BbsBlsSignature2020({ 
                key: keyPair
            });
        }, `${issuerDid}#${key.kid}`);

        return factory;
    }

    getSuiteForVerification() {
        return new BbsBlsSignature2020();
    }

    preDidResolutionModification(didUrl: string, didDoc: DIDDocument): void {
        
    }

    preSigningCredModification(credential: CredentialPayload): void {
        
    }
}


