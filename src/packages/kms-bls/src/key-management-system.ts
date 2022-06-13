import { AbstractKeyManagementSystem, AbstractPrivateKeyStore } from '@veramo/key-manager'
import { KeyManagementSystem } from '@veramo/kms-local'
import { TKeyType, IKey, ManagedKeyInfo, MinimalImportableKey, RequireOnly } from '@veramo/core'

import { Bls12381G2KeyPair } from '@mattrglobal/bls12381-key-pair';

import * as u8a from 'uint8arrays'

export class BlsKeyManagementSystem extends AbstractKeyManagementSystem {
    private readonly keyStore: AbstractPrivateKeyStore
    private readonly innerKeyManagementSystem: KeyManagementSystem;

    constructor(keyStore: AbstractPrivateKeyStore) {
        super();

        this.keyStore = keyStore;
        this.innerKeyManagementSystem = new KeyManagementSystem(keyStore);
    }

    async importKey(args: Omit<MinimalImportableKey, 'kms'>): Promise<ManagedKeyInfo> {
        if (!args.type || !args.privateKeyHex) {
            throw new Error('invalid_argument: type and privateKeyHex are required to import a key')
        }

        if (args.type === 'Bls12381G2') {

            if (!args.publicKeyHex) {
                throw new Error('invalid_argument: publicKeyHex is required to import a key')
            }

            const managedKey = this.asManagedKeyInfo({ ...args })
            await this.keyStore.import({ alias: managedKey.kid, ...args })

            return managedKey
        }
        else {
            throw Error('key type not supported');
        }
    }

    async deleteKey(args: { kid: string }) {
        return this.innerKeyManagementSystem.deleteKey(args);
    }

    async createKey({ type }: { type: TKeyType }): Promise<ManagedKeyInfo> {
        let key: ManagedKeyInfo

        if (type === "Bls12381G2") {
            const keyPair = await Bls12381G2KeyPair.generate();

            if (!keyPair.privateKeyBuffer || !keyPair.publicKeyBuffer) {
                throw new Error('error: keys were not generated')
            }

            key = await this.importKey({
                type,
                privateKeyHex: u8a.toString(keyPair.privateKeyBuffer, 'base16'),
                publicKeyHex: u8a.toString(keyPair.publicKeyBuffer, 'base16')
                
            })
            return key;
        } else {
            return this.innerKeyManagementSystem.createKey({ type });
        }
    }

    async listKeys(): Promise<ManagedKeyInfo[]> {
        const privateKeys = await this.keyStore.list({})
        
        const managedKeys = privateKeys.filter((key) => key.type == "Bls12381G2")
            .map((key) => this.asManagedKeyInfo(key));
        
        return managedKeys
    }

    async sign({
        keyRef,
        algorithm,
        data,
    }: {
        keyRef: Pick<IKey, 'kid'>
        algorithm?: string
        data: Uint8Array
    }): Promise<string> {

        throw Error("not supported");
    }

    async sharedSecret(args: {
        myKeyRef: Pick<IKey, 'kid'>
        theirKey: Pick<IKey, 'type' | 'publicKeyHex'>
    }): Promise<string> {
        throw Error("not supported");
    }
    
    /**
  * Converts a {@link ManagedPrivateKey} to {@link ManagedKeyInfo}
  */
    private asManagedKeyInfo(args: Omit<MinimalImportableKey, 'kms'>): ManagedKeyInfo {

        const key: Partial<ManagedKeyInfo> = {
            type: args.type,
            kid: args.publicKeyHex,
            publicKeyHex: args.publicKeyHex,
            meta: {
                verificationMethod: {
                  type: "BbsBlsSignatureProof2020"
                }
            }
        }

        return key as ManagedKeyInfo;
    }
}

