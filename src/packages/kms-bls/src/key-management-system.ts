import { AbstractKeyManagementSystem, AbstractPrivateKeyStore, ManagedPrivateKey } from '@veramo/key-manager'
import { KeyManagementSystem } from '@veramo/kms-local'
import { TKeyType, IKey, ManagedKeyInfo, MinimalImportableKey, RequireOnly } from '@veramo/core'

import { Bls12381G2KeyPair } from '@mattrglobal/bls12381-key-pair';

import * as u8a from 'uint8arrays'

const { binary_to_base58 } = require('base58-js')

export class BlsKeyManagementSystem extends AbstractKeyManagementSystem {
    private readonly keyStore: AbstractPrivateKeyStore

    constructor(keyStore: AbstractPrivateKeyStore) {
        super();

        this.keyStore = keyStore;
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
            throw Error('not_supported: key type not supported');
        }
    }

    async deleteKey(args: { kid: string }) {
        return await this.keyStore.delete({ alias: args.kid })
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
            throw Error('not_supported: key type not supported');
        }
    }

    async listKeys(): Promise<ManagedKeyInfo[]> {
        const privateKeys = await this.keyStore.list({})

        const managedKeys = privateKeys.filter((key) => key.type == "Bls12381G2")
            .map((key) => this.asManagedKeyInfo(key));

        return managedKeys;
    }

    async sign(args: {
        keyRef: Pick<IKey, 'kid'>
        algorithm?: string
        data: Uint8Array
        [x: string]: any
      }): Promise<string> {

        let managedKey: ManagedPrivateKey
        try {
            managedKey = await this.keyStore.get({ alias: args.keyRef.kid })
        } catch (e) {
            throw new Error(`key_not_found: No key entry found for kid=${args.keyRef.kid}`)
        }
        
        if(!args.binaryData) {
            throw new Error(`invalid_args: binaryData argument is null`);
        }

        if(!managedKey.privateKeyHex) {
            throw new Error(`invalid_private_key: no private key for kid=${args.keyRef.kid}`);
        }

        if(managedKey.type != 'Bls12381G2') {
            throw Error('not_supported: key type not supported');
        }

        const binaryData = args.binaryData;
            
        const publicKey = u8a.fromString(args.keyRef.kid, 'base16'); 
        const privateKey = u8a.fromString(managedKey.privateKeyHex, 'base16');      

        const k = new Bls12381G2KeyPair({
            id: '',
            publicKeyBase58: binary_to_base58(publicKey),
            privateKeyBase58: binary_to_base58(privateKey),
        });

        const signedData = await k.signer().sign({ data: binaryData });

        return u8a.toString(signedData, 'base64');
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

