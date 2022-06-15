// Core interfaces
import { createAgent, IDIDManager, IResolver, IDataStore, IKeyManager, IMessageHandler } from '@veramo/core'

// Core identity manager plugin
import { DIDManager } from '@veramo/did-manager'

// Web did identity provider
import { WebDIDProvider } from '@veramo/did-provider-web'

// Core key manager plugin
import { KeyManager } from '@veramo/key-manager'

// Custom key management system for RN
import { KeyManagementSystem, SecretBox } from '@veramo/kms-local'

import { BlsKeyManagementSystem } from '../packages/kms-bls/src'

// Custom resolvers
import { DIDResolverPlugin } from '@veramo/did-resolver'
import { Resolver } from 'did-resolver'
import { getResolver as webDidResolver } from 'web-did-resolver'

// Storage plugin using TypeOrm
import { Entities, KeyStore, DIDStore, PrivateKeyStore, migrations, DataStoreORM } from '@veramo/data-store'

// TypeORM is installed with `@veramo/data-store`
import { createConnection } from 'typeorm'

// Credential issuer
import { CredentialIssuer, ICredentialIssuer } from '@veramo/credential-w3c';

import {
  ICredentialIssuerLD,
  CredentialIssuerLD,
  LdDefaultContexts,
  VeramoEcdsaSecp256k1RecoverySignature2020,
  VeramoEd25519Signature2018
} from '@veramo/credential-ld';

import { VeramoBbsBlsSignatureProof2020 } from '../packages/credential-ld-bls/src';

// Storage for saving credentials locally
import { DataStore } from '@veramo/data-store';

import * as fs from 'fs';
import * as path from 'path';

// This will be the name for the local sqlite database for demo purposes
const DATABASE_FILE = 'database.sqlite'

// You will need to get a project ID from infura https://www.infura.io
const INFURA_PROJECT_ID = '6741d374bd12457daf1a18241a3999f7'

// This will be the secret key for the KMS
const KMS_SECRET_KEY = '11d9943d70e8f7a4bb291648599cf61a817d15c8e2a9c69400d6bb5c9c62592c';

function _read(_path: string) {
  return JSON.parse(fs.readFileSync(path.join(__dirname, '../contexts', _path), { encoding: 'utf8' }))
}

const dbConnection = createConnection({
  type: 'sqlite',
  database: DATABASE_FILE,
  synchronize: false,
  migrations,
  migrationsRun: true,
  logging: ['error', 'info', 'warn'],
  entities: Entities,
});

const contexts = new Map([
  ['https://w3id.org/citizenship/v1', _read('citizen.jsonld')],
  ['https://w3id.org/security/bbs/v1', _read('bbs.jsonld')],
  ['https://w3id.org/security/suites/jws-2020/v1', _read('lds-jws2020-v1.jsonld')],
  ['https://w3id.org/security/suites/bls12381-2020/v1', _read('ldp-bbs2020.jsonld')]
]);

export const agent = createAgent<IDIDManager & IKeyManager & IDataStore & IResolver & ICredentialIssuer & ICredentialIssuerLD>({
  plugins: [
    new KeyManager({
      store: new KeyStore(dbConnection),
      kms: {
        local: new BlsKeyManagementSystem(new PrivateKeyStore(dbConnection, new SecretBox(KMS_SECRET_KEY))),
      },
    }),
    new DIDManager({
      store: new DIDStore(dbConnection),
      defaultProvider: 'did:web',
      providers: {
        'did:web': new WebDIDProvider({
          defaultKms: 'local',
        })
      },
    }),
    new DIDResolverPlugin({
      resolver: new Resolver({
        ...webDidResolver(),
      }),
    }),
    new CredentialIssuerLD({
      contextMaps: [LdDefaultContexts, contexts],
      suites: [
        new VeramoEcdsaSecp256k1RecoverySignature2020(), 
        new VeramoEd25519Signature2018(),
        new VeramoBbsBlsSignatureProof2020()],
    }),
    new CredentialIssuer(),
    new DataStore(dbConnection),
    new DataStoreORM(dbConnection)
  ],
})