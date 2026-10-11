#!/usr/bin/env node
// Prints a new Ed25519 private JWK (with kid) to stdout.
// Pipe it straight into your secret store. Never redirect it into a file in this repo.
import { generateKeyPairSync, randomBytes } from 'node:crypto'

const { privateKey } = generateKeyPairSync('ed25519')
const jwk = privateKey.export({ format: 'jwk' })
jwk.kid = randomBytes(8).toString('hex')
jwk.alg = 'EdDSA'
jwk.use = 'sig'
process.stdout.write(JSON.stringify(jwk))
