import { generateKeyPair } from 'node:crypto'
import { promisify } from 'node:util'

const generateKeyPairAsync = promisify(generateKeyPair)

async function generateKeys() {
  const { privateKey, publicKey } = await generateKeyPairAsync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  })
  console.info('Private Key:', privateKey)
  console.info('Public Key:', publicKey)
}

generateKeys()
