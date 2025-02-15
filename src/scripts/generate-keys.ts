import { generateKeyPair } from 'crypto'
import { promisify } from 'util'

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

  console.log('Private Key:', privateKey)
  console.log('Public Key:', publicKey)
}

generateKeys()
