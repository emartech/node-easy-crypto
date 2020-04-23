# node-easy-crypto [ ![Codeship Status for emartech/node-easy-crypto](https://codeship.com/projects/0baf8660-f4ea-0133-b502-5ef57cbd419a/status?branch=master)](https://codeship.com/projects/150193) [![Depedencies](https://david-dm.org/emartech/node-easy-crypto.svg)](https://david-dm.org/emartech/node-easy-crypto) [![Dev depedencies](https://david-dm.org/emartech/node-easy-crypto/dev-status.svg)](https://david-dm.org/emartech/node-easy-crypto#info=devDependencies&view=table)
Provides simple wrappers around Node's crypto implementation. The library provides two interfaces: simple and advanced. Simple mode is designed for ease-of-use and advanced mode provides some performance benefits in certain use-cases. See below for more details.

All the underlying crypto operations are the same.

## Simple usage (Recommended)
To get started just require the lib and create an instance right away. 

```js
const crypto = require('crypto');
const easyCrypto = require('@emartech/easy-crypto');

const password = crypto.randomBytes(24).toString('hex');
const randomData = crypto.randomBytes(1024).toString('hex');

const ecrypto = easyCrypto(password);

async function exampleAsyncFunction() {
    const encrypted = await ecrypto.encrypt(randomData);
    const decrypted = await ecrypto.decrypt(encrypted);
    randomData === decrypted; //true
}
```

## Advanced usage (Use for performance)
[Key derivation](https://en.wikipedia.org/wiki/Key_derivation_function) is a resource heavy process. The default settings recompute the key before each encryption/decryption process. 

These options allow you to cache the result of the key derivation. This is required if you need to encrypt/decrypt multiple times with the same derived key. Caching the keys with [node-cache](https://github.com/node-cache/node-cache) saves you the time to have to recompute it before every encryption/decryption.

To get started just require the lib and create an instance right away.

```js
const crypto = require('crypto');
const easyCrypto = require('@emartech/easy-crypto');

const password = crypto.randomBytes(24).toString('hex');
const randomData = [
    crypto.randomBytes(1024).toString('hex'),
    crypto.randomBytes(1024).toString('hex'),
    crypto.randomBytes(1024).toString('hex')
];

const ecrypto = easyCrypto(password, {
  encryptCacheTtl: 3600,
  decryptCachePoolSize: 100,
});

async function exampleAsyncFunction() {
    const encrypted = await Promise.all(
        randomData.map(item => ecrypto.encrypt(item))
    );

    const decrypted = await Promise.all(
        encrypted.map(item => ecrypto.decrypt(item))
    );
    
    return data.reduce((allValid, item, index) => {
        return allValid && item === decrypted[index];
    }, true);
}
```

## Interface

### Initialization
There aren't too many options you can change and that is on purpose. This small wrapper library is secure by default. You can change two configurations: `encryptCacheTtl`, `decryptCachePoolSize` by passing them to the initialization function as follows:
```js
let ecrypto = require('@emartech/easy-crypto')('password', {
  encryptCacheTtl: 3600,
  decryptCachePoolSize: 100,
});
```

#### `password`
`password` should be any normal string. It will be used to generate the encryption key.

#### `encryptCacheTtl`
Time in seconds while the same key is reused during encryption. Must be an integer.

#### `decryptCachePoolSize`
Maximum number of keys kept in the cache during decryption. Must be an integer.

### encrypt(`plaintext`) -> `ciphertext`
`plaintext` must be `utf-8` encoded string. It will be "converted" to `bytes` and those will be used for the cryptographic operations. The output of this operations is `base64` encoded buffers. This will be used as the input of the `decrypt` operation. This return value is a `Promise`.

### decrypt(`ciphertext`) -> `plaintext`
`ciphertext` must be the output of the `encrypt` method. The library is not compatible with any other encryption library out of the box! The output of this operation is the original `utf-8` encoded string. This return value is a `Promise`.

## The crypto parts
The library is only a thin wrapper of node's own `crypto` module. It uses well known and battle tested encryption techniques. It provides a convenient wrapper around these functions, taking away the details of using encryption correctly. Feel free to explore the source!

### Encryption process
1. It generates random bytes for later operations
2. `passwordSaltSize` random `bytes` are used to create the `256 bit` long encryption key from the `password` using `pbkdf2` and the given `iteration count`
3. The `plaintext` is encrypted using `aes-256-gcm` with the generated key and a `12 bytes` long random `initialization vector`, this operation also yields a `16 bytes` long `authentication tag`, which can be used to verify the encrypted data's integrity
4. It concatenates the following data to into a buffer: `passwordSalt bytes`, `initialization vector bytes`, `ciphertext bytes`, `authentication tag bytes`
5. It encodes the whole buffer using `base64` and returns it

### Decryption process
1. It decodes the `base64` input to bytes
2. It slices this data into: `passwordSalt bytes`, `initialization vector bytes`, `ciphertext bytes`, `authentication tag bytes`
3. The `passwordSalt bytes` and the `password` are used to generate the `256 bit` long encryption key using `pbkdf2` and the given `iteration count`
4. The `ciphertext bytes` are decrypted using `aes-256-gcm` with the generated key the `initialization vector bytes`. During encryption the integrity of the date is also verified using the `authentication tag bytes`
5. It encodes the decrypted buffer using `utf-8` and returns it

## Found a bug? Have a comment?
Please find us, we would love your feedback!