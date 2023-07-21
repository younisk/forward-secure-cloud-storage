# Puncturable Key Wrapping

A proto-implementation of Puncturable Key Wrapping based on *Puncturable Key Wrapping and Its Applications* (Backendal,
Günther & Paterson, 2022).

## API

### [AbstractPKW](pkw/pkw.h)

An abstract class defining the interface puncturable key wrapping classes should provide.

### [NaivePKW](pkw/naive_pkw.h)

A naive instantiation for show purposes, using *CryptoPP*.

## Key serialization

Keys can be exported from a PKW Class ([serializeKey](pkw/pkw.h)). For easier secure key handling, a passphrase can be
provided in [serializeAndEncryptKey](pkw/pkw.h).

### Deserialization

Keys can be reimported using the respective factories, the abstract interface is defined
by [AbstractPKWFactory](pkw/pkw.h)

### Storing secret keys

It is strongly advised to protect keys when they are stored.

## TODO

* Add library export functionality (CMake)
* SecureByteBuffer: explicitly delete copy constructor?