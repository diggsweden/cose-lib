# CBOR Object Encryption and Signing (COSE) Implementation in Java

[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD%203--Clause-blue?style=for-the-badge)](LICENSE)
[![REUSE](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.reuse.software%2Fstatus%2Fgithub.com%2Fdiggsweden%2Fcose-lib&query=status&style=for-the-badge&label=REUSE)](https://api.reuse.software/info/github.com/diggsweden/cose-lib)

[![Tag](https://img.shields.io/github/v/tag/diggsweden/cose?style=for-the-badge&color=green)](https://github.com/diggsweden/cose-lib/tags)

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/diggsweden/cose-lib/badge?style=for-the-badge)](https://scorecard.dev/viewer/?uri=github.com/diggsweden/cose-lib)

This project is a Java implementation of the IETF CBOR Encoded Message Syntax (COSE).  
COSE is specified in [RFC 8152](https://tools.ietf.org/html/rfc8152).

The library is built using **Bouncy Castle** for cryptographic operations and **PeterO CBOR** for CBOR parsing and serialization: [https://github.com/peteroupc/CBOR-Java](https://github.com/peteroupc/CBOR-Java).

## Credits

This implementation is entirely based on the IETF reference implementation, originally developed by the late **Jim Schaad**, a valued friend and contributor to the IETF. Jim's selfless and generous contributions to the community have left a lasting impact.

The original library is available at [COSE-JAVA on GitHub](https://github.com/cose-wg/COSE-JAVA),
but has unfortunately not been updated for a long time.

### Continuation of the Project

This library has been updated and maintained to stay compatible with recent dependency updates,
ensuring its usability in contemporary projects.
We originally created this to meet our own needs for a Java based COSE implementation that was also using PeterO CBOR.
We publish this here to allow others to benefit and to contribute to the continuation and usability of this code base.

If you feel any aspect of the credit to Jim or other contributors should be updated or modified, please reach out.

## Changelog

Future modifications will be documented in the [CHANGELOG](CHANGELOG.md).
The following changes were made in comparison to the original library before the Changelog introduction:

- **Renaming Classes:**
  - The `OneKey` class has been renamed to `COSEKey`.
  - Message classes now use `COSEObject` as a naming base (e.g., `Sign1Message` is renamed to `Sign1COSEObject`).

- **Extended Header Keys:**
  - Support for X.509 certificate header parameters, such as `x5chain`, has been added to `HeaderKeys`.

- **Interoperability Enhancements:**
  - Payloads can now be provided directly under the CBOR data tag `24` to ensure compatibility with implementations that may not fully adhere to the standard (honoring Postel’s Law).

## Installation

To include it in a Maven project, add the following dependency to the `dependencies` section of your `pom.xml` file:

```xml
<dependency>
    <groupId>se.digg.cose-lib</groupId>
    <artifactId>cose</artifactId>
    <version>...X.Y.Z...</version>
</dependency>
```
Note: The plan is to publish this code on maven central in the near future once we have done some final reviews,
and checked with the IETF community that doing so would be appreciated and considered respectful to the original authors.

## Development

See the [Development Guide](docs/DEVELOPMENT.md).
