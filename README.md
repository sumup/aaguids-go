# AAGUIDS

Small package mapping AAGUIDs (Authenticator Attestation Global Unique Identifier, an identifier for FIDO2 security keys) to their respective metadata from the [FIDO's Metadata Service (MDS)](https://fidoalliance.org/metadata/).

```go
package main

import (
  "fmt"

  "github.com/sumup/aaguids-go"
)

func main() {
  metadata, _ := aaguid.GetMetadata("fbfc3007-154e-4ecc-8c0b-6e020557d7bd")
  fmt.Println(metadata.Name)
}
```

## Contributing

The data are obtained from [FIDO Metadata Service](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html).

> The FIDO Authenticator Metadata Specification defines so-called "Authenticator Metadata" statements. The metadata statements contains the "Trust Anchor" required to validate the attestation object, and they also describe several other important characteristics of the authenticator. The metadata service described in this document defines a baseline method for relying parties to access the latest metadata statements.

## Glossary

An **AAGUID** (Authenticator Attestation Global Unique Identifier) is an identifier for FIDO2 security keys.

## Resources

- [Determine the passkey provider with AAGUID](https://web.dev/articles/webauthn-aaguid) guide by Google
