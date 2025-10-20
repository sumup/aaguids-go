module github.com/sumup/aaguid-go/cmd

go 1.22.0
toolchain go1.24.1

replace github.com/sumup/aaguid-go => ../

require (
	github.com/lestrrat-go/jwx/v2 v2.0.21
	github.com/sumup/aaguid-go v0.0.0-00010101000000-000000000000
)

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.2.0 // indirect
	github.com/goccy/go-json v0.10.2 // indirect
	github.com/lestrrat-go/blackmagic v1.0.2 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc v1.0.5 // indirect
	github.com/lestrrat-go/iter v1.0.2 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/segmentio/asm v1.2.0 // indirect
	github.com/sumup/aaguids-go v0.0.0-20240612214548-428fcdf43331 // indirect
	golang.org/x/crypto v0.35.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
)
