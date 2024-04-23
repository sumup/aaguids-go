package aaguids_test

import (
	"fmt"

	"github.com/sumup/aaguids-go"
)

func ExampleGetMetadata() {
	metadata, err := aaguids.GetMetadata("fbfc3007-154e-4ecc-8c0b-6e020557d7bd")
	if err != nil {
		panic(err)
	}

	fmt.Println(metadata.Name)
	// Output: iCloud Keychain
}
