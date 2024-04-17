package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/lestrrat-go/jwx/v2/jws"

	"github.com/sumup/aaguid-go"
)

type Manifest struct {
	LegalHeader string         `json:"legalHeader"`
	No          int            `json:"no"`
	NextUpdate  time.Time      `json:"nextUpdate"`
	Entries     []aaguid.Entry `json:"entries"`
}

func main() {
	resp, err := http.Get("https://mds.fidoalliance.org/")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	raw, err := jws.ParseReader(resp.Body)
	if err != nil {
		panic(err)
	}

	if err := os.WriteFile("../raw.json", raw.Payload(), 0644); err != nil {
		panic(fmt.Errorf("dump raw file: %w", err))
	}

	var manifest Manifest
	if err := json.Unmarshal(raw.Payload(), &manifest); err != nil {
		panic(err)
	}

	fmt.Println(manifest)
}
