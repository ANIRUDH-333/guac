//
// Copyright 2022 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dsse

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"

	// "crypto/rsa"
	// "crypto/sha256"
	// "encoding/base64"
	"fmt"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	// "github.com/guacsec/guac/pkg/logging"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

type dsseParser struct {
	doc        *processor.Document
	identities []common.TrustInformation
}

// NewDSSEParser initializes the dsseParser
func NewDSSEParser() common.DocumentParser {
	return &dsseParser{
		identities: []common.TrustInformation{},
	}
}

// Parse breaks out the document into the graph components
func (d *dsseParser) Parse(ctx context.Context, doc *processor.Document) error {
	d.doc = doc

	if err := d.verifySignature(ctx); err != nil {
		return fmt.Errorf("getIdentity returned error: %v", err)
	}
	return nil
}


func b64Decode(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("unable to base64 decode payload (is payload in the right format?)")
		}
	}

	return b, nil
}

func (d *dsseParser) verifySignature(ctx context.Context) error {
    var envelope dsse.Envelope

    if err := json.Unmarshal(d.doc.Blob, &envelope); err != nil {
        return fmt.Errorf("failed to unmarshal DSSE envelope: %v", err)
    }

    payloadBytes, err := b64Decode(envelope.Payload)
    if err != nil {
        return fmt.Errorf("failed to decode payload: %v", err)
    }

    if len(envelope.Signatures) == 0 {
        return fmt.Errorf("no signatures found in the envelope")
    }

    signatureBytes, err := b64Decode(envelope.Signatures[0].Sig)
    if err != nil {
        return fmt.Errorf("failed to decode signature: %v", err)
    }

	publicKeyPEM := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxNmap9BTL2mTAE5B0CFm
E008Hh5UUWnpsx+sn/nIMWnAZFbagN7XKPca2PvoLxeXROfYljXHapMU0byVRSxo
HITjY7Ymglvi87LSoq5b+xVnUKPYMfRTepBFgBCu1X07RV9PtfLIFcaKLNZFvfHH
85VVmliSPSprrcqsTcvzQ7BTNd3pWHgHtGgKgc6FntUaG4Zxd7qLdjFHxvT9x4GY
dxeg7CQhMsNHSzJZxk2YMCVYD13e9lOundUV+WkEKmKgJ8hEsGO5Kb1RseivdXSt
0nDEPO6nHioTT0enb0/0525QEBxxJfKzVsKx83nNAaUvTQ5izBVGcKJKHgKW6X6C
DwIDAQAB
-----END PUBLIC KEY-----`

    block, _ := pem.Decode([]byte(publicKeyPEM))
    if block == nil {
        return fmt.Errorf("failed to parse PEM block containing the public key")
    }

    pub, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        return fmt.Errorf("failed to parse public key: %v", err)
    }

    publicKey, ok := pub.(*rsa.PublicKey)
    if !ok {
        return fmt.Errorf("not an RSA public key")
    }

    hashedPayload := sha256.Sum256(payloadBytes)

    err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashedPayload[:], signatureBytes)
    if err != nil {
        return fmt.Errorf("signature verification failed: %v", err)
    }

    fmt.Println("Signature verified successfully")
    return nil
}


// func VerifySignature(intotoEnvelope *in_toto.Envelope) {
// 	var key in_toto.Key
// 	err := key.LoadKeyDefaults("./keys/alice_pub.pem")
// 	if err != nil {
// 		logrus.Warn("Error while loading the key", err)
// 	}

// 	LoadKey(&key, "./keys/alice_pub.pem")

// 	err = intotoEnvelope.VerifySignature(key)
// 	if err != nil {
// 		logrus.Warn("Error verifying the signature..")
// 	}
// 	logrus.Println("Verified signature successfully!")
// }

// func (d *dsseParser) verifySignature(ctx context.Context) error {
// 	// My idea
// 	// 1. Decode the payload (base64)
// 	// 2. Decode the sig (base64)
// 	// 3. Hash the payload (same as sig)
// 	// 4. Use the public key to verify


// }

// func (d *dsseParser) getIdentity(ctx context.Context) error {
// 	// TODO (pxp928): enable dsse verification once the identity and key management is finalized
// 	// See issue: https://github.com/guacsec/guac/issues/75 and https://github.com/guacsec/guac/issues/443
// 	//  identities, err := verifier.VerifyIdentity(ctx, d.doc)
// 	// if err != nil {
// 	// 	return fmt.Errorf("failed to verify identity: %w", err)
// 	// }
// 	// for _, i := range identities {
// 	// 	if i.Verified {
// 	// 		pemBytes, err := cryptoutils.MarshalPublicKeyToPEM(i.Key.Val)
// 	// 		if err != nil {
// 	// 			return fmt.Errorf("MarshalPublicKeyToPEM returned error: %w", err)
// 	// 		}
// 	// 		// TODO: change this to new TrustInformation struct by resolving https://github.com/guacsec/guac/issues/75
// 	// 		// d.identities = append(d.identities, common.TrustInformation{
// 	// 		// 	ID: i.ID, Digest: i.Key.Hash, Key: base64.StdEncoding.EncodeToString(pemBytes),
// 	// 		// 	KeyType: string(i.Key.Type), KeyScheme: string(i.Key.Scheme), NodeData: *assembler.NewObjectMetadata(d.doc.SourceInformation)})
// 	// 		_ = pemBytes
// 	// 	} else {
// 	// 		logger := logging.FromContext(ctx)
// 	// 		logger.Errorf("failed to verify DSSE with provided key: %v", i.ID)
// 	// 	}
// 	// } 
// 	logger := logging.FromContext(ctx)
// 	logger.Warn("DSSE verification currently not implemented in this release. Continuing without DSSE verification")
// 	return nil
// }

// TODO: Needs to be handled as part of https://github.com/guacsec/guac/issues/75
// GetIdentities gets the identity node from the document if they exist
func (d *dsseParser) GetIdentities(ctx context.Context) []common.TrustInformation {
	return []common.TrustInformation{}
	//return d.identities
}

func (d *dsseParser) GetIdentifiers(ctx context.Context) (*common.IdentifierStrings, error) {
	return nil, fmt.Errorf("not yet implemented")
}

// TODO: Right now, trust information isn't encapsulated yet as nodes as edges
// see https://github.com/guacsec/guac/issues/75
func (d *dsseParser) GetPredicates(ctx context.Context) *assembler.IngestPredicates {
	return &assembler.IngestPredicates{}
}
