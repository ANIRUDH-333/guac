package kms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/guacsec/guac/pkg/ingestor/key"
	"github.com/guacsec/guac/pkg/logging"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	sigstoreAws "github.com/sigstore/sigstore/pkg/signature/kms/aws"
)

type kms struct {
	collector map[string]*key.Key
}

const (
	rsaKeyType            key.KeyType   = "rsa"
	ecdsaKeyType          key.KeyType   = "ecdsa"
	ed25519KeyType        key.KeyType   = "ed25519"
	rsassapsssha256Scheme key.KeyScheme = "rsassa-pss-sha256"
	ecdsaSha2nistp256     key.KeyScheme = "ecdsa-sha2-nistp256"
	ed25519Scheme         key.KeyScheme = "ed25519"
)

func NewKmsProvider() *kms {
	return &kms{
		collector: map[string]*key.Key{},
	}
}

func (m *kms) RetrieveKey(ctx context.Context, id string) (*key.Key, error) {
	logger := logging.FromContext(ctx)

	pubKey, err := getKmsPubKey(ctx, id)
	if err != nil {
		logger.Errorf("error while fetching kms public key: %s", err)
		return nil, err
	}

	pubKeyHash, err := dsse.SHA256KeyID(pubKey)
	if err != nil {
		logger.Errorf("error while calculating sha256 digest of the public key: %s", err)
		return nil, err
	}

	keyType, KeyScheme, err := getKeyInfo(pubKey)
	if err != nil {
		logger.Errorf("error while getting public key info: %s", err)
		return nil, err
	}

	return &key.Key{
		Hash:   pubKeyHash,
		Type:   keyType,
		Val:    pubKey,
		Scheme: KeyScheme,
	}, nil
}

func (m *kms) StoreKey(ctx context.Context, id string, pk *key.Key) error {
	logger := logging.FromContext(ctx)
	logger.Warnf("unimplemented for kms key provider")
	return nil
}

func (m *kms) DeleteKey(ctx context.Context, id string) error {
	logger := logging.FromContext(ctx)
	logger.Warnf("unimplemented for kms key provider")
	return nil
}

func (m *kms) Type() key.KeyProviderType {
	return "kms"
}

func getKmsPubKey(ctx context.Context, keyArn string) (crypto.PublicKey, error) {
	logger := logging.FromContext(ctx)

	signerProvider, err := sigstoreAws.LoadSignerVerifier(
		context.Background(),
		keyArn,
		config.WithRegion("us-west-2"),
	)
	if err != nil {
		logger.Errorf("error while loading kms signer verifier: %s", err)
		return nil, err
	}

	return signerProvider.PublicKey()
}

func getKeyInfo(pub crypto.PublicKey) (key.KeyType, key.KeyScheme, error) {
	switch pub.(type) {
	case *rsa.PublicKey:
		return rsaKeyType, rsassapsssha256Scheme, nil
	case *ecdsa.PublicKey:
		return ecdsaKeyType, ecdsaSha2nistp256, nil
	// ed25519 is not using a pointer here due to its implementation. Using a pointer
	// will result in the case statement failing to find the ed25519 key type
	case ed25519.PublicKey:
		return ed25519KeyType, ed25519Scheme, nil
	default:
		return "", "", errors.New("unsupported key type")
	}
}
