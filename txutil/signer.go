package txutil

import (
	gocrypto "github.com/tendermint/go-crypto"
	"github.com/tendermint/tendermint/crypto"
)

// Return a Signer backed by the given KeySigner (such as a crypto.PrivKey)
func NewPrivateKeySigner(key KeySigner) Signer {
	return privateKeySigner{key}
}

type privateKeySigner struct {
	key KeySigner
}

func (s privateKeySigner) Sign(tx SignableTx) error {
	sig, err := s.key.Sign(tx.SignBytes())
	if err != nil {
		return err
	}
	return tx.Sign(s.key.PubKey(), sig)
}

func (s privateKeySigner) SignBytes(bytes []byte) (crypto.Signature, crypto.PubKey, error) {
	sig, err := s.key.Sign(bytes)
	if err != nil {
		return nil, nil, err
	}
	return sig, s.key.PubKey(), nil
}

type StoreSigner interface {
	Sign(name, passphrase string, msg []byte) (gocrypto.Signature, gocrypto.PubKey, error)
}

// Return a Signer backed by a keystore
func NewKeystoreSigner(store StoreSigner, keyName, password string) Signer {
	return keyStoreSigner{store, keyName, password}
}

type keyStoreSigner struct {
	store    StoreSigner
	keyName  string
	password string
}

func (s keyStoreSigner) Sign(tx SignableTx) error {
	sig, pubkey, err := s.SignBytes(tx.SignBytes())
	if err != nil {
		return err
	}
	return tx.Sign(pubkey, sig)
}

func (s keyStoreSigner) SignBytes(bytes []byte) (crypto.Signature, crypto.PubKey, error) {
	gosig, gopub, err := s.store.Sign(s.keyName, s.password, bytes)
	if err != nil {
		return nil, nil, err
	}

	sig, err := crypto.SignatureFromBytes(gosig.Bytes())
	if err != nil {
		return nil, nil, err
	}

	pub, err := crypto.PubKeyFromBytes(gopub.Bytes())
	if err != nil {
		return nil, nil, err
	}
	return sig, pub, nil
}
