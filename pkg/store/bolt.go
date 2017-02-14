// Copyright 2015 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package store

import (
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"time"

	"fmt"

	"github.com/boltdb/bolt"
	"github.com/google/easypki/pkg/certificate"
)

var (
	keysBucketKey    = []byte("keys")
	certsBucketKey   = []byte("certs")
	revokedBucketKey = []byte("revoked")
)

// Errors.
var (
	ErrDoesNotExist = errors.New("does not exist")
)

// Bolt lets us store a Certificate Authority in a Bolt DB.
//
// Certificate bundles are stored per CA bucket, and each of them has a keys
// bucket and a certs buckets.
type Bolt struct {
	DB *bolt.DB
}

// Add adds the given bundle to the database.
func (b *Bolt) Add(caName, name string, isCa bool, key, cert []byte) error {
	return b.DB.Update(func(tx *bolt.Tx) error {
		kb, cb, err := buckets(tx, caName)
		if err != nil {
			return err
		}
		k := []byte(name)
		if err := kb.Put(k, key); err != nil {
			return fmt.Errorf("failed puting %v key into %v keys bucket: %v", name, caName, err)
		}
		if err := cb.Put(k, cert); err != nil {
			return fmt.Errorf("failed puting %v cert into %v certs bucket: %v", name, caName, err)
		}

		if isCa && name != caName {
			kb, cb, err = buckets(tx, name)
			if err != nil {
				return err
			}
			if err := kb.Put(k, key); err != nil {
				return fmt.Errorf("failed puting %v key into %v keys bucket: %v", name, name, err)
			}
			if err := cb.Put(k, cert); err != nil {
				return fmt.Errorf("failed puting %v cert into %v certs bucket: %v", name, name, err)
			}
		}
		return nil
	})
}

// Fetch fetchs the private key and certificate for a given name signed by caName.
func (b *Bolt) Fetch(caName, name string) ([]byte, []byte, error) {
	var key, cert []byte
	err := b.DB.View(func(tx *bolt.Tx) error {
		rb := tx.Bucket([]byte(caName))
		if rb == nil {
			return fmt.Errorf("%v bucket does not exist", caName)
		}
		kb := rb.Bucket(keysBucketKey)
		if kb == nil {
			return fmt.Errorf("%v keys bucket does not exist", caName)
		}
		cb := rb.Bucket(certsBucketKey)
		if cb == nil {
			return fmt.Errorf("%v certs bucket does not exist", caName)
		}
		k := []byte(name)
		key = kb.Get(k)
		cert = cb.Get(k)
		if key == nil || cert == nil {
			return ErrDoesNotExist
		}
		return nil
	})
	return key, cert, err
}

// Update updates the state of a given certificate in the index.txt.
func (b *Bolt) Update(caName string, sn *big.Int, st certificate.State) error {
	if st != certificate.Revoked {
		return fmt.Errorf("unsupported update for certificate state %v", st)
	}
	return b.DB.Update(func(tx *bolt.Tx) error {
		root, err := tx.CreateBucketIfNotExists([]byte(caName))
		if err != nil {
			return fmt.Errorf("failed getting %v bucket: %v", caName, err)
		}
		revoked, err := root.CreateBucketIfNotExists(revokedBucketKey)
		if err != nil {
			return fmt.Errorf("failed getting %v revoked bucket: %v", root, err)
		}
		t, err := time.Now().GobEncode()
		if err != nil {
			return fmt.Errorf("failed gob encoding current time: %v", err)
		}
		k, err := sn.GobEncode()
		if err != nil {
			return fmt.Errorf("failed gob encoding serial number %v: %v", sn, err)
		}
		if err := revoked.Put(k, t); err != nil {
			return fmt.Errorf("failed adding serial number %v to the %v revoked bucket: %v", sn, caName, err)
		}
		return nil
	})
}

// Revoked returns a list of revoked certificates.
func (b *Bolt) Revoked(caName string) ([]pkix.RevokedCertificate, error) {
	var revokedCerts []pkix.RevokedCertificate
	if err := b.DB.View(func(tx *bolt.Tx) error {
		root := tx.Bucket([]byte(caName))
		if root == nil {
			return fmt.Errorf("%v bucket does not exist", caName)
		}
		revoked := root.Bucket(revokedBucketKey)
		if revoked == nil {
			return nil
		}
		return revoked.ForEach(func(k, v []byte) error {
			sn := big.NewInt(0)
			if err := sn.GobDecode(k); err != nil {
				return fmt.Errorf("failed gob decoding serial number: %v", err)
			}
			t := time.Time{}
			if err := t.GobDecode(v); err != nil {
				return fmt.Errorf("failed gob decoding revocation time: %v", err)
			}
			revokedCerts = append(revokedCerts, pkix.RevokedCertificate{
				SerialNumber:   sn,
				RevocationTime: t,
			})
			return nil
		})
	}); err != nil {
		return nil, err
	}
	return revokedCerts, nil
}

// buckets returns respectively the keys and certs buckets nested below the
// given root bucket.
func buckets(tx *bolt.Tx, root string) (*bolt.Bucket, *bolt.Bucket, error) {
	rb, err := tx.CreateBucketIfNotExists([]byte(root))
	if err != nil {
		return nil, nil, fmt.Errorf("failed getting %v bucket: %v", root, err)
	}
	kb, err := rb.CreateBucketIfNotExists(keysBucketKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed getting %v keys bucket: %v", root, err)
	}
	cb, err := rb.CreateBucketIfNotExists(certsBucketKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed getting %v certs bucket: %v", root, err)
	}
	return kb, cb, nil
}
