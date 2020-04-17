// Copyright 2017 Google Inc.
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
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"testing"

	"reflect"

	"github.com/google/easypki/pkg/certificate"
	bolt "go.etcd.io/bbolt"
)

func TestBolt(t *testing.T) {
	f, err := ioutil.TempFile("", "boltdb")
	if err != nil {
		t.Fatalf("failed creating tempfile for boltdb: %v", err)
	}
	defer os.Remove(f.Name())
	db, err := bolt.Open(f.Name(), 0600, nil)
	if err != nil {
		t.Fatalf("failed opening temp boltdb: %v", err)
	}
	defer db.Close()
	b := &Bolt{DB: db}

	var (
		fakeKeyValue  = []byte("fakeKeyValue")
		fakeCertValue = []byte("fakeCertValue")
	)
	if err := b.Add("rootCA", "rootCA", true, fakeKeyValue, fakeCertValue); err != nil {
		t.Errorf("Add(rootCA, rootCA): got error %v != expected nil", err)
	}

	if err := b.Add("rootCA", "intermediateCA", true, fakeKeyValue, fakeCertValue); err != nil {
		t.Errorf("Add(rootCA, intermediateCA): got error %v != expected nil", err)
	}
	if err := b.Add("intermediateCA", "somecert", false, fakeKeyValue, fakeCertValue); err != nil {
		t.Errorf("Add(intermediateCA, somecert): got error %v != expected nil", err)
	}

	expectedKeys := []struct {
		bucket string
		key    string
	}{
		{"rootCA", "rootCA"},
		{"rootCA", "intermediateCA"},
		{"intermediateCA", "intermediateCA"},
		{"intermediateCA", "somecert"},
	}
	// Using Update instead of View so we can use buckets() as a shortcut to
	// the buckets reference.
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, key := range expectedKeys {
			kb, cb, err := buckets(tx, key.bucket)
			if err != nil {
				t.Errorf("buckets(%v): got error %v != expected nil", key.bucket, err)
				continue
			}
			k := []byte(key.key)
			if kb.Get(k) == nil {
				t.Errorf("(%v keys bucket).Get(%v): not found", key.bucket, key.key)
			}
			if cb.Get(k) == nil {
				t.Errorf("(%v certs bucket).Get(%v): not found", key.bucket, key.key)
			}
		}
		return nil
	}); err != nil {
		t.Errorf("failed checking keys existence: %v", err)
	}

	k, c, err := b.Fetch("intermediateCA", "somecert")
	if err != nil {
		t.Errorf("Fetch(intermediateCA, somecert): got error %v != expected nil", err)
	}
	if !reflect.DeepEqual(k, fakeKeyValue) {
		t.Errorf("Fetch(intermediateCA, somecert): got key value %v != expected %v", k, fakeKeyValue)
	}
	if !reflect.DeepEqual(c, fakeCertValue) {
		t.Errorf("Fetch(intermediateCA, somecert): got cert value %v != expected %v", c, fakeCertValue)
	}

	_, _, err = b.Fetch("dummyCA", "dummyCA")
	if err == nil || err.Error() != "dummyCA bucket does not exist" {
		t.Errorf("Fetch(dummyCA, dummyCA): got error %v != expected dummyCA bucket does not exist", err)
	}

	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucket([]byte("dummyCA"))
		return err
	}); err != nil {
		t.Errorf("failed creating dummyCA bucket: %v", err)
	}

	_, _, err = b.Fetch("dummyCA", "dummyCA")
	if err == nil || err.Error() != "dummyCA keys bucket does not exist" {
		t.Errorf("Fetch(dummyCA, dummyCA): got error %v != expected dummyCA keys bucket does not exist", err)
	}

	if err := db.Update(func(tx *bolt.Tx) error {
		caBucket := tx.Bucket([]byte("dummyCA"))
		if caBucket == nil {
			return fmt.Errorf("missing dummyCA bucket")
		}
		_, err := caBucket.CreateBucket(keysBucketKey)
		return err
	}); err != nil {
		t.Errorf("failed creating dummyCA keys bucket: %v", err)
	}

	_, _, err = b.Fetch("dummyCA", "dummyCA")
	if err == nil || err.Error() != "dummyCA certs bucket does not exist" {
		t.Errorf("Fetch(dummyCA, dummyCA): got error %v != expected dummyCA certs bucket does not exist", err)
	}

	if err := db.Update(func(tx *bolt.Tx) error {
		caBucket := tx.Bucket([]byte("dummyCA"))
		if caBucket == nil {
			return fmt.Errorf("missing dummyCA bucket")
		}
		_, err := caBucket.CreateBucket(certsBucketKey)
		return err
	}); err != nil {
		t.Errorf("failed creating dummyCA certs bucket: %v", err)
	}
	_, _, err = b.Fetch("dummyCA", "dummyCA")
	if err == nil || err != ErrDoesNotExist {
		t.Errorf("Fetch(dummyCA, dummyCA): got error %v != %v", err, ErrDoesNotExist)
	}

	sn := big.NewInt(101)
	if err := b.Update("intermediateCA", sn, certificate.Expired); err == nil {
		t.Errorf("Update(intermediateCA, 101, Expired): got error nil != expected %v %v", "unsupported update for certificate state", certificate.Expired)
	}
	if err := b.Update("intermediateCA", sn, certificate.Revoked); err != nil {
		t.Errorf("Update(intermediateCA, 101, Revoked): got error %v != expected nil", err)
	}
	if err := b.DB.View(func(tx *bolt.Tx) error {
		caBucket := tx.Bucket([]byte("intermediateCA"))
		if caBucket == nil {
			return fmt.Errorf("intermediateCA does not exist")
		}
		revokedBucket := caBucket.Bucket(revokedBucketKey)
		if revokedBucket == nil {
			return fmt.Errorf("intermediateCA revoked bucket does not exist")
		}
		k, err := sn.GobEncode()
		if err != nil {
			return fmt.Errorf("failed gob encoding serial number 101: %v", err)
		}
		if revokedBucket.Get(k) == nil {
			return fmt.Errorf("(intermediateCA revoked bucket).Get(101): does not exist")
		}
		return nil
	}); err != nil {
		t.Errorf("failed checking revoked entry: %v", err)
	}

	revoked, err := b.Revoked("intermediateCA")
	if err != nil {
		t.Fatalf("Revoked(intermediateCA): got error %v != expected nil", err)
	}
	if revoked[0].SerialNumber.Cmp(sn) != 0 {
		t.Errorf("Revoked(intermediateCA): Revoked serial %v != expected serial %v", revoked[0].SerialNumber, sn)
	}

	if _, err = b.Revoked("nonexisting"); err == nil {
		t.Error("Revoked(nonexisting): got error nil != expected nonexisting bucket does not exist")
	}
	revoked, err = b.Revoked("dummyCA")
	if err != nil {
		t.Errorf("Revoked(dummyCA) with no revoked bucket: got error %v != expected nil", err)
	}
	if revoked != nil {
		t.Errorf("Revoked(dummyCA) with no revoked bucket: got list %v != expected nil", revoked)
	}

	if err := db.Update(func(tx *bolt.Tx) error {
		caBucket := tx.Bucket([]byte("dummyCA"))
		if caBucket == nil {
			return fmt.Errorf("missing dummyCA bucket")
		}
		_, err := caBucket.CreateBucket(revokedBucketKey)
		return err
	}); err != nil {
		t.Errorf("failed creating dummyCA revoked bucket: %v", err)
	}
	revoked, err = b.Revoked("dummyCA")
	if err != nil {
		t.Errorf("Revoked(dummyCA) with revoked bucket: got error %v != expected nil", err)
	}
	if revoked != nil {
		t.Errorf("Revoked(dummyCA) with revoked bucket: got list %v != expected nil", revoked)
	}
}
