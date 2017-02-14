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

// Package store provides different methods to store a Public Key Infrastructure.
package store

import (
	"crypto/x509/pkix"
	"math/big"

	"github.com/google/easypki/pkg/certificate"
)

// Store reprents a way to store a Certificate Authority.
type Store interface {
	// Add adds a newly signed certificate bundle to the store.
	//
	// Args:
	//  The CA name, if the certificate was signed with an intermediate CA.
	//  The certificate bundle name.
	//  Is the bundle to add an intermediate CA.
	//  The raw private key.
	//  The raw certificate.
	//
	// Returns an error if it failed to store the bundle.
	Add(string, string, bool, []byte, []byte) error

	// Fetch fetches a certificate bundle from the store.
	//
	// Args:
	//   The CA name, if the certificate was signed with an intermediate CA.
	//   The name of the certificate bundle.
	//
	// Returns the raw private key and certificate respectively or an error.
	Fetch(string, string) ([]byte, []byte, error)

	// Update updates the state of a certificate. (Valid, Revoked, Expired)
	//
	// Args:
	//   The CA name, if the certificate was signed with an intermediate CA.
	//   The serial of the certificate to update.
	//   The new state.
	//
	// Returns an error if the update failed.
	Update(string, *big.Int, certificate.State) error

	// Revoked returns a list of revoked certificates for a given CA.
	//
	// Args:
	//   The CA name, if it is for an intermediate CA.
	//
	// Returns a list of revoked certificate or an error.
	Revoked(string) ([]pkix.RevokedCertificate, error)
}
