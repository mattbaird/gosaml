// Copyright 2012 Matthew Baird
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

package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
)

func LoadCertificate(crtFile string) (*x509.Certificate, error) {
	fi, err := os.Open(crtFile)
	if err != nil {
		return nil, err
	}
	pemBytes := make([]byte, 1024)
	n, err := fi.Read(pemBytes)
	if n >= 1024 {
		return nil, err
	}
	if err != io.EOF && err != nil {
		return nil, err
	}
	block, pemrest := pem.Decode(pemBytes[:n])
	if len(pemrest) > 0 {
		fmt.Println("pem.Decode had trailing", pemrest)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	return certificate, err
}

func LoadCertificateFromBytes(cert []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(cert)
}
