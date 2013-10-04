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
	"encoding/xml"
	"fmt"
	"github.com/nu7hatch/gouuid"
	"time"
)

type AuthorizationRequest struct {
	Id           string
	IssueInstant string
	Settings     AppSettings
	Base64       int
}

func NewAuthorizationRequest(appSettings AppSettings, accountSettings AccountSettings) *AuthorizationRequest {
	myIdUUID, err := uuid.NewV4()
	if err != nil {
		fmt.Println("Error is UUID Generation:", err)
	}
	layout := "2006-01-02T15:04:05"
	t, err := time.Parse(layout, time.Now().String())
	return &AuthorizationRequest{Settings: appSettings, Id: "_" + myIdUUID.String(), IssueInstant: t.String()}
}

func (ar AuthorizationRequest) GetRequest() (string, error) {
	d := AuthnRequest{
		XMLName: xml.Name{
			Local: "samlp:AuthnRequest",
		},
		SAMLP: "urn:oasis:names:tc:SAML:2.0:protocol",
		SAML:  "urn:oasis:names:tc:SAML:2.0:assertion",
		ID:    ar.Id,
		Issuer: Issuer{XMLName: xml.Name{
			Local: "saml:Issuer",
		}, Url: "https://sp.example.com/SAML2"},
		IssueInstant: ar.IssueInstant,
		NameIDPolicy: NameIDPolicy{
			XMLName: xml.Name{
				Local: "samlp:NameIDPolicy",
			},
			AllowCreate: false,
			Format:      "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
		},
		RequestedAuthnContext: RequestedAuthnContext{
			XMLName: xml.Name{
				Local: "samlp:RequestedAuthnContext",
			},
			Comparison: "exact",
		},
		AuthnContextClassRef: AuthnContextClassRef{
			XMLName: xml.Name{
				Local: "saml:AuthnContextClassRef",
			},
		},
	}
	b, err := xml.MarshalIndent(d, "", "    ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

type AuthnRequest struct {
	XMLName                        xml.Name
	SAMLP                          string                `xml:"xmlns:samlp,attr"`
	SAML                           string                `xml:"xmlns:saml,attr"`
	ID                             string                `xml:"ID,attr"`
	Version                        string                `xml:"Version,attr"`
	ProtocolBinding                string                `xml:"ProtocolBinding,attr"`
	AssertionConsumerServiceURL    string                `xml:"AssertionConsumerServiceURL,attr"`
	IssueInstant                   string                `xml:"IssueInstant,attr"`
	AssertionConsumerServiceIndex  int                   `xml:"AssertionConsumerServiceIndex,attr"`
	AttributeConsumingServiceIndex int                   `xml:"AttributeConsumingServiceIndex,attr"`
	Issuer                         Issuer                `xml:"Issuer"`
	NameIDPolicy                   NameIDPolicy          `xml:"NameIDPolicy"`
	RequestedAuthnContext          RequestedAuthnContext `xml:"RequestedAuthnContext"`
	AuthnContextClassRef           AuthnContextClassRef  `xml:"AuthnContextClassRef"`
}

type Issuer struct {
	XMLName xml.Name
	Url     string `xml:",innerxml"`
}

type NameIDPolicy struct {
	XMLName     xml.Name
	AllowCreate bool   `xml:"AllowCreate,attr"`
	Format      string `xml:"Format,attr"`
}

type RequestedAuthnContext struct {
	XMLName    xml.Name
	Comparison string `xml:"Comparison,attr"`
}

type AuthnContextClassRef struct {
	XMLName xml.Name
}

func main() {
	d := AuthnRequest{
		XMLName: xml.Name{
			Local: "samlp:AuthnRequest",
		},

		SAMLP: "urn:oasis:names:tc:SAML:2.0:protocol",
		SAML:  "urn:oasis:names:tc:SAML:2.0:assertion",
		Issuer: Issuer{XMLName: xml.Name{
			Local: "saml:Issuer",
		}, Url: "https://sp.example.com/SAML2"},
		IssueInstant: "2004-12-05T09:21:59",
		NameIDPolicy: NameIDPolicy{
			XMLName: xml.Name{
				Local: "samlp:NameIDPolicy",
			},
			AllowCreate: false,
			Format:      "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
		},
		RequestedAuthnContext: RequestedAuthnContext{
			XMLName: xml.Name{
				Local: "samlp:RequestedAuthnContext",
			},
			Comparison: "exact",
		},
		AuthnContextClassRef: AuthnContextClassRef{
			XMLName: xml.Name{
				Local: "saml:AuthnContextClassRef",
			},
		},
	}
	b, err := xml.MarshalIndent(d, "", "    ")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(b))
}

/*
 <samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="aaf23196-1773-2113-474a-fe114412ab72"
    Version="2.0"
    IssueInstant="2004-12-05T09:21:59"
    AssertionConsumerServiceIndex="0"
    AttributeConsumingServiceIndex="0">
    <saml:Issuer>https://sp.example.com/SAML2</saml:Issuer>
    <samlp:NameIDPolicy
      AllowCreate="true"
      Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"/>
  </samlp:AuthnRequest>
*/
type AccountSettings struct {
	Certificate        string
	IDP_SSO_Target_URL string
}

type AppSettings struct {
	AssertionConsumerServiceURL string
	Issuer                      string
}
