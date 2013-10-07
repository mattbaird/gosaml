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

func NewAuthorizationRequest(appSettings AppSettings, accountSettings AccountSettings) *AuthorizationRequest {
	myIdUUID, err := uuid.NewV4()
	if err != nil {
		fmt.Println("Error is UUID Generation:", err)
	}
	//yyyy-MM-dd'T'H:mm:ss
	layout := "2006-01-02T15:04:05"
	t := time.Now().Format(layout)

	return &AuthorizationRequest{Settings: appSettings, Id: "_" + myIdUUID.String(), IssueInstant: t}
}

// GetRequest returns a string formatted XML document that represents the SAML document
// TODO: parameterize more parts of the request
func (ar AuthorizationRequest) GetRequest() (string, error) {
	d := AuthnRequest{
		XMLName: xml.Name{
			Local: "samlp:AuthnRequest",
		},
		SAMLP:                       "urn:oasis:names:tc:SAML:2.0:protocol",
		SAML:                        "urn:oasis:names:tc:SAML:2.0:assertion",
		ID:                          ar.Id,
		ProtocolBinding:             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
		Version:                     "2.0",
		AssertionConsumerServiceURL: ar.Settings.AssertionConsumerServiceURL,
		Issuer: Issuer{XMLName: xml.Name{
			Local: "saml:Issuer",
		}, Url: "https://sp.example.com/SAML2"},
		IssueInstant: ar.IssueInstant,
		NameIDPolicy: NameIDPolicy{
			XMLName: xml.Name{
				Local: "samlp:NameIDPolicy",
			},
			AllowCreate: true,
			Format:      "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
		},
		RequestedAuthnContext: RequestedAuthnContext{
			XMLName: xml.Name{
				Local: "samlp:RequestedAuthnContext",
			},
			SAMLP:      "urn:oasis:names:tc:SAML:2.0:protocol",
			Comparison: "exact",
		},
		AuthnContextClassRef: AuthnContextClassRef{
			XMLName: xml.Name{
				Local: "saml:AuthnContextClassRef",
			},
			SAML:      "urn:oasis:names:tc:SAML:2.0:assertion",
			Transport: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
		},
	}
	b, err := xml.MarshalIndent(d, "", "    ")
	if err != nil {
		return "", err
	}
	return string(b), nil
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
func main() {
	appSettings := NewAppSettings("http://www.onelogin.net", "issuer")
	accountSettings := NewAccountSettings("cert", "http://www.onelogin.net")
	authRequest := NewAuthorizationRequest(*appSettings, *accountSettings)
	saml, err := authRequest.GetRequest()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(saml)
}

type AuthorizationRequest struct {
	Id           string
	IssueInstant string
	Settings     AppSettings
	Base64       int
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
	SAMLP      string `xml:"xmlns:samlp,attr"`
	Comparison string `xml:"Comparison,attr"`
}

type AuthnContextClassRef struct {
	XMLName   xml.Name
	SAML      string `xml:"xmlns:saml,attr"`
	Transport string `xml:",innerxml"`
}

type AccountSettings struct {
	Certificate        string
	IDP_SSO_Target_URL string
}

func NewAccountSettings(cert string, targetUrl string) *AccountSettings {
	return &AccountSettings{cert, targetUrl}
}

type AppSettings struct {
	AssertionConsumerServiceURL string
	Issuer                      string
}

func NewAppSettings(assertionServiceUrl string, issuer string) *AppSettings {
	return &AppSettings{assertionServiceUrl, issuer}
}
