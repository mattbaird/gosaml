// Copyright 2014 Matthew Baird
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

package saml

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"github.com/nu7hatch/gouuid"
	"net/url"
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

	return &AuthorizationRequest{AccountSettings: accountSettings, AppSettings: appSettings, Id: "_" + myIdUUID.String(), IssueInstant: t}
}

// GetRequest returns a string formatted XML document that represents the SAML document
// TODO: parameterize more parts of the request
func (ar AuthorizationRequest) GetRequest(base64Encode bool) (string, error) {
	d := AuthnRequest{
		XMLName: xml.Name{
			Local: "samlp:AuthnRequest",
		},
		SAMLP:                       "urn:oasis:names:tc:SAML:2.0:protocol",
		SAML:                        "urn:oasis:names:tc:SAML:2.0:assertion",
		ID:                          ar.Id,
		ProtocolBinding:             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
		Version:                     "2.0",
		AssertionConsumerServiceURL: ar.AppSettings.AssertionConsumerServiceURL,
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
	if base64Encode {
		data := []byte(b)
		return base64.StdEncoding.EncodeToString(data), nil
	} else {
		return string(b), nil
	}
}

// GetSignedRequest returns a string formatted XML document that represents the SAML document
// TODO: parameterize more parts of the request
func (ar AuthorizationRequest) GetSignedRequest(base64Encode bool) (string, error) {
	d := AuthnSignedRequest{
		XMLName: xml.Name{
			Local: "samlp:AuthnRequest",
		},
		SAMLP:                       "urn:oasis:names:tc:SAML:2.0:protocol",
		SAML:                        "urn:oasis:names:tc:SAML:2.0:assertion",
		SAMLSIG:                     "http://www.w3.org/2000/09/xmldsig#",
		ID:                          ar.Id,
		ProtocolBinding:             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
		Version:                     "2.0",
		AssertionConsumerServiceURL: ar.AppSettings.AssertionConsumerServiceURL,
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
		Signature: Signature{
			XMLName: xml.Name{
				Local: "samlsig:Signature",
			},
			Id: "Signature1",
			SignedInfo: SignedInfo{
				XMLName: xml.Name{
					Local: "samlsig:SignedInfo",
				},
				CanonicalizationMethod: CanonicalizationMethod{
					XMLName: xml.Name{
						Local: "samlsig:CanonicalizationMethod",
					},
					Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
				},
				SignatureMethod: SignatureMethod{
					XMLName: xml.Name{
						Local: "samlsig:SignatureMethod",
					},
					Algorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
				},
				SamlsigReference: SamlsigReference{
					XMLName: xml.Name{
						Local: "samlsig:Reference",
					},
					URI: "#" + ar.Id,
					SamlsigTransforms: SamlsigTransforms{
						XMLName: xml.Name{
							Local: "samlsig:Transforms",
						},
						Transform: SamlsigTransform{
							XMLName: xml.Name{
								Local: "samlsig:Transform",
							},
							Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
						},
					},
					DigestMethod: DigestMethod{
						XMLName: xml.Name{
							Local: "samlsig:DigestMethod",
						},
					},
					DigestValue: DigestValue{
						XMLName: xml.Name{
							Local: "samlsig:DigestValue",
						},
					},
				},
			},
			SignatureValue: SignatureValue{
				XMLName: xml.Name{
					Local: "samlsig:SignatureValue",
				},
			},
			SamlsigKeyInfo: SamlsigKeyInfo{
				XMLName: xml.Name{
					Local: "samlsig:KeyInfo",
				},
				X509Data: SamlsigX509Data{
					XMLName: xml.Name{
						Local: "samlsig:X509Data",
					},
					X509Certificate: SamlsigX509Certificate {
						XMLName: xml.Name{
							Local: "samlsig:X509Certificate",
						},
						Cert: "Cert Placeholder",
					},
				},
			},
		},
	}
	b, err := xml.MarshalIndent(d, "", "    ")
	if err != nil {
		return "", err
	}
	if base64Encode {
		data := []byte(b)
		return base64.StdEncoding.EncodeToString(data), nil
	} else {
		return string(b), nil
	}
}

// String reqString = accSettings.getIdp_sso_target_url()+"?SAMLRequest=" +
// AuthRequest.getRidOfCRLF(URLEncoder.encode(authReq.getRequest(AuthRequest.base64),"UTF-8"));
func (ar AuthorizationRequest) GetRequestUrl() (string, error) {
	u, err := url.Parse(ar.AccountSettings.IDP_SSO_Target_URL)
	if err != nil {
		return "", err
	}
	base64EncodedUTF8SamlRequest, err := ar.GetRequest(true)
	if err != nil {
		return "", err
	}
	u.Query().Add("SAMLRequest", base64EncodedUTF8SamlRequest)
	return u.String(), nil
}

type AuthorizationRequest struct {
	Id              string
	IssueInstant    string
	AppSettings     AppSettings
	AccountSettings AccountSettings
	Base64          int
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

type AuthnSignedRequest struct {
	XMLName                        xml.Name
	SAMLP                          string                `xml:"xmlns:samlp,attr"`
	SAML                           string                `xml:"xmlns:saml,attr"`
	SAMLSIG                        string                `xml:"xmlns:samlsig,attr"`
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
	Signature                      Signature             `xml:"Signature"`
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

type Signature struct {
	XMLName        xml.Name
	Id             string         `xml:"Id,attr"`
	SignedInfo     SignedInfo     `xml:",innerxml"`
	SignatureValue SignatureValue `xml:",innerxml"`
	SamlsigKeyInfo SamlsigKeyInfo `xml:",innerxml"`
}

type SignedInfo struct {
	XMLName                xml.Name
	CanonicalizationMethod CanonicalizationMethod `xml:",innerxml"`
	SignatureMethod        SignatureMethod        `xml:",innerxml"`
	SamlsigReference       SamlsigReference       `xml:",innerxml"`
}

type SignatureValue struct {
	XMLName xml.Name
}

type SamlsigKeyInfo struct {
	XMLName  xml.Name
	X509Data SamlsigX509Data `xml:",innerxml"`
}

type CanonicalizationMethod struct {
	XMLName   xml.Name
	Algorithm string   `xml:"Algorithm,attr"`
}

type SignatureMethod struct {
	XMLName   xml.Name
	Algorithm string   `xml:"Algorithm,attr"`
}

type SamlsigReference struct {
	XMLName           xml.Name
	URI               string            `xml:"URI,attr"`
	SamlsigTransforms SamlsigTransforms `xml:",innerxml"`
	DigestMethod      DigestMethod      `xml:",innerxml"`
	DigestValue       DigestValue       `xml:",innerxml"`
}

type SamlsigX509Data struct {
	XMLName         xml.Name
	X509Certificate SamlsigX509Certificate `xml:",innerxml"`
}

type SamlsigTransforms struct {
	XMLName   xml.Name
	Transform SamlsigTransform
}

type DigestMethod struct {
	XMLName   xml.Name
	Algorithm string   `xml:"Algorithm,attr"`
}

type DigestValue struct {
	XMLName xml.Name
}

type SamlsigX509Certificate struct {
	XMLName xml.Name
	Cert    string   `xml:",innerxml"`
}

type SamlsigTransform struct {
	XMLName   xml.Name
	Algorithm string   `xml:"Algorithm,attr"`
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
