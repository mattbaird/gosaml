// Copyright 2014 Matthew Baird, Andrew Mussey
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
	"io/ioutil"
	"os/exec"
	"os"
	"strings"
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
		Issuer: Issuer{
			XMLName: xml.Name{
				Local: "saml:Issuer",
			},
			Url: "https://sp.example.com/SAML2",
		},
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

	xmlAuthnRequest := fmt.Sprintf("<?xml version='1.0' encoding='UTF-8'?>\n%s", b)

	if base64Encode {
		data := []byte(xmlAuthnRequest)
		return base64.StdEncoding.EncodeToString(data), nil
	} else {
		return string(xmlAuthnRequest), nil
	}
}

// GetSignedRequest returns a string formatted XML document that represents the SAML document
// TODO: parameterize more parts of the request
func (ar AuthorizationRequest) GetSignedRequest(base64Encode bool, publicCert string, privateCert string) (string, error) {
	cert, err := LoadCertificate(publicCert)
	if err != nil {
		return "", err
	}

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
		Issuer: Issuer{
			XMLName: xml.Name{
				Local: "saml:Issuer",
			},
			Url: "https://sp.example.com/SAML2",
		},
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
					Transforms: Transforms{
						XMLName: xml.Name{
							Local: "samlsig:Transforms",
						},
						Transform: Transform{
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
						Algorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
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
			KeyInfo: KeyInfo{
				XMLName: xml.Name{
					Local: "samlsig:KeyInfo",
				},
				X509Data: X509Data{
					XMLName: xml.Name{
						Local: "samlsig:X509Data",
					},
					X509Certificate: X509Certificate {
						XMLName: xml.Name{
							Local: "samlsig:X509Certificate",
						},
						Cert: cert,
					},
				},
			},
		},
	}
	b, err := xml.MarshalIndent(d, "", "    ")
	if err != nil {
		return "", err
	}

	samlAuthnRequest := string(b)
	// Write the SAML to a file.

	samlXmlsecInput, err := ioutil.TempFile(os.TempDir(), "tmpgs")
	if err != nil {
		return "", err
	}
	samlXmlsecOutput, err := ioutil.TempFile(os.TempDir(), "tmpgs")
	if err != nil {
		return "", err
	}

	samlXmlsecOutput.Close()

	samlXmlsecInput.WriteString("<?xml version='1.0' encoding='UTF-8'?>\n")
	samlXmlsecInput.WriteString(samlAuthnRequest)
	samlXmlsecInput.Close()

	_, errOut := exec.Command("xmlsec1", "--sign", "--privkey-pem", privateCert,
		"--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:protocol:AuthnRequest",
		"--output", samlXmlsecOutput.Name(), samlXmlsecInput.Name()).Output()
    if errOut != nil {
        return "", errOut
    }

	samlSignedRequest, err := ioutil.ReadFile(samlXmlsecOutput.Name())
	if err != nil {
		return "", err
	}
	samlSignedRequestXml := strings.Trim(string(samlSignedRequest), "\n")

	if base64Encode {
		data := []byte(samlSignedRequestXml)
		return base64.StdEncoding.EncodeToString(data), nil
	} else {
		return string(samlSignedRequestXml), nil
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

	q := u.Query()
	q.Add("SAMLRequest", base64EncodedUTF8SamlRequest)

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func NewAccountSettings(cert string, targetUrl string) *AccountSettings {
	return &AccountSettings{cert, targetUrl}
}

func NewAppSettings(assertionServiceUrl string, issuer string) *AppSettings {
	return &AppSettings{assertionServiceUrl, issuer}
}
