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
    "encoding/xml"
)

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
    KeyInfo        KeyInfo        `xml:",innerxml"`
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

type KeyInfo struct {
    XMLName  xml.Name
    X509Data X509Data `xml:",innerxml"`
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
    XMLName      xml.Name
    URI          string       `xml:"URI,attr"`
    Transforms   Transforms   `xml:",innerxml"`
    DigestMethod DigestMethod `xml:",innerxml"`
    DigestValue  DigestValue  `xml:",innerxml"`
}

type X509Data struct {
    XMLName         xml.Name
    X509Certificate X509Certificate `xml:",innerxml"`
}

type Transforms struct {
    XMLName   xml.Name
    Transform Transform
}

type DigestMethod struct {
    XMLName   xml.Name
    Algorithm string   `xml:"Algorithm,attr"`
}

type DigestValue struct {
    XMLName xml.Name
}

type X509Certificate struct {
    XMLName xml.Name
    Cert    string   `xml:",innerxml"`
}

type Transform struct {
    XMLName   xml.Name
    Algorithm string   `xml:"Algorithm,attr"`
}

type AccountSettings struct {
    Certificate        string
    IDP_SSO_Target_URL string
}

type AppSettings struct {
    AssertionConsumerServiceURL string
    Issuer                      string
}
