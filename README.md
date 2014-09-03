gosaml
======

SAML client library written in Go (golang)

SAML is the successful OASIS standard for cloud based single sign on (SSO). SAML allows for companies that maintain a security infrastructure internally to allow using that same set of credentials via a safe, secure mechanism with externally hosted services.

For instance, New Relic allows you to configure a saml provider (https://newrelic.com/docs/subscriptions/saml-service-providers) so you can maintain your own credentials instead of using New Relic's.

Ping Identity has a nice video for SAML here: https://www.pingidentity.com/resource-center/Introduction-to-SAML-Video.cfm

Installation
------------

Use the `go get` command to fetch `gosaml` and its dependencies into your local `$GOPATH`:

    $ go get github.com/mattbaird/gosaml

Usage
-----

### Generating Unsigned AuthnRequests

```go
package main

import (
    "fmt"
    "github.com/mattbaird/gosaml"
)

func main() {
    // Configure the app and account settings
    appSettings := saml.NewAppSettings("http://www.onelogin.net", "issuer")
    accountSettings := saml.NewAccountSettings("cert", "http://www.onelogin.net")

    // Construct an AuthnRequest
    authRequest := saml.NewAuthorizationRequest(*appSettings, *accountSettings)

    // Return a SAML AuthnRequest as a string
    saml, err := authRequest.GetRequest(false)

    if err != nil {
        fmt.Println(err)
        return
    }
    fmt.Println(saml)
}
```

The above code will generate the following AuthnRequest XML:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_fd22bc94-0dee-489f-47d5-b86e3100268c" Version="2.0" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    AssertionConsumerServiceURL="http://www.onelogin.net" IssueInstant="2014-09-02T13:15:28" AssertionConsumerServiceIndex="0"
    AttributeConsumingServiceIndex="0">
    <saml:Issuer>https://sp.example.com/SAML2</saml:Issuer>
    <samlp:NameIDPolicy AllowCreate="true" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"></samlp:NameIDPolicy>
    <samlp:RequestedAuthnContext xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Comparison="exact"></samlp:RequestedAuthnContext>
    <saml:AuthnContextClassRef xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
    </saml:AuthnContextClassRef>
</samlp:AuthnRequest>
```

### Generating Signed AuthnRequests

See the github wiki for basic instructions on [generating an X.509 certificate for signing](https://github.com/mattbaird/gosaml/wiki/Generating-an-X.509-Certificate-for-Signing).

```go
package main

import (
    "fmt"
    "github.com/mattbaird/gosaml"
)

func main() {
    // Configure the app and account settings
    appSettings := saml.NewAppSettings("http://www.onelogin.net", "issuer")
    accountSettings := saml.NewAccountSettings("cert", "http://www.onelogin.net")

    // Construct an AuthnRequest
    authRequest := saml.NewAuthorizationRequest(*appSettings, *accountSettings)

    // Return a SAML AuthnRequest as a string
    saml, err := authRequest.GetSignedRequest(false, "/path/to/publickey.cer", "/path/to/privatekey.pem")

    if err != nil {
        fmt.Println(err)
        return
    }
    fmt.Println(saml)
}
```

The above code will generate the following AuthnRequest XML:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    xmlns:samlsig="http://www.w3.org/2000/09/xmldsig#" ID="_0a4ca0ba-a90c-4780-5f73-d0142f0f0c0f" Version="2.0"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="http://www.onelogin.net"
    IssueInstant="2014-09-03T11:17:07" AssertionConsumerServiceIndex="0" AttributeConsumingServiceIndex="0">
    <saml:Issuer>https://sp.example.com/SAML2</saml:Issuer>
    <samlp:NameIDPolicy AllowCreate="true" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"/>
    <samlp:RequestedAuthnContext xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Comparison="exact"/>
    <saml:AuthnContextClassRef xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
    </saml:AuthnContextClassRef>
    <samlsig:Signature Id="Signature1">
        <samlsig:SignedInfo>
            <samlsig:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <samlsig:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
            <samlsig:Reference URI="#_0a4ca0ba-a90c-4780-5f73-d0142f0f0c0f">
                <samlsig:Transforms>
                    <samlsig:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                </samlsig:Transforms>
                <samlsig:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                <samlsig:DigestValue>8nJJwstdugjt6LJ+pbICc2iBwCc=</samlsig:DigestValue>
            </samlsig:Reference>
        </samlsig:SignedInfo>
        <samlsig:SignatureValue>J35w3/wk5pmrKn6qdfo4L0r0c...t2MGKH8w==</samlsig:SignatureValue>
        <samlsig:KeyInfo>
            <samlsig:X509Data>
                <samlsig:X509Certificate>MIICKzCCAdWgAwIBA...JHpg+GVGdcCty+4xA==</samlsig:X509Certificate>
            </samlsig:X509Data>
        </samlsig:KeyInfo>
    </samlsig:Signature>
</samlp:AuthnRequest>
```
