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
