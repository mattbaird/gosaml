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

package gosaml

import (
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
	return "", nil
}

type AccountSettings struct {
	Certificate        string
	IDP_SSO_Target_URL string
}

type AppSettings struct {
	AssertionConsumerServiceURL string
	Issuer                      string
}
