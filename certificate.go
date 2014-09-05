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
	"io/ioutil"
	"strings"
	"regexp"
)

func LoadCertificate(crtFile string) (string, error) {
	crtByte, err := ioutil.ReadFile(crtFile)
	if err != nil {
		return "", err
	}
	crtString := string(crtByte)

	re := regexp.MustCompile("---(.*)CERTIFICATE(.*)---")
	crtString = re.ReplaceAllString(crtString, "")
	crtString = strings.Trim(crtString, " \n")
	crtString = strings.Replace(crtString, "\n", "", -1)

	return crtString, err
}
