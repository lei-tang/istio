//  Copyright 2019 Istio Authors
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package helm

import (
	"fmt"
	"istio.io/istio/pkg/test/scopes"
	"istio.io/istio/pkg/test/shell"
	"unicode"
)

// Init calls "helm init"
func Init(homeDir string, clientOnly bool) error {
	clientSuffix := ""
	if clientOnly {
		clientSuffix = " --client-only"
	}

	out, err := shell.Execute("helm --home %s init %s", homeDir, clientSuffix)
	if err != nil {
		scopes.Framework.Errorf("helm init: %v, out:%q", err, out)
	} else {
		scopes.CI.Infof("helm init:\n%s\n", out)
	}

	return err
}

func Template(homeDir, template, name, namespace string, valuesFile string, values map[string]string) (string, error) {
	// Apply the overrides for the values file.
	valuesString := ""
	for k, v := range values {
		valuesString += fmt.Sprintf(" --set %s=%s", k, v)
		//if containSpaces(v) {
		//	// Quote the string value so that a string "part1 part2" is not
		//	// interpreted as " --set key=part1 part2".
		//	valuesString += fmt.Sprintf(" --set %s=\"%s\"", k, v)
		//} else {
		//	valuesString += fmt.Sprintf(" --set %s=%s", k, v)
		//}
	}

	valuesFileString := ""
	if valuesFile != "" {
		valuesFileString = fmt.Sprintf("--values %s", valuesFile)
	}

	out, err := shell.Execute("helm --home %s template %s --name %s --namespace %s %s %s",
		homeDir, template, name, namespace, valuesFileString, valuesString)
	if err != nil {
		scopes.Framework.Errorf("helm template: %v, out:%q", err, out)
	}

	return out, err
}

func containSpaces(str string) bool {
	if len(str) == 0 {
		return false
	}
	for _, c := range str {
		// Check each character to see if it is a whitespace.
		if unicode.IsSpace(c) {
			return true
		}
	}
	return false
}
