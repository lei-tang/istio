// Copyright 2018 Istio Authors
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

// Signs a CSR at Vault

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"istio.io/istio/security/pkg/util"
)

var (
	vaultAddr        = flag.String("vault-addr", "", "The address of Vault, e.g., https://1.2.3.4:8200.")
	vaultLoginRole   = flag.String("vault-login-role", "", "The name of the Vault login role.")
	vaultLoginPath   = flag.String("vault-login-path", "", "The path of Vault login.")
	vaultSignCsrPath = flag.String("vault-sign-csr-path", "", "The path of sign CSR on Vault.")
	saFileName       = flag.String("service-account-file", "", "The path of the k8s service account.")
	csrFileName      = flag.String("csr-file", "", "The path of the file storing the CSR to sign.")
)

type CsrResponse struct {
	// Whether the CSR is approved.
	IsApproved bool
	// The signed target cert.
	SignedCert []byte
	// The cert chain up to the trusted root cert. It includes all the certs between the
	// newly signed cert and the root cert.
	CertChain []byte
}

func SignCSR(csrPem []byte) (*CsrResponse, error) {
	saToken, err := ioutil.ReadFile(*saFileName)
	if err != nil {
		return nil, fmt.Errorf("Failed to read the service account token: %v", err)
	}

	client, err := util.CreateVaultClient(*vaultAddr)
	if err != nil {
		return nil, fmt.Errorf("Failed to create a Vault connection: %v", err)
	}

	token, err := util.LoginVaultK8sAuthMethod(client, *vaultLoginPath, *vaultLoginRole, string(saToken[:]))
	if err != nil {
		return nil, fmt.Errorf("Failed to login Vault: %v", err)
	}
	client.SetToken(token)
	cert, certChain, err := util.SignCsrByVault(client, *vaultSignCsrPath, csrPem[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign CSR: %v", err)
	}

	response := &CsrResponse{
		IsApproved: true,
		SignedCert: cert,
		CertChain:  certChain,
	}
	return response, nil
}

//Example:
// - GCP project: lt-istio-dev1, cluster: vault-demo1
// - go run main.go -vault-addr=http://35.247.45.173:8200 -vault-login-role=istio-cert -vault-login-path=auth/kubernetes/login -vault-sign-csr-path=istio_ca/sign/istio-pki-role -service-account-file=./citadel-sa.jwt -csr-file=./workload-1.csr
// - To get the citadel sa:
// gcloud container clusters get-credentials vault-demo1 --zone us-west1-b --project lt-istio-dev1
//citadel_sa=$(kubectl get secret $(kubectl get serviceaccount vault-citadel-sa \
//-o jsonpath={.secrets[0].name}) -o jsonpath={.data.token} | base64 --decode -)
//echo -n "$citadel_sa" > citadel-sa.jwt

func main() {
	flag.Parse()

	csr, err := ioutil.ReadFile(*csrFileName)
	if err != nil {
		fmt.Printf("Failed to read the CSR to sign: %v.", err)
		return
	}

	resp, err := SignCSR(csr)
	if err != nil {
		fmt.Printf("Failed to sign CSR: %v.", err)
	}

	if resp != nil && resp.IsApproved {
		fmt.Println("CSR is signed successfully.")
		fmt.Printf("CSR signed certificate is:\n %v\n", string(resp.SignedCert[:]))
		//TO-DO (leitang): check that the certificate chain in the response matches that of the signing CA
		fmt.Printf("CSR certificate chain is:\n %v\n", string(resp.CertChain[:]))
	} else {
		fmt.Println("No certificate is generated.")
	}

}
