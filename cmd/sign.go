/*-
 * Copyright 2015 Square Inc.
 * Copyright 2014 CoreOS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cmd

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/square/certstrap/depot"
	"github.com/square/certstrap/pkix"
	"github.com/urfave/cli/v2"
)

// NewSignCommand sets up a "sign" command to sign a CSR with a given CA for a new certificate
func NewSignCommand() *cli.Command {
	return &cli.Command{
		Name:        "sign",
		Usage:       "Sign certificate request",
		Description: "Sign certificate request with CA, and generate certificate for the host.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "passphrase",
				Usage: "Passphrase to decrypt private-key PEM block of CA",
			},
			&cli.IntFlag{
				Name:   "years",
				Hidden: true,
			},
			&cli.StringFlag{
				Name:  "expires",
				Value: "2 years",
				Usage: "How long until the certificate expires (example: 1 year 2 days 3 months 4 hours)",
			},
			&cli.StringFlag{
				Name:  "CA",
				Usage: "Name of CA to issue cert with",
			},
			&cli.StringFlag{
				Name:  "csr",
				Usage: "Path to certificate request PEM file (if blank, will use --depot-path and default name)",
			},
			&cli.StringFlag{
				Name:  "cert",
				Usage: "Path to certificate output PEM file (if blank, will use --depot-path and default name)",
			},
			&cli.BoolFlag{
				Name:  "stdout",
				Usage: "Print certificate to stdout in addition to saving file",
			},
			&cli.BoolFlag{
				Name:  "intermediate",
				Usage: "Whether generated certificate should be a intermediate",
			},
			&cli.BoolFlag{
				Name:  "codesigning",
				Usage: "Whether generated certificate should include the codeSigning extended key usage extension",
			},
		},
		Action: newSignAction,
	}
}

func newSignAction(c *cli.Context) error {
	if c.Args().Len() != 1 {
		return fmt.Errorf("One host name must be provided.")
	}

	formattedReqName := strings.Replace(c.Args().First(), " ", "_", -1)
	formattedCAName := strings.Replace(c.String("CA"), " ", "_", -1)

	if depot.CheckCertificate(d, formattedReqName) {
		return fmt.Errorf("Certificate \"%s\" already exists!", formattedReqName)
	}

	expires := c.String("expires")
	if years := c.Int("years"); years != 0 {
		expires = fmt.Sprintf("%s %d years", expires, years)
	}

	// Expiry parsing is a naive regex implementation
	// Token based parsing would provide better feedback but
	expiresTime, err := parseExpiry(expires)
	if err != nil {
		return fmt.Errorf("Invalid expiry: %s", err)
	}

	csr, err := getCertificateSigningRequest(c, d, formattedReqName)
	if err != nil {
		return fmt.Errorf("Get certificate request error: %s", err)
	}
	crt, err := depot.GetCertificate(d, formattedCAName)
	if err != nil {
		return fmt.Errorf("Get CA certificate error: %s", err)
	}
	// Validate that crt is allowed to sign certificates.
	raw_crt, err := crt.GetRawCertificate()
	if err != nil {
		return fmt.Errorf("GetRawCertificate failed on CA certificate: %s", err)
	}
	// We punt on checking BasicConstraintsValid and checking MaxPathLen. The goal
	// is to prevent accidentally creating invalid certificates, not protecting
	// against malicious input.
	if !raw_crt.IsCA {
		return fmt.Errorf("Selected CA certificate is not allowed to sign certificates.")
	}

	key, err := depot.GetPrivateKey(d, formattedCAName)
	if err != nil {
		pass, err := getPassPhrase(c, "CA key")
		if err != nil {
			return fmt.Errorf("Get CA key error: %s", err)
		}
		key, err = depot.GetEncryptedPrivateKey(d, formattedCAName, pass)
		if err != nil {
			return fmt.Errorf("Get CA key error: %s", err)
		}
	}

	var crtOut *pkix.Certificate
	if c.Bool("intermediate") {
		fmt.Fprintln(os.Stderr, "Building intermediate")
		crtOut, err = pkix.CreateIntermediateCertificateAuthority(crt, key, csr, expiresTime)
	} else if c.Bool("codesigning") {
		fmt.Fprintln(os.Stderr, "Including codeSigning extended key usage")
		extKeyUsage := []x509.ExtKeyUsage{
			x509.ExtKeyUsageCodeSigning,
		}
		crtOut, err = pkix.CreateCertificateHostWithExtUsage(crt, key, csr, expiresTime, extKeyUsage)
	} else {
		crtOut, err = pkix.CreateCertificateHost(crt, key, csr, expiresTime)
	}

	if err != nil {
		return fmt.Errorf("Create certificate error: %s", err)
	} else {
		fmt.Printf("Created %s/%s.crt from %s/%s.csr signed by %s/%s.key\n", depotDir, formattedReqName, depotDir, formattedReqName, depotDir, formattedCAName)
	}

	if c.Bool("stdout") {
		crtBytes, err := crtOut.Export()
		if err != nil {
			return fmt.Errorf("Print certificate error: %s", err)
		} else {
			fmt.Printf(string(crtBytes))
		}
	}

	if err = putCertificate(c, d, formattedReqName, crtOut); err != nil {
		return fmt.Errorf("Save certificate error: %s", err)
	}

	return nil
}
