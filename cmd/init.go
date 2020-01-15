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
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/square/certstrap/depot"
	"github.com/square/certstrap/pkix"
	"github.com/urfave/cli/v2"
)

// NewInitCommand sets up an "init" command to initialize a new CA
func NewInitCommand() *cli.Command {
	return &cli.Command{
		Name:        "init",
		Usage:       "Create Certificate Authority",
		Description: "Create Certificate Authority, including certificate, key and extra information file.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "passphrase",
				Usage: "Passphrase to encrypt private key PEM block",
			},
			&cli.IntFlag{
				Name:  "key-bits",
				Value: 4096,
				Usage: "Size (in bits) of RSA keypair to generate (example: 4096)",
			},
			&cli.IntFlag{
				Name:   "years",
				Hidden: true,
			},
			&cli.StringFlag{
				Name:  "expires",
				Value: "18 months",
				Usage: "How long until the certificate expires (example: 1 year 2 days 3 months 4 hours)",
			},
			&cli.StringFlag{
				Name:  "organization, o",
				Usage: "Sets the Organization (O) field of the certificate",
			},
			&cli.StringFlag{
				Name:  "organizational-unit, ou",
				Usage: "Sets the Organizational Unit (OU) field of the certificate",
			},
			&cli.StringFlag{
				Name:  "country, c",
				Usage: "Sets the Country (C) field of the certificate",
			},
			&cli.StringFlag{
				Name:  "common-name, cn",
				Usage: "Sets the Common Name (CN) field of the certificate",
			},
			&cli.StringFlag{
				Name:  "province, st",
				Usage: "Sets the State/Province (ST) field of the certificate",
			},
			&cli.StringFlag{
				Name:  "locality, l",
				Usage: "Sets the Locality (L) field of the certificate",
			},
			&cli.StringFlag{
				Name:  "key",
				Usage: "Path to private key PEM file (if blank, will generate new key pair)",
			},
			&cli.BoolFlag{
				Name:  "stdout",
				Usage: "Print certificate to stdout in addition to saving file",
			},
		},
		Action: initAction,
	}
}

func initAction(c *cli.Context) error {
	if !c.IsSet("common-name") {
		return fmt.Errorf("Must supply Common Name for CA")
	}

	formattedName := strings.Replace(c.String("common-name"), " ", "_", -1)

	if depot.CheckCertificate(d, formattedName) || depot.CheckPrivateKey(d, formattedName) {
		return fmt.Errorf("CA with specified name \"%s\" already exists!", formattedName)
	}

	var err error
	expires := c.String("expires")
	if years := c.Int("years"); years != 0 {
		expires = fmt.Sprintf("%s %d years", expires, years)
	}

	// Expiry parsing is a naive regex implementation
	// Token based parsing would provide better feedback but
	expiresTime, err := parseExpiry(expires)
	if err != nil {
		return fmt.Errorf("Invalid expiry: %s\n", err)
	}

	var passphrase []byte
	if c.IsSet("passphrase") {
		passphrase = []byte(c.String("passphrase"))
	} else {
		passphrase, err = createPassPhrase()
		if err != nil {
			return err
		}
	}

	var key *pkix.Key
	if c.IsSet("key") {
		keyBytes, err := ioutil.ReadFile(c.String("key"))
		key, err = pkix.NewKeyFromPrivateKeyPEM(keyBytes)
		if err != nil {
			return fmt.Errorf("Read Key error: %s", err)
		}
		fmt.Printf("Read %s\n", c.String("key"))
	} else {
		key, err = pkix.CreateRSAKey(c.Int("key-bits"))
		if err != nil {
			return fmt.Errorf("Create RSA Key error: %s", err)
		}
		if len(passphrase) > 0 {
			fmt.Printf("Created %s/%s.key (encrypted by passphrase)\n", depotDir, formattedName)
		} else {
			fmt.Printf("Created %s/%s.key\n", depotDir, formattedName)
		}
	}

	crt, err := pkix.CreateCertificateAuthority(key, c.String("organizational-unit"), expiresTime, c.String("organization"), c.String("country"), c.String("province"), c.String("locality"), c.String("common-name"))
	if err != nil {
		return fmt.Errorf("Create certificate error: %s", err)
	}
	fmt.Printf("Created %s/%s.crt\n", depotDir, formattedName)

	if c.Bool("stdout") {
		crtBytes, err := crt.Export()
		if err != nil {
			return fmt.Errorf("Print CA certificate error: %s", err)
		} else {
			fmt.Printf(string(crtBytes))
		}
	}

	if err = depot.PutCertificate(d, formattedName, crt); err != nil {
		return fmt.Errorf("Save certificate error: %s", err)
	}
	if len(passphrase) > 0 {
		if err = depot.PutEncryptedPrivateKey(d, formattedName, key, passphrase); err != nil {
			return fmt.Errorf("Save encrypted private key error: %s", err)
		}
	} else {
		if err = depot.PutPrivateKey(d, formattedName, key); err != nil {
			return fmt.Errorf("Save private key error: %s", err)
		}
	}

	// Create an empty CRL, this is useful for Java apps which mandate a CRL.
	crl, err := pkix.CreateCertificateRevocationList(key, crt, expiresTime)
	if err != nil {
		return fmt.Errorf("Create CRL error: %s", err)
	}
	if err = depot.PutCertificateRevocationList(d, formattedName, crl); err != nil {
		return fmt.Errorf("Save CRL error: %s", err)
	}
	fmt.Printf("Created %s/%s.crl\n", depotDir, formattedName)
	return nil
}
