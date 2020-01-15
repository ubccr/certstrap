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

package main

import (
	"os"

	"github.com/square/certstrap/cmd"
	"github.com/square/certstrap/depot"
	"github.com/urfave/cli/v2"
)

// release is overriden by the build script using -X argument that is passed to the Go linker.
var release = "(version not set)"

func main() {
	app := cli.NewApp()
	app.Name = "certstrap"
	app.Version = release
	app.Usage = "A simple certificate manager written in Go, to bootstrap your own certificate authority and public key infrastructure."
	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:  "depot-path",
			Value: depot.DefaultFileDepotDir,
			Usage: "Location to store certificates, keys and other files.",
		},
	}
	app.Authors = []*cli.Author{{Name: "Square Inc., CoreOS", Email: ""}}
	app.Commands = []*cli.Command{
		cmd.NewInitCommand(),
		cmd.NewCertRequestCommand(),
		cmd.NewSignCommand(),
		cmd.NewRevokeCommand(),
	}
	app.Before = func(c *cli.Context) error {
		cmd.InitDepot(c.String("depot-path"))
		return nil
	}

	if err := app.Run(os.Args); err != nil {
		os.Exit(1)
	}
}
