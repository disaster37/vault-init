// Copyright 2018 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package main

import (
	"encoding/base64"
	"encoding/json"
	"gopkg.in/urfave/cli.v1"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/disaster37/vault-init/backend"
	"github.com/disaster37/vault-init/vault/model"
	"github.com/disaster37/vault-init/vault/service"
)

var (
	vaultUrl      string
	checkInterval int
	backendStore  string
	filePath      string
	cryptKey      string
	httpClient    http.Client
)

func main() {

	// CLI settings
	app := cli.NewApp()
	app.Usage = "Auto init and auto unseal vault"
	app.Version = "develop"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:        "vault-url",
			Usage:       "The Rancher base URL",
			Value:       "https://127.0.0.1:8200",
			Destination: &vaultUrl,
		},
		cli.IntFlag{
			Name:        "check-interval",
			Usage:       "The interval in second to check if vault is online",
			Value:       10,
			Destination: &checkInterval,
		},
	}
	app.Commands = []cli.Command{
		{
			Name:  "file-store",
			Usage: "Store the rootToken and unseal keys in encrypted file",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "file-path",
					Usage: "The full path where to store the crypt file",
				},
				cli.StringFlag{
					Name:  "encrypt-key",
					Usage: "The key to encrypt / decrypt data",
				},
			},
			Action: manageVaultFileStore,
		},
		{
			Name:  "read-file-store",
			Usage: "Read the contend of encrypted file to retrive rootToken and unseal keys",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "file-path",
					Usage: "The full path where to store the crypt file",
				},
				cli.StringFlag{
					Name:  "encrypt-key",
					Usage: "The key to encrypt / decrypt data",
				},
			},
			Action: readFileStore,
		},
		{
			Name:  "write-file-store",
			Usage: "Write file store for already initialized vault",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "file-path",
					Usage: "The full path where to store the crypt file",
				},
				cli.StringFlag{
					Name:  "encrypt-key",
					Usage: "The key to encrypt / decrypt data",
				},
				cli.StringFlag{
					Name:  "root-token",
					Usage: "The root Token",
				},
				cli.StringFlag{
					Name:  "unseal-keys",
					Usage: "The unseal Keys separated by comma",
				},
			},
			Action: writeFileStore,
		},
	}

	app.Run(os.Args)
}

func manageVaultFileStore(c *cli.Context) error {

	if c.String("file-path") == "" {
		return cli.NewExitError("You must set --file-path parameter", 1)
	}

	if c.String("encrypt-key") == "" {
		return cli.NewExitError("You must set --encrypt-key parameter", 1)
	}

	backendService := backend.NewFileBackend(c.String("file-path"), c.String("encrypt-key"))

	err := manageVault(backendService)
	if err != nil {
		return cli.NewExitError(err, 1)
	}

	return nil
}

func manageVault(backendService backend.Backend) error {

	log.Println("Starting the vault-init service...")

	vaultService := vaultService.NewVault(vaultUrl)
	checkIntervalDuration := time.Duration(checkInterval) * time.Second

	defer backendService.Defer()
	err := backendService.Init()
	if err != nil {
		return err
	}

	for {

		httpStatusCode, err := vaultService.Health()

		if err != nil {
			log.Println(err)
			time.Sleep(checkIntervalDuration)
			continue
		}

		switch httpStatusCode {
		case 200:
			log.Println("Vault is initialized and unsealed.")
			break
		case 429:
			log.Println("Vault is unsealed and in standby mode.")
			break
		case 501:
			log.Println("Vault is not initialized. Initializing and unsealing...")
			err := vaultService.Initialize(backendService)
			if err != nil {
				log.Fatal("Error during Vault initialization: ", err)
				return err
			}
			err = vaultService.Unseal(backendService)
			if err != nil {
				log.Fatal("Error during unseal step: ", err)
				return err
			}
			break
		case 503:
			log.Println("Vault is sealed. Unsealing...")
			err := vaultService.Unseal(backendService)
			if err != nil {
				log.Fatal("Error during unseal step: ", err)
				return err
			}
			break
		default:
			log.Printf("Vault is in an unknown state. Status code: %d", httpStatusCode)
		}

		log.Printf("Next check in %s", checkIntervalDuration)
		time.Sleep(checkIntervalDuration)
	}

	log.Printf("Shutting down")
	backendService.Defer()

	return nil
}

func readFileStore(c *cli.Context) error {
	if c.String("file-path") == "" {
		return cli.NewExitError("You must set --file-path parameter", 1)
	}

	if c.String("encrypt-key") == "" {
		return cli.NewExitError("You must set --encrypt-key parameter", 1)
	}

	backendService := backend.NewFileBackend(c.String("file-path"), c.String("encrypt-key"))

	initResponse, err := backendService.Read()
	if err != nil {
		return cli.NewExitError(err, 1)
	}

	initResponseJson, err := json.Marshal(initResponse)
	if err != nil {
		return cli.NewExitError(err, 1)
	}

	log.Printf("Yours infos:\n %s", initResponseJson)

	return nil

}

func writeFileStore(c *cli.Context) error {

	if c.String("file-path") == "" {
		return cli.NewExitError("You must set --file-path parameter", 1)
	}

	if c.String("encrypt-key") == "" {
		return cli.NewExitError("You must set --encrypt-key parameter", 1)
	}

	if c.String("root-token") == "" {
		return cli.NewExitError("You must set --root-token parameter", 1)
	}

	if c.String("unseal-keys") == "" {
		return cli.NewExitError("You must set --unseal-keys parameter", 1)
	}

	backendService := backend.NewFileBackend(c.String("file-path"), c.String("encrypt-key"))

	keys := strings.Split(c.String("unseal-keys"), ",")
	keysBase64 := make([]string, 0, 1)

	for _, key := range keys {
		keysBase64 = append(keysBase64, base64.StdEncoding.EncodeToString([]byte(key)))
	}

	initResponse := &vaultModel.InitResponse{
		Keys:       keys,
		KeysBase64: keysBase64,
		RootToken:  c.String("root-token"),
	}

	err := backendService.Write(initResponse)
	if err != nil {
		return cli.NewExitError(err, 1)
	}

	log.Printf("Encrypted file %s created successfully", c.String("file-path"))

	return nil

}
