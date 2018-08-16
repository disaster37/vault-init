package vaultService

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/disaster37/vault-init/backend"
	"github.com/disaster37/vault-init/vault/model"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
)

type Vault struct {
	url        string
	httpClient http.Client
}

func NewVault(url string) *Vault {

	return &Vault{
		url: url,
		httpClient: http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
	}
}

func (v *Vault) Health() (int, error) {

	response, err := v.httpClient.Head(v.url + "/v1/sys/health")

	if response != nil && response.Body != nil {
		response.Body.Close()
	}

	if err != nil {
		return 0, err
	}

	return response.StatusCode, nil

}

func (v *Vault) Initialize(backend backend.Backend) error {

	initRequest := vaultModel.InitRequest{
		SecretShares:    5,
		SecretThreshold: 3,
	}

	initRequestData, err := json.Marshal(&initRequest)
	if err != nil {
		return err
	}

	r := bytes.NewReader(initRequestData)
	request, err := http.NewRequest("PUT", v.url+"/v1/sys/init", r)
	if err != nil {
		return err
	}

	response, err := v.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	initRequestResponseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}

	if response.StatusCode != 200 {
		return errors.New(fmt.Sprintf("init: non 200 status code: %d", response.StatusCode))
	}

	var initResponse vaultModel.InitResponse
	if err := json.Unmarshal(initRequestResponseBody, &initResponse); err != nil {
		return err
	}

	// Write the rootToken and unseal keys
	err = backend.Write(&initResponse)
	return err

}

func (v *Vault) Unseal(backend backend.Backend) error {

	initResponse, err := backend.Read()
	if err != nil {
		return nil
	}

	for _, key := range initResponse.KeysBase64 {

		isUnsealed, err := v.unsealOne(key)
		if err != nil {
			return err
		}

		if isUnsealed == true {
			return nil
		}

	}

	return errors.New("Unseal failed ! Maybee have you use wrong unseal keys")

}

func (v *Vault) unsealOne(key string) (bool, error) {

	unsealRequest := vaultModel.UnsealRequest{
		Key: key,
	}

	unsealRequestData, err := json.Marshal(&unsealRequest)
	if err != nil {
		return false, err
	}

	r := bytes.NewReader(unsealRequestData)
	request, err := http.NewRequest(http.MethodPut, v.url+"/v1/sys/unseal", r)
	if err != nil {
		return false, err
	}

	response, err := v.httpClient.Do(request)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		return false, errors.New(fmt.Sprintf("unseal: non-200 status code: %d", response.StatusCode))
	}

	unsealRequestResponseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return false, err
	}

	var unsealResponse vaultModel.UnsealResponse
	if err := json.Unmarshal(unsealRequestResponseBody, &unsealResponse); err != nil {
		return false, err
	}

	if !unsealResponse.Sealed {
		return true, nil
	}

	return false, nil

}
