package backend

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/disaster37/vault-init/vault/model"
	"github.com/pkg/errors"
	"io"
	"io/ioutil"
	"os"
)

type File struct {
	path     string
	cryptKey []byte
}

func NewFileBackend(path string, cryptKey string) *File {

	hash := md5.Sum([]byte(cryptKey))
	return &File{
		path:     path,
		cryptKey: hash[:],
	}
}

func (f *File) Init() error {

	if f.path == "" {
		return errors.New("You must set path")
	}

	if len(f.cryptKey) == 0 {
		return errors.New("You must set the cryptKey")
	}

	var _, err = os.Stat(f.path)
	if err != nil {
		if os.IsNotExist(err) {
			var file, err = os.Create(f.path)
			if err != nil {
				return err
			}
			defer file.Close()
		} else {
			return err
		}
	}

	return nil
}

func (f *File) Write(initResponse *vaultModel.InitResponse) error {

	// We crypt en store the Json struct
	jsonInitResponse, err := json.Marshal(initResponse)
	if err != nil {
		return err
	}
	encryptedJsonInitResponse := f.encrypt([]byte(jsonInitResponse))

	err = ioutil.WriteFile(f.path, encryptedJsonInitResponse, 0644)
	if err != nil {
		return err
	}

	return nil

}

func (f *File) Read() (*vaultModel.InitResponse, error) {

	encryptedJsonInitResponse, err := ioutil.ReadFile(f.path)
	if err != nil {
		return nil, err
	}

	if len(encryptedJsonInitResponse) == 0 {
		return nil, errors.New(fmt.Sprintf("The file %s is empty", f.path))
	}

	jsonInitResponse := &vaultModel.InitResponse{}

	err = json.Unmarshal(f.decrypt([]byte(encryptedJsonInitResponse)), jsonInitResponse)
	if err != nil {
		return nil, err
	}

	return jsonInitResponse, nil

}

func (f *File) encrypt(data []byte) []byte {

	block, err := aes.NewCipher(f.cryptKey)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

func (f *File) decrypt(data []byte) []byte {

	if len(data) == 0 {
		return data
	}

	block, err := aes.NewCipher(f.cryptKey)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

func (f *File) Defer() {

}
