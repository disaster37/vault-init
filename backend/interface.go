package backend

import (
	"github.com/disaster37/vault-init/vault/model"
)

type Backend interface {
	Init() error
	Write(initResponse *vaultModel.InitResponse) error
	Read() (*vaultModel.InitResponse, error)
	Defer()
}
