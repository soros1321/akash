package node

import (
	"encoding/json"
	"io/ioutil"
	"os"

	"github.com/ovrclk/akash/types"
	"github.com/tendermint/tendermint/p2p"
	"github.com/tendermint/tendermint/privval"
	tmtypes "github.com/tendermint/tendermint/types"
)

// Tendermint genesis doc from file
func TMGenesisFromFile(path string) (*tmtypes.GenesisDoc, error) {
	obj := new(tmtypes.GenesisDoc)

	buf, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if err := cdc.UnmarshalJSON(buf, obj); err != nil {
		return nil, err
	}

	return obj, nil
}

// Akash genesis doc from file
func GenesisFromTMGenesis(genesis *tmtypes.GenesisDoc) (*types.Genesis, error) {
	obj := new(types.Genesis)
	if err := json.Unmarshal(genesis.AppOptions, obj); err != nil {
		return nil, err
	}
	return obj, nil
}

func TMGenesisToJSON(obj *tmtypes.GenesisDoc) ([]byte, error) {
	return cdc.MarshalJSON(obj)
}

func PVFromFile(path string) (*privval.FilePV, error) {
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return PVFromJSON(buf)
}

func PVFromJSON(buf []byte) (*privval.FilePV, error) {
	obj := new(privval.FilePV)
	return obj, cdc.UnmarshalJSON(buf, obj)
}

func PVToJSON(obj tmtypes.PrivValidator) ([]byte, error) {
	return cdc.MarshalJSON(obj)
}

func PVToFile(path string, perm os.FileMode, obj tmtypes.PrivValidator) error {
	return writeConfigIfNotExist(path, perm, obj)
}

func NodeKeyToJSON(obj *p2p.NodeKey) ([]byte, error) {
	return cdc.MarshalJSON(obj)
}

func NodeKeyToFile(path string, perm os.FileMode, obj *p2p.NodeKey) error {
	return writeConfigIfNotExist(path, perm, obj)
}

func writeConfigIfNotExist(path string, perm os.FileMode, obj interface{}) error {
	data, err := cdc.MarshalJSON(obj)
	if err != nil {
		return err
	}
	_, err = os.Stat(path)
	if !os.IsNotExist(err) {
		return nil
	}
	err = ioutil.WriteFile(path, data, perm)
	if err != nil {
		return err
	}
	return nil
}
