package utils

import (
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/btcsuite/btcutil/base58"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"math/big"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
	"rosen-bridge/tss-api/models"
)

//	get absolute address of an address
func GetAbsoluteAddress(address string) (string, error) {
	var absAddress string
	switch address[0:1] {
	case ".":
		addr, err := filepath.Abs(address)
		if err != nil {
			return "", err
		}
		absAddress = addr
	case "~":
		userHome, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		addr := filepath.Join(userHome, address[1:])
		absAddress = addr
	case "/":
		absAddress = address
	default:
		return "", fmt.Errorf("wrong address format: %s", address)
	}
	return absAddress, nil
}

// GetPKFromEDDSAPub returns the public key Serialized from an EDDSA public key.
func GetPKFromEDDSAPub(x *big.Int, y *big.Int) []byte {
	return edwards.NewPublicKey(x, y).Serialize()
}

// GetPKFromECDSAPub returns the public key Serialized from an ECDSA public key.
func GetPKFromECDSAPub(x *big.Int, y *big.Int) []byte {
	return elliptic.MarshalCompressed(tss.EC(), x, y)
}

//	reads in config file and ENV variables if set.
func InitConfig(configFile string) (models.Config, error) {
	// Search config in home directory with name "default" (without extension).
	viper.SetConfigFile(configFile)
	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	err := viper.ReadInConfig()
	if err != nil {
		return models.Config{}, fmt.Errorf("error using config file: %s", err.Error())
	}
	conf := models.Config{}
	err = viper.Unmarshal(&conf)
	if err != nil {
		return models.Config{}, fmt.Errorf("error Unmarshalling config file: %s", err.Error())
	}
	return conf, nil
}

//	finds index of element in a slice of bigInt
func IndexOf(collection []*big.Int, el *big.Int) int {
	for i, x := range collection {
		if x.Cmp(el) == 0 {
			return i
		}
	}
	return -1
}

//	setups files and creates them
func SetupDir(address string) (string, error) {
	absAddress, err := GetAbsoluteAddress(address)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(absAddress, os.ModePerm); err != nil {
		return "", err
	}
	return absAddress, nil
}

func HexDecoder(message string) ([]byte, error) {
	return hex.DecodeString(message)
}

func HexEncoder(message []byte) string {
	return hex.EncodeToString(message)
}

func Base58Decoder(text string) []byte {
	return base58.Decode(text)
}
