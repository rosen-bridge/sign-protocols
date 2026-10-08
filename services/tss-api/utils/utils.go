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

// checks that a party list can actually run a tss operation: every party
// must be distinct and there must be more parties than the threshold.
// A duplicated party makes tss-lib panic with "index of two parties are
// equal" while preparing a signature, and a party set of threshold or
// fewer can never complete an operation, so both are rejected here,
// before any party is created.
func ValidatePartyIds(partyIds []*tss.PartyID, threshold int) error {
	seenIds := make(map[string]bool, len(partyIds))
	seenKeys := make([]*big.Int, 0, len(partyIds))
	for _, partyId := range partyIds {
		if partyId == nil || partyId.Key == nil {
			return fmt.Errorf("party id is missing its share key")
		}
		if seenIds[partyId.Id] {
			return fmt.Errorf("duplicate party id in party list: %s", partyId.Id)
		}
		seenIds[partyId.Id] = true
		if IndexOf(seenKeys, partyId.KeyInt()) != -1 {
			return fmt.Errorf(
				"duplicate party share key in party list: %s",
				partyId.Id,
			)
		}
		seenKeys = append(seenKeys, partyId.KeyInt())
	}
	if len(partyIds) <= threshold {
		return fmt.Errorf(
			"not enough parties for the threshold: %d parties, threshold %d",
			len(partyIds),
			threshold,
		)
	}
	return nil
}
