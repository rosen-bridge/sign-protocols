package storage

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"rosen-bridge/tss-api/logger"
	"rosen-bridge/tss-api/models"
)

type Storage interface {
	makefilePath(peerHome string, protocol string) string
	WriteData(data interface{}, peerHome string, fileFormat string, protocol string) error
	LoadEDDSAKeygen(peerHome string, p2pId string) (models.TssConfigEDDSA, *tss.PartyID, error)
	LoadECDSAKeygen(peerHome string, p2pId string) (models.TssConfigECDSA, *tss.PartyID, error)
}

type storage struct{}

var logging *zap.SugaredLogger

//	Constructor of a storage struct
func NewStorage() Storage {
	logging = logger.NewSugar("storage")
	return &storage{}
}

//	Constructor of a storage struct
func (f *storage) makefilePath(peerHome string, protocol string) string {
	return fmt.Sprintf("%s/%s", peerHome, protocol)
}

// WriteData writing given data to file in given path
func (f *storage) WriteData(data interface{}, peerHome string, fileFormat string, protocol string) error {

	logging.Info("writing data to the file")

	filePath := f.makefilePath(peerHome, protocol)
	err := os.MkdirAll(filePath, os.ModePerm)
	if err != nil {
		return err
	}

	path := filepath.Join(filePath, fileFormat)

	logging.Infof("file path: %s", path)
	fd, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	defer func(fd *os.File) {
		err := fd.Close()
		if err != nil {
			logging.Errorf("unable to close file %s, err:{%v}", path, err)
		}
	}(fd)

	if err != nil {
		return fmt.Errorf("unable to open File %s for writing, err:{%v}", path, err)
	}
	bz, err := json.MarshalIndent(&data, "", "    ")
	if err != nil {
		return fmt.Errorf("unable to marshal data, err:{%v}", err)
	}
	_, err = fd.Write(bz)
	if err != nil {
		return fmt.Errorf("unable to write to File %s", path)
	}
	logging.Infof("data was written successfully in a file: %s", path)
	return nil
}

//	Loads the EDDSA keygen data from the file
func (f *storage) LoadEDDSAKeygen(peerHome string, p2pId string) (models.TssConfigEDDSA, *tss.PartyID, error) {
	// locating file
	var keygenFile string

	filePath := f.makefilePath(peerHome, models.EDDSA)
	files, err := ioutil.ReadDir(filePath)
	if err != nil || len(files) == 0 {
		logging.Warnf("couldn't find eddsa keygen %v", err)
		return models.TssConfigEDDSA{}, nil, errors.New(models.EDDSANoKeygenDataFoundError)
	}

	for _, File := range files {
		if strings.Contains(File.Name(), "keygen") {
			keygenFile = File.Name()
		}
	}
	keyFilePath := filepath.Join(filePath, keygenFile)
	logging.Infof("key file path: %v", keyFilePath)

	// reading file
	bz, err := ioutil.ReadFile(keyFilePath)
	if err != nil {
		return models.TssConfigEDDSA{}, nil, errors.Wrapf(
			err,
			"could not open the file for party in the expected location: %s. run keygen first.", keyFilePath,
		)
	}
	var tssConfig models.TssConfigEDDSA
	if err = json.Unmarshal(bz, &tssConfig); err != nil {
		return models.TssConfigEDDSA{}, nil, errors.Wrapf(
			err,
			"could not unmarshal data for party located at: %s", keyFilePath,
		)
	}

	//creating data from file
	for _, kbxj := range tssConfig.KeygenData.BigXj {
		kbxj.SetCurve(tss.Edwards())
	}
	tssConfig.KeygenData.EDDSAPub.SetCurve(tss.Edwards())
	id := p2pId
	pMoniker := fmt.Sprintf("tssPeer/%s", p2pId)
	partyID := tss.NewPartyID(id, pMoniker, tssConfig.KeygenData.ShareID)

	var parties tss.UnSortedPartyIDs
	parties = append(parties, partyID)
	sortedPIDs := tss.SortPartyIDs(parties)
	return tssConfig, sortedPIDs[0], nil
}

//	Loads the ECDSA keygen data from the file
func (f *storage) LoadECDSAKeygen(peerHome string, p2pId string) (models.TssConfigECDSA, *tss.PartyID, error) {
	// locating file
	var keygenFile string

	filePath := f.makefilePath(peerHome, models.ECDSA)
	files, err := ioutil.ReadDir(filePath)
	if err != nil || len(files) == 0 {
		logging.Warnf("couldn't find ecdsa keygen %v", err)
		return models.TssConfigECDSA{}, nil, errors.New(models.ECDSANoKeygenDataFoundError)
	}

	for _, File := range files {
		if strings.Contains(File.Name(), "keygen") {
			keygenFile = File.Name()
		}
	}
	keyFilePath := filepath.Join(filePath, keygenFile)
	logging.Infof("key file path: %v", keyFilePath)

	// reading file
	bz, err := ioutil.ReadFile(keyFilePath)
	if err != nil {
		return models.TssConfigECDSA{}, nil, errors.Wrapf(
			err,
			"could not open the file for party in the expected location: %s. run keygen first.", keyFilePath,
		)
	}
	var tssConfig models.TssConfigECDSA
	if err = json.Unmarshal(bz, &tssConfig); err != nil {
		return models.TssConfigECDSA{}, nil, errors.Wrapf(
			err,
			"could not unmarshal data for party located at: %s", keyFilePath,
		)
	}

	//creating data from file
	for _, kbxj := range tssConfig.KeygenData.BigXj {
		kbxj.SetCurve(tss.S256())
	}
	tssConfig.KeygenData.ECDSAPub.SetCurve(tss.S256())
	id := p2pId
	pMoniker := fmt.Sprintf("tssPeer/%s", p2pId)
	partyID := tss.NewPartyID(id, pMoniker, tssConfig.KeygenData.ShareID)

	var parties tss.UnSortedPartyIDs
	parties = append(parties, partyID)
	sortedPIDs := tss.SortPartyIDs(parties)
	return tssConfig, sortedPIDs[0], nil
}
