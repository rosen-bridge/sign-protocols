package main

import (
	"flag"
	"fmt"
	"rosen-bridge/tss-api/models"
	"strings"

	"github.com/labstack/echo/v4"
	"rosen-bridge/tss-api/api"
	"rosen-bridge/tss-api/app"
	"rosen-bridge/tss-api/logger"
	"rosen-bridge/tss-api/network"
	"rosen-bridge/tss-api/storage"
	"rosen-bridge/tss-api/utils"
)

func main() {

	// parsing cli flags
	projectUrl := flag.String("host", "http://localhost:4000", "project url (e.g. http://localhost:4000)")
	guardUrl := flag.String("guardUrl", "http://localhost:8080", "guard url (e.g. http://localhost:8080)")
	publishPath := flag.String(
		"publishPath", "/p2p/send", "publish path of p2p (e.g. /p2p/send)",
	)
	subscriptionPath := flag.String(
		"subscriptionPath", "/p2p/channel/subscribe", "subscriptionPath for p2p (e.g. /p2p/channel/subscribe)",
	)
	getPeerIDPath := flag.String(
		"getP2PIDPath", "/p2p/getPeerID", "getP2PIDPath for p2p (e.g. /p2p/getPeerID)",
	)
	configFile := flag.String(
		"configFile", "./conf/conf.env", "config file",
	)
	trustKey := flag.String("trustKey", "", "fd010545-1f9e-41d8-8515-1094c0498073")
	flag.Parse()

	// initiating and reading configs
	config, err := utils.InitConfig(*configFile)
	if err != nil {
		panic(err)
	}

	absLogAddress, err := utils.SetupDir(config.LogAddress)
	if err != nil {
		panic(err)
	}

	logFile := fmt.Sprintf("%s/%s", absLogAddress, "tss.log")
	err = logger.Init(logFile, config, false)
	if err != nil {
		panic(err)
	}

	logging := logger.NewSugar("main")

	defer func() {
		err = logger.Sync()
		if err != nil {
			logging.Error(err)
		}
	}()

	logging.Debugf("config: %+v", config)

	if *trustKey == "" {
		logging.Warnf("the trustKey flag is not set or is empty")
	}

	// creating new instance of echo framework
	e := echo.New()

	// creating connection and storage and app instance
	conn := network.InitConnection(*publishPath, *subscriptionPath, *guardUrl, *getPeerIDPath)
	localStorage := storage.NewStorage()

	tss := app.NewRosenTss(conn, localStorage, config, *trustKey)

	// setting up peer home based on configs
	err = tss.SetPeerHome(config.HomeAddress)
	if err != nil {
		logging.Fatal(err)
	}

	// subscribe to p2p
	err = tss.GetConnection().Subscribe(*projectUrl)
	if err != nil {
		logging.Fatal(err)
	}

	// running echo framework
	tssController := api.NewTssController(tss)
	e.Validator = tssController

	// get p2pId
	err = tss.SetP2pId()
	if err != nil {
		logging.Fatal(err)
	}

	// setting up meta data if exist for eddsa
	eddsaKeygenData, err := tss.GetStorage().LoadEDDSAKeygen(tss.GetPeerHome(), tss.GetP2pId())
	if err != nil {
		logging.Warn(err)
	}

	err = tss.SetMetaData(eddsaKeygenData.TssConfig.MetaData, models.EDDSA)
	if err != nil {
		logging.Warn(models.EDDSANoMetaDataFoundError)
	}

	// setting up meta data if exist for ecdsa
	ecdsaKeygenData, err := tss.GetStorage().LoadECDSAKeygen(tss.GetPeerHome(), tss.GetP2pId())
	if err != nil {
		logging.Warn(err)
	}

	err = tss.SetMetaData(ecdsaKeygenData.TssConfig.MetaData, models.ECDSA)
	if err != nil {
		logging.Warn(models.ECDSANoMetaDataFoundError)
	}

	api.InitRouting(e, tssController)
	hostPath := strings.ReplaceAll(*projectUrl, "https://", "")
	hostPath = strings.ReplaceAll(hostPath, "http://", "")
	logging.Fatal(e.Start(hostPath))
}
