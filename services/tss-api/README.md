# tss-api project

This project is used for keygen, sign and regroup operations on eddsa and ecdsa protocols in threshold signature.
It is based on Binance's TSS-lib. For massage passing you should run ts-guard-service project and set it's port as guardUrl argument.

### build command 
```bash
go build -trimpath -o bin/rosenTss
```

### config

set peer home address, log configs and operation timeout in second.

### run command
```bash
./roesnTss [options]
  -configFile string
        config file (default "./conf/conf.env")
  --guardUrl string
        guard url (e.g. http://localhost:8080) (default "http://localhost:8080")
  -host string
        project url (e.g. http://localhost:4000) (default "http://localhost:4000")
  -publishPath string
        publish path of p2p (e.g. /p2p/send) (default "/p2p/send")
  -subscriptionPath string
        subscriptionPath for p2p (e.g. /p2p/channel/subscribe) (default "/p2p/channel/subscribe")
  -getP2PIDPath string
        getP2PIDPath for p2p (e.g. /p2p/getPeerID) (default "/p2p/getPeerID")
```
