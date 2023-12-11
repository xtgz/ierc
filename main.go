package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"io/ioutil"
	"net/http"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	log "github.com/sirupsen/logrus"
)

var (
	priv      *ecdsa.PrivateKey
	address   common.Address
	ethClient *ethclient.Client
	dataTemp  string
)
var (
	globalNonce = time.Now().UnixNano()
	zeroAddress = common.HexToAddress("0x0000000000000000000000000000000000000000")
	chainID     = big.NewInt(0)
	userNonce   = -1
)

func main() {
	log.Infoln()
	log.Infoln(" ██ ███████ ██████   ██████     ███    ███ ██ ███    ██ ███████ ██████ ")
	log.Infoln(" ██ ██      ██   ██ ██          ████  ████ ██ ████   ██ ██      ██   ██")
	log.Infoln(" ██ █████   ██████  ██          ██ ████ ██ ██ ██ ██  ██ █████   ██████ ")
	log.Infoln(" ██ ██      ██   ██ ██          ██  ██  ██ ██ ██  ██ ██ ██      ██   ██")
	log.Infoln(" ██ ███████ ██   ██  ██████     ██      ██ ██ ██   ████ ███████ ██   ██")
	log.Infoln()
	log.Infoln(`作者 @chenmin22998595  https://twitter.com/chenmin22998595`)
	log.Infoln(`Author @chenmin22998595  https://twitter.com/chenmin22998595`)
	log.Infoln()
	dataTemp = fmt.Sprintf(`data:application/json,{"p":"ierc-20","op":"mint","tick":"%s","amt":"%d","nonce":"%%d"}`, config.Tick, config.Amt)
	var err error
	ethClient, err = ethclient.Dial(config.Rpc)
	if err != nil {
		panic(err)
	}

	chainID, err = ethClient.ChainID(context.Background())
	if err != nil {
		panic(err)
	}

	bytePriv, err := hexutil.Decode(config.PrivateKey)
	if err != nil {
		panic(err)
	}
	prv, _ := btcec.PrivKeyFromBytes(bytePriv)
	priv = prv.ToECDSA()
	address = crypto.PubkeyToAddress(*prv.PubKey().ToECDSA())
	log.WithFields(log.Fields{
		"prefix":   config.Prefix,
		"amt":      config.Amt,
		"tick":     config.Tick,
		"count":    config.Count,
		"address":  address.String(),
		"chain_id": chainID.Int64(),
	}).Info("prepare done")

	startNonce := globalNonce
	go func() {
		for {
			last := globalNonce
			time.Sleep(time.Second * 10)

			if config.EnableAPI {
				amount, max := checkAmount(config.Tick)
				if amount+int64(config.Amt) > max {
					os.Exit(0)
				}

				log.WithFields(log.Fields{
					"hash_rate":  fmt.Sprintf("%dhashes/s", (globalNonce-last)/10),
					"hash_count": globalNonce - startNonce,
					"amount":     amount,
					"max":        max,
				}).Info()
			} else {
				log.WithFields(log.Fields{
					"hash_rate":  fmt.Sprintf("%dhashes/s", (globalNonce-last)/10),
					"hash_count": globalNonce - startNonce,
				}).Info()
			}
		}
	}()

	wg := new(sync.WaitGroup)
	for i := 0; i < config.Count; i++ {
		tx := makeBaseTx()
		wg.Add(runtime.NumCPU())
		ctx, cancel := context.WithCancel(context.Background())
		for j := 0; j < runtime.NumCPU(); j++ {
			go func(ctx context.Context, cancelFunc context.CancelFunc) {
				for {
					select {
					case <-ctx.Done():
						wg.Done()
						return
					default:
						makeTx(cancelFunc, tx)
					}
				}
			}(ctx, cancel)
		}
		wg.Wait()
	}
}

func makeTx(cancelFunc context.CancelFunc, innerTx *types.DynamicFeeTx) {
	atomic.AddInt64(&globalNonce, 1)
	temp := fmt.Sprintf(dataTemp, globalNonce)
	innerTx.Data = []byte(temp)
	tx := types.NewTx(innerTx)
	signedTx, _ := types.SignTx(tx, types.NewCancunSigner(chainID), priv)
	if strings.HasPrefix(signedTx.Hash().String(), config.Prefix) {
		log.WithFields(log.Fields{
			"tx_hash": signedTx.Hash().String(),
			"data":    temp,
		}).Info("found new transaction")

		err := ethClient.SendTransaction(context.Background(), signedTx)
		if err != nil {
			log.WithFields(log.Fields{
				"tx_hash": signedTx.Hash().String(),
				"err":     err,
			}).Error("failed to send transaction")
		} else {
			log.WithFields(log.Fields{
				"tx_hash": signedTx.Hash().String(),
			}).Info("broadcast transaction")
		}

		cancelFunc()
	}
}

func makeBaseTx() *types.DynamicFeeTx {
	if userNonce < 0 {
		nonce, err := ethClient.PendingNonceAt(context.Background(), address)
		if err != nil {
			panic(err)
		}
		userNonce = int(nonce)
	} else {
		userNonce++
	}
	innerTx := &types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     uint64(userNonce),
		GasTipCap: new(big.Int).Mul(big.NewInt(1000000000), big.NewInt(int64(config.GasTip))),
		GasFeeCap: new(big.Int).Mul(big.NewInt(1000000000), big.NewInt(int64(config.GasMax))),
		Gas:       30000 + uint64(rand.Intn(1000)),
		To:        &zeroAddress,
		Value:     big.NewInt(0),
	}

	return innerTx
}

func checkAmount(tick string) (int64, int64) {
	payload := fmt.Sprintf(`{"tick": "%s"}`, tick)
	PostOneUrl := "https://service.ierc20.com/api/v1/ticks/one"

	resp, err := http.Post(PostOneUrl,
		"application/json; charset=utf-8",
		bytes.NewBuffer([]byte(payload)))
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	var f map[string]interface{}
	if err := json.Unmarshal(body, &f); err != nil {
		panic(err)
	}
	f = f["data"].(map[string]interface{})

	amount, _ := strconv.ParseInt(f["amount"].(string), 10, 0)
	max, _ := strconv.ParseInt(f["max"].(string), 10, 0)
	return amount, max
}
