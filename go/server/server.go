package main

import (
	"bitbucket.org/ortutay/bitnet"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/conformal/btcec"
	"github.com/conformal/btcnet"
	"github.com/conformal/btcscript"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwire"
	log "github.com/golang/glog"
	"github.com/gorilla/rpc"
	"github.com/gorilla/rpc/json"
	"net/http"
	"time"
)

const sigMagic = "Bitcoin Signed Message:\n"

type BitnetService struct {
	Bitcoin   Bitcoin
	Address   bitnet.BitcoinAddress
	Datastore *bitnet.Datastore
}

func NewBitnetServiceOnHelloBlock(address bitnet.BitcoinAddress) *BitnetService {
	hb := new(HelloBlock)
	hb.SetNetwork(Testnet3)
	bitnet := BitnetService{
		Address:   address,
		Datastore: bitnet.NewDatastore(),
		Bitcoin:   hb,
	}
	return &bitnet
}

func main() {
	addr := "localhost:4000"
	log.Info("Listening on %v...\n", addr)

	hb := new(HelloBlock)
	hb.SetNetwork(Testnet3)
	// helloblock.SetNetwork(helloblock.Testnet)
	btcAddr := bitnet.BitcoinAddress("mrvdXP7dNodDu9YcdrFWzfXomnWNvASGnb")
	bitnet := NewBitnetServiceOnHelloBlock(btcAddr)

	server := rpc.NewServer()
	server.RegisterCodec(json.NewCodec(), "application/json")
	server.RegisterService(&bitnet, "Bitnet")
	http.Handle("/bitnetRPC", server)
	http.ListenAndServe(addr, nil)
}

func (b *BitnetService) netParams() *btcnet.Params {
	return &btcnet.TestNet3Params
}

func (b *BitnetService) BuyTokens(r *http.Request, args *bitnet.BuyTokensArgs, reply *bitnet.BuyTokensReply) error {
	log.Infof("Handling BuyTokens %v\n", args)
	txData, err := hex.DecodeString(args.RawTx)
	if err != nil {
		return errors.New("couldn't decode raw transaction")
	}
	tx, err := btcutil.NewTxFromBytes(txData)
	if err != nil {
		return fmt.Errorf("couldn't decode tx: %v", err)
	}
	log.Infof("got tx: %v\n", tx)
	value := int64(0)
	for _, out := range tx.MsgTx().TxOut {
		scriptClass, addresses, _, err := btcscript.ExtractPkScriptAddrs(
			out.PkScript, b.netParams())
		if err != nil {
			log.Errorf("Couldn't decode %v: %v", out.PkScript, err)
			return errors.New("couldn't decode transaction")
		}
		if scriptClass != btcscript.PubKeyHashTy {
			continue
		}
		fmt.Printf("class: %v, addrs: %v\n", scriptClass, addresses)
		if addresses[0].String() != b.Address.String() {
			continue
		}
		value += out.Value
	}
	numTokens := value * bitnet.TokensPerSatoshi
	log.Infof("Tx value to us: %v -> %v tokens\n", value, numTokens)

	txHash, err := b.Bitcoin.SendRawTransaction(args.RawTx)
	if err != nil {
		return errors.New("bitcoin network did not accept transaction")
	}
	log.Infof("Successfully submitted transaction, ID: %v\n", txHash)

	pubKey, err := pubKeyFromHex(args.PubKey)
	if err != nil {
		return errors.New("couldn't decode public key")
	}

	// TODO(ortutay): Getting an error here is bad, because we have already
	// submitted the client's transaction. We should have more handling around
	// this case.
	if err := b.Datastore.AddTokens(pubKey, numTokens); err != nil {
		log.Errorf("Couldn't add tokens in datastore %v", err)
		return errors.New("Transaction was accepted, but error while crediting tokens. Please report.")
	}

	return nil
}

func (b *BitnetService) ClaimTokens(r *http.Request, args *bitnet.ClaimTokensArgs, reply *bitnet.ClaimTokensReply) error {
	log.Infof("ClaimTokens(%v)", args)

	// Verify signature.
	message, err := args.SignableHash()
	if err != nil {
		log.Errorf("Couldn't get message for %v: %v", args, err)
		return errors.New("couldn't verify signature")
	}
	fullMessage := bitnet.BitcoinSigMagic + message

	sigBytes, err := base64.StdEncoding.DecodeString(args.Sig)
	if err != nil {
		log.Errorf("Couldn't decode signature for %v: %v", args, err)
		return errors.New("couldn't verify signature")
	}
	hash := btcwire.DoubleSha256([]byte(fullMessage))
	pubKey, wasCompressed, err := btcec.RecoverCompact(btcec.S256(), sigBytes, hash)

	btcPubKey := (*btcec.PublicKey)(pubKey)
	var serializedBytes []byte
	if wasCompressed {
		serializedBytes = btcPubKey.SerializeCompressed()
	} else {
		serializedBytes = btcPubKey.SerializeUncompressed()
	}
	btcAddr, err := btcutil.NewAddressPubKey(serializedBytes, &btcnet.TestNet3Params)
	if err != nil {
		log.Errorf("Couldn't create bitcoin address for %v %v: %v", serializedBytes, args, err)
		return errors.New("couldn't verify signature")
	}
	if btcAddr.EncodeAddress() != args.BitcoinAddress {
		return errors.New("invalid signature")
	}

	// Verify that challenge is valid.
	if !b.Datastore.HasChallenge(args.Challenge) {
		return errors.New("invalid challenge")
	}
	expires, err := b.Datastore.GetChallengeExpiration(args.Challenge)
	if err != nil {
		log.Errorf("Couldn't get challenge %v: %v", args.Challenge, err)
		return errors.New("server error")
	}
	expired := expires < time.Now().Unix()
	if err := b.Datastore.DeleteChallenge(args.Challenge); err != nil {
		log.Errorf("Couldn't delete challenge %v: %v", args.Challenge, err)
		if !expired {
			return errors.New("server error")
		}
	}
	if expired {
		return errors.New("challenge expired, retry with new challenge")
	}

	// TODO(ortutay): Check balance on bitcoin address
	tokensPubKey, err := pubKeyFromHex(args.PubKey)
	if err != nil {
		return errors.New("couldn't decode public key")
	}
	if err := b.Datastore.AddTokens(tokensPubKey, bitnet.TokensForAddressWithBalance); err != nil {
		log.Errorf("Couldn't add tokens in datastore %v", err)
		return errors.New("Signature was accepted, but error while crediting tokens.")
	}

	pkHashAddr, err := bitnet.NewBitcoinAddress(args.BitcoinAddress)
	if err != nil {
		// We have already validated the address, so we should never reach this.
		log.Errorf("Invalid address reach unexpectedly for %q", args.BitcoinAddress)
		return errors.New("invalid bitcoin address")
	}
	if err := b.Datastore.StoreUsedAddress(pkHashAddr); err != nil {
		log.Errorf("Error while noting address use: %v", err)
		// Do not return error, since we have credited the tokens.
	}

	return nil
}

func (b *BitnetService) Challenge(r *http.Request, args *bitnet.ChallengeArgs, reply *bitnet.ChallengeReply) error {
	// TODO(ortutay): This is susceptible to DOS attack in two ways:
	// 1) Filling the datastore with lots of challenge strings.
	// 2) Exhausting entropy on the system.
	// Mitigation possibilities:
	// - Add expiration to challenge string, and regularly purge the datastore.
	// - When system lacks entropy, we could make a call to trusted external
	//   source of entropy, like random.org. This is undesireable and a potential
	//   security hole.
	// - Require tokens to generate a challenge. This is undeseriable, since
	//   challenge is used for the ClaimTokens method.
	buf := make([]byte, 32)
	_, err := rand.Read(buf)
	if err != nil {
		log.Errorf("Couldn't generate challenge: %v", err)
		return errors.New("couldn't generate challenge")
	}
	challenge := hex.EncodeToString(buf)
	if err := b.Datastore.StoreChallenge(challenge); err != nil {
		log.Errorf("Couldn't store challenge: %v", err)
		return errors.New("couldn't generate challenge")
	}
	reply.Challenge = challenge
	return nil
}

func pubKeyFromHex(pubKeyHex string) (*btcec.PublicKey, error) {
	pubKeyData, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return nil, err
	}
	pubKey, err := btcec.ParsePubKey(pubKeyData, btcec.S256())
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}
