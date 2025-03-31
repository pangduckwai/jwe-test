package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

// Generate private key:
//  - openssl genrsa -out private.pem 2048
// Output public key:
//  - openssl rsa -in private.pem -outform PEM -pubout -out public.pem

func readPrivateKey(fstr string) (prvkey *rsa.PrivateKey, err error) {
	prvf, err := os.ReadFile(fstr)
	if err != nil {
		err = fmt.Errorf("[PRV1] %v", err)
		return
	}
	prvb, _ := pem.Decode(prvf)
	prvp, err := x509.ParsePKCS8PrivateKey(prvb.Bytes)
	if err != nil {
		err = fmt.Errorf("[PRV2] %v", err)
		return
	}
	prvkey = prvp.(*rsa.PrivateKey)
	return
}

func readPublicKey(fstr string) (pubkey *rsa.PublicKey, err error) {
	pubf, err := os.ReadFile(fstr)
	if err != nil {
		err = fmt.Errorf("[PUB1] %v", err)
		return
	}
	pubb, _ := pem.Decode(pubf)
	pubp, err := x509.ParsePKIXPublicKey(pubb.Bytes)
	if err != nil {
		err = fmt.Errorf("[PUB2] %v", err)
		return
	}
	pubkey = pubp.(*rsa.PublicKey)
	return
}

func main() {
	// Read sender private key
	prvs, err := readPrivateKey("send.pem")
	if err != nil {
		log.Fatalf("[PRVS] %v", err)
	}

	// Read sender public key
	pubs, err := readPublicKey("sendpub.pem")
	if err != nil {
		log.Fatalf("[PUBS] %v", err)
	}

	// Read receiver private key
	prvr, err := readPrivateKey("rcvr.pem")
	if err != nil {
		log.Fatalf("[PRVR] %v", err)
	}

	// Read receiver public key
	pubr, err := readPublicKey("rcvrpub.pem")
	if err != nil {
		log.Fatalf("[PUBR] %v", err)
	}

	// Main
	if len(os.Args) < 2 {
		log.Printf("Usage: go run . [jwe|jws]\n")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "jws":
		vfy(prvs, pubs)
	case "jwe":
		enc(prvs, prvr, pubs, pubr)
	default:
		log.Printf("Usage: go run . [jws|jwe]\n")
		os.Exit(1)
	}
}
