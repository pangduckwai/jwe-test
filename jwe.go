package main

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
)

func enc(
	prvkeys, prvkeyr *rsa.PrivateKey,
	pubkeys, pubkeyr *rsa.PublicKey,
) {
	// Sign
	token, err := signJws(prvkeys)
	if err != nil {
		log.Fatalf("[SIGN] %v", err)
	}
	fmt.Printf("JWS:\n%v\n\n", token)

	buff := []byte(token) // []byte("Hello there!!!") //

	encrypted, err := jwe.Encrypt(buff, jwe.WithKey(jwa.RSA_OAEP_256, pubkeyr), jwe.WithContentEncryption(jwa.A128CBC_HS256))
	if err != nil {
		log.Fatalf("[ENC] %v", err)
	}
	fmt.Printf("ENC:\n%s\n\n", encrypted)

	jmsg, err := jwe.Parse(encrypted)
	if err != nil {
		log.Fatalf("[ENC] %v", err)
	}
	fmt.Println("JWE:")
	json.NewEncoder(os.Stdout).Encode(jmsg)
	for iter := jmsg.ProtectedHeaders().Iterate(context.TODO()); iter.Next(context.TODO()); {
		fmt.Printf("Protected \"%v\" : \"%v\"\n", iter.Pair().Key, iter.Pair().Value)
	}
	fmt.Println()

	decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.RSA_OAEP_256, prvkeyr))
	if err != nil {
		log.Fatalf("[DEC] %v", err)
	}
	fmt.Printf("DEC:\n%s\n\n", decrypted)

	header, claims, err := verifyJws(string(decrypted), pubkeys)
	if err != nil {
		log.Fatalf("[VERIFY] %v", err)
	}
	for h, v := range header {
		fmt.Printf("Header \"%v\": \"%v\"\n", h, v)
	}
	for c, v := range claims {
		fmt.Printf("Claims \"%v\": \"%v\"\n", c, v)
	}
}
