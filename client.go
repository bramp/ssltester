package main

import (
//	"bufio"
	"flag"
	"github.com/bramp/sslconn"
	"log"
	"net"
	"fmt"
//	"reflect"
//	"regexp"
//	"strconv"
//	"crypto/cipher"
)


var settings Settings;

type Method string

type Settings struct {
	allowedMethods map[Method] bool
	minBits int                      // Min allowed
	server string
}

func init() {
	settings.allowedMethods = map[Method] bool {
		"SSLv2": false,
		"SSLv3": false,
		"TLSv1": true,
		"TLSv1_1": true,
		"TLSv1_2": true,
	}

	settings.minBits = 128

	flag.StringVar(&settings.server, "server", "localhost:443", "server address")
}

/*
 Tests all supported ciphers against the target
 The client accepts all ciphers and attempts a connection. Each time a success occurs, we remove that
 cipher from the allowed list. We repeat until we get a failure. This way we know all the allowed
 ciphers and the priority order as defined by the server
 */
func test_all_ciphers() {

	const noMethod = sslconn.OP_NO_SSLv2 | sslconn.OP_NO_SSLv3 | sslconn.OP_NO_TLSv1 | sslconn.OP_NO_TLSv1_1 | sslconn.OP_NO_TLSv1_2

	var methods = map[Method] sslconn.Options {
		"SSLv2"   : noMethod & ^ sslconn.OP_NO_SSLv2,
		"SSLv3"   : noMethod & ^ sslconn.OP_NO_SSLv3,
		"TLSv1"   : noMethod & ^ sslconn.OP_NO_TLSv1,
		"TLSv1_1" : noMethod & ^ sslconn.OP_NO_TLSv1_1,
		"TLSv1_2" : noMethod & ^ sslconn.OP_NO_TLSv1_2,
	}

	config := &sslconn.Config{}
	config.Verify = sslconn.VERIFY_NONE

	supported := make(map[string] []Method)

	// For each method (SSLv2, v3, TLS, etc)
	for method, options := range methods {

		config.Options = options

		// Absolutely all ciphers ( https://www.openssl.org/docs/apps/ciphers.html )
		allowedCiphers := "ALL:COMPLEMENTOFALL"
		count := 0

		// TODO Move this loop into a function, so defer works
		for {
			conn, err := net.Dial("tcp", settings.server)
			if err != nil {
				log.Fatalf("Dial error: %s", err.Error())
			}
			defer conn.Close()

			config.CipherList = allowedCiphers

			sslc, err := sslconn.NewConn(conn, conn, config, false)
			if err != nil {
				log.Fatalf("New connection error: %s", err.Error())
			}
			defer sslc.Free()

			err = sslc.Handshake()
			if err != nil {
				break
			}

			// Now forbid whichever cipher work, and loop again
			cipher := sslc.Cipher()
			allowedCiphers = "!"+cipher+":"+allowedCiphers
			//fmt.Printf("%d %s %s OK\n", count, method, cipher)

			// TODO use some kind of ordered map to store the prio order of the cipher
			count++
			supported[cipher] = append(supported[cipher], method)
		}
	}

	supportedMethods := make(map[Method] bool)

	for cipher, methods := range supported {
		fmt.Println(cipher, methods)
		for _, method := range methods {
			supportedMethods[method] = true
		}
	}

	// Test if we are allowing a method we shouldn't
	fmt.Println(supportedMethods)
	for method := range supportedMethods {
		if found := settings.allowedMethods[method]; !found {
			fmt.Printf("ERR Unsupported method %s\n", method)
		}
	}
}

func main() {

	flag.Parse()

	test_all_ciphers()


}
