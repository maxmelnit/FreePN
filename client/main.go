//go:build linux

package main

import (
	"freepn/tun"
	"log"
)

func main() {
	log.Println("Booting FreePN...")

	// Configure TUN
	res, err := tun.OpenTUN("freepn-tun")

	if err != nil {
		log.Fatal("There was a problem creating the virtual interface: ", err)
	} else {
		log.Println("Virtual interface created")
	}

	// Authenticate with JWT, then Diffie-Hellmanefkngfhjn sjj  soodfkd akdjaodondkk  kskkn  fllakkesn dfjsnmnf smd  jdsjd efjn skdkklasndllsnn f asldkllwknmfdsfaa
}
