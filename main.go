//go:build linux

package main

import (
	"fmt"
	"freepn/tun"
)

func main() {
	fmt.Println("Booting FreePN...")
	
	// Configure TUN
	res, err := tun.OpenTUN("freepn-tun")

	if err != "" {
		fmt.Println(err)
	} else {
		fmt.Println(res)
	}

	// Authenticate






}
