package transport

import (
	"log"
	"os"
)

func Write(fd *os.File, data []byte) {

	// goroutine not needed for write, since it's quick
	fd.Write(data)
}

func Read(fd *os.File) chan []byte {

	channel := make(chan []byte)

	// fd.Read() is a blocking call, which can prevent writing
	go func() {
		// 1500 bytes is MTU
		var buffer [1500]byte
		for {

			// Read up to n bytes from the file descriptor and store in the buffer
			n, err := fd.Read(buffer[:])

			// If error occurs, exit goroutine and close channel
			if err != nil {
				log.Println("Error reading packet")
				close(channel)
				return
			}

			channel <- buffer[:n]
		}
	}()

	return channel

}
