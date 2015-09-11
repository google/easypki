package easyca

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
)

func NextSerial(pkiroot string) (*big.Int, error) {
	serial := big.NewInt(0)

	f, err := os.OpenFile(filepath.Join(pkiroot, "serial"), os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	n, err := fmt.Fscanf(f, "%X\n", serial)
	if err != nil {
		return nil, err
	}
	if n != 1 {
		return nil, fmt.Errorf("supposed to read 1 element, read: %v", n)
	}

	next := big.NewInt(1)
	next.Add(serial, next)
	output := fmt.Sprintf("%X", next)
	// For compatibility with openssl we need an even length
	if len(output)%2 == 1 {
		output = "0" + output
	}
	f.Truncate(0)
	f.Seek(0, 0)

	n, err = fmt.Fprintln(f, output)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, fmt.Errorf("supposed to write 1 element, written: %v", n)
	}

	return serial, nil
}
