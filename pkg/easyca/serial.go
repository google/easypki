package easyca

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func NextSerial(pkiroot string) (int64, error) {
	var serial int64
	f, err := os.OpenFile(filepath.Join(pkiroot, "serial"), os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	out, err := ioutil.ReadAll(f)
	if err != nil {
		return 0, err
	}
	if len(out) == 0 {
		serial = 1
	} else {
		// If serial file is edited manually, it will probably get \n or \r\n
		// We make sure to clean the unwanted characters
		serial, err = strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
		if err != nil {
			return 0, err
		}
		serial += 1
	}

	f.Seek(0, 0)
	written, err := fmt.Fprint(f, serial)
	if err != nil {
		return 0, err
	}
	if written == 0 {
		return 0, fmt.Errorf("wanted to write %s to serial file, no byte written", written)
	}

	return serial, nil
}
