package internal

import (
	"archive/tar"
	"github.com/google/go-containerregistry/pkg/name"
	"io"
	"os"
	"path/filepath"
	"slices"
)

func OnError(err error, callback func(err error)) {
	if err != nil {
		callback(err)
	}
}

func SubtractSlice(left []string, right []string) []string {
	remains := []string{}

	for _, key := range left {
		if !slices.Contains(right, key) {
			remains = append(remains, key)
		}
	}

	return remains
}

func IsOCI(source string) bool {
	// Check whether this looks like an OCI endpoint
	// You can see the verification for the regex at https://regex101.com/r/Z8172m
	_, err := name.NewTag(source, name.StrictValidation)
	return err == nil
}

func Untar(destination string, tarReader io.Reader) error {
	tr := tar.NewReader(tarReader)

	for {
		header, err := tr.Next()

		switch {

		// if no more files are found return
		case err == io.EOF:
			return nil

		// return any other error
		case err != nil:
			return err

		// if the header is nil, just skip it (not sure how this happens)
		case header == nil:
			continue
		}

		// the target location where the dir/file should be created
		target := filepath.Join(destination, header.Name)

		// the following switch could also be done using fi.Mode(), not sure if there
		// a benefit of using one vs. the other.
		// fi := header.FileInfo()

		// check the file type
		switch header.Typeflag {

		// if its a dir and it doesn't exist create it
		case tar.TypeDir:
			if _, err := os.Stat(target); err != nil {
				if err := os.MkdirAll(target, 0755); err != nil {
					return err
				}
			}

		// if it's a file create it
		case tar.TypeReg:
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return err
			}

			// copy over contents
			if _, err := io.Copy(f, tr); err != nil {
				return err
			}

			// manually close here after each file operation; defering would cause each file close
			// to wait until all operations have completed.
			f.Close()
		}
	}
}
