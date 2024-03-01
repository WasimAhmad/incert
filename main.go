package main

import (
	"archive/tar"
	"bytes"

	// "encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/stream"
)

var (
	imageURL        string
	caCertFile      string
	caCertsImageURL string
	destImageURL    string
	imageCertPath   string
	outputCerts     string
	replaceCerts    bool
)

func init() {
	flag.StringVar(&imageURL, "image-url", "", "The URL of the image to append the CA certificates to")
	flag.StringVar(&caCertFile, "ca-certs-file", "", "The path to the local CA certificates file")
	flag.StringVar(&caCertsImageURL, "ca-certs-image-url", "", "The URL of an image to extract the CA certificates from")
	flag.StringVar(&destImageURL, "dest-image-url", "", "The URL of the image to push the modified image to")
	flag.StringVar(&imageCertPath, "image-cert-path", "/etc/ssl/certs/ca-certificates.crt", "The path to the certificate file in the image (optional)")
	flag.StringVar(&outputCerts, "output-certs-path", "", "Output the (appended) certificates file from the image to a local file (optional)")
	flag.BoolVar(&replaceCerts, "replace-certs", false, "Replace the certificates in the certificate file instead of appending them")
}

func main() {
	flag.Parse()

	if imageURL == "" || destImageURL == "" || (caCertFile == "" && caCertsImageURL == "") {
		flag.Usage()
		os.Exit(1)
	}

	caCertBytes, err := getCertBytes()
	if err != nil {
		log.Fatalf("Failed to get certificate bytes: %s", err)
	}

	img, err := fetchImage(imageURL)
	if err != nil {
		log.Fatalf("Failed to fetch image %s: %s\n", imageURL, err)
	}

	newImg, err := newImage(img, caCertBytes)
	if err != nil {
		log.Fatalf("Failed to create new image: %s\n", err)
	}

	if outputCerts != "" {
		if err := os.WriteFile(outputCerts, caCertBytes, 0644); err != nil {
			log.Fatalf("Failed to write certificates to file %s: %s.\n", outputCerts, err)
		}
	}

	newRef, err := name.ParseReference(destImageURL)
	if err != nil {
		log.Fatalf("Failed to parse destination image URL %s: %s\n", destImageURL, err)
	}

	err = remote.Write(newRef, newImg, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		log.Fatalf("Failed to push modified image %s: %s\n", newRef.String(), err)
	}

	fmt.Fprintf(os.Stderr, "Successfully appended CA certificates to image %s\n", newRef.String())
	if h, err := newImg.Digest(); err == nil {
		fmt.Printf("%s@sha256:%s\n", newRef.String(), h.Hex)
	} else {
		log.Printf("Failed to get digest of image %s: %s\n", newRef.String(), err)
	}
}

func fetchImage(imageURL string) (v1.Image, error) {
	ref, err := name.ParseReference(imageURL)
	if err != nil {
		return nil, err
	}
	return remote.Image(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
}

func getCertBytes() ([]byte, error) {
	if caCertFile != "" {
		return os.ReadFile(caCertFile)
	}
	return extractCACerts(caCertsImageURL)
}

func extractCACerts(imageURL string) ([]byte, error) {
	img, err := fetchImage(imageURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch image %s: %w", imageURL, err)
	}

	flattened := mutate.Extract(img)
	tr := tar.NewReader(flattened)
	defer flattened.Close()

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading tar: %w", err)
		}

		if hdr.Name == imageCertPath || hdr.Name == strings.TrimPrefix(imageCertPath, "/") {
			certBytes, err := io.ReadAll(tr)
			if err != nil {
				return nil, fmt.Errorf("error reading cert file %s: %w", hdr.Name, err)
			}
			return certBytes, nil
		}
	}
	return nil, fmt.Errorf("failed to find %s in remote image", imageCertPath)
}

func newImage(old v1.Image, caCertBytes []byte) (v1.Image, error) {
	var newCaCertBytes []byte
	// var err error
	if replaceCerts {
		newCaCertBytes = caCertBytes
	} else {
		imgCaCertBytes, err := extractCACerts(imageURL)
		if err != nil {
			return nil, fmt.Errorf("failed to extract CA certificates from image: %w", err)
		}
		newCaCertBytes = append(imgCaCertBytes, caCertBytes...)
	}

	buf := bytes.Buffer{}
	tarW := tar.NewWriter(&buf)
	if err := tarW.WriteHeader(&tar.Header{Name: imageCertPath, Mode: 0644, Size: int64(len(newCaCertBytes))}); err != nil {
		return nil, fmt.Errorf("failed to write tar header: %w", err)
	}
	if _, err := tarW.Write(newCaCertBytes); err != nil {
		return nil, fmt.Errorf("failed to write tar body: %w", err)
	}
	tarW.Close()

	return mutate.Append(old, mutate.Addendum{Layer: stream.NewLayer(io.NopCloser(&buf))})
}
