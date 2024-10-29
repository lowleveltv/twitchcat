package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	"github.com/alexflint/go-arg"
)

func loadCertificate(path string) (*x509.Certificate, error) {
  dat, err := os.ReadFile(path)
  if err != nil {
    log.Println(err)
    return nil, err
  }

  pemblock, _ := pem.Decode(dat)
  cert, err := x509.ParseCertificate(pemblock.Bytes)
  if (err != nil) {
    log.Println(err)
    return nil, err
  }
  return cert, nil 

}

func generateCertPool(certs []x509.Certificate) (*x509.CertPool, error) {
  pool := x509.NewCertPool()

  for _, c := range certs {
    pool.AddCert(&c)
  }

  return pool, nil
}


func main()  {

  var args struct {
    CertFile string
    KeyFile string
    RootCAFile string
  }

  arg.MustParse(&args)

  fmt.Println("[+] Starting TLS Server");

  cer, err := tls.LoadX509KeyPair(args.CertFile, args.KeyFile)
  if err != nil {
    log.Println(err)
    return
  }

  rootCAcert, err := loadCertificate(args.RootCAFile)
  if err != nil {
    log.Println(err)
    return
  }

  pool, err := generateCertPool([]x509.Certificate{*rootCAcert})
  if err != nil {
    log.Println(err)
    return
  }

  config := &tls.Config{
    Certificates: []tls.Certificate{cer},
    ClientAuth: tls.RequireAndVerifyClientCert,
    RootCAs: pool,
    ServerName: "lowlevel.server2",
  }

  sock, err := tls.Listen("tcp", ":8443", config)
  if err != nil {
    log.Println(err)
    return
  }

  defer sock.Close()

  for {
    conn, err := sock.Accept()
    if err != nil {
      log.Println(err)
      continue
    }

    t := conn.(*tls.Conn)
    t.Handshake()
    username := t.ConnectionState().PeerCertificates[0].Subject.Organization

    fmt.Printf("[!] %v connected!\n", string(username[0]))

    conn.Write([]byte("Hello world, you are ~*authenticated*~\n"));

  }
  
}
