package main

import (
	"crypto/tls"
	"fmt"
	"log"
  "os"
  "crypto/x509"
)

func loadCertificate(path string) (*tls.Certificate, error) {
  dat, err := os.ReadFile(path)
  if err != nil {
    log.Println(err)
    return nil, err
  }

  cert := &tls.Certificate{
    Certificate: [][]byte{dat},
  }

  return cert, nil 

}

func generateCertPool(certs []tls.Certificate) (*x509.CertPool, error) {
  pool := x509.NewCertPool()

  for _, c := range certs {
    newcert := x509.Certificate{
      Raw: c.Certificate[0],
    }

    pool.AddCert(&newcert)
  }

  return pool, nil
}


func main()  {
  fmt.Println("[+] Starting TLS Server");

  cer, err := tls.LoadX509KeyPair("./key/server.crt", "./key/server.key")
  if err != nil {
    log.Println(err)
    return
  }

  rootCAcert, err := loadCertificate("./key/rootCA.der")
  if err != nil {
    log.Println(err)
    return
  }

  pool, err := generateCertPool([]tls.Certificate{*rootCAcert})
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

    fmt.Println("[!] Accepted a client connection!")

    conn.Write([]byte("Hello world, you are ~*authenticated*~\n"));

  }
  
}
