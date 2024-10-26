package main

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"os"
)

func generateCertPoolFromPath(path string) (*x509.CertPool, error) {
  pool := x509.NewCertPool()

  dat, err := os.ReadFile(path)
  if err != nil {
    log.Println(err)
    return nil, err
  }

  pool.AppendCertsFromPEM(dat)

  return pool, nil
}

func main() {
    log.SetFlags(log.Lshortfile)

    pool, err := generateCertPoolFromPath("./key/rootCA.pem")
    if err != nil {
      log.Println(err)
      return
    }

    cert, err := tls.LoadX509KeyPair("./key/client.crt", "./key/client.key")
    if err != nil {
      log.Println(err)
      return
    }

    conf := &tls.Config{
      Certificates: []tls.Certificate{cert},
      RootCAs: pool,
      ClientAuth: tls.RequireAndVerifyClientCert,
      ServerName: "lowlevel.server2",
    }

    conn, err := tls.Dial("tcp", "127.0.0.1:8443", conf)
    if err != nil {
        log.Println(err)
        return
    }
    defer conn.Close()

    n, err := conn.Write([]byte("hello\n"))
    if err != nil {
        log.Println(n, err)
        return
    }

    buf := make([]byte, 100)
    n, err = conn.Read(buf)
    if err != nil {
        log.Println(n, err)
        return
    }

    println(string(buf[:n]))
}
