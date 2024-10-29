package main

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"os"
  "github.com/alexflint/go-arg"
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
    var args struct {
      Keyfile string
      Host string
    }

    arg.MustParse(&args)

    log.SetFlags(log.Lshortfile)

    cert, err := tls.LoadX509KeyPair(args.Keyfile, args.Keyfile)
    if err != nil {
      log.Println(err)
      return
    }
  
    
    conf := &tls.Config{
      Certificates: []tls.Certificate{cert},
      ClientAuth: tls.RequireAndVerifyClientCert,
      InsecureSkipVerify: true,
    }

    conn, err := tls.Dial("tcp", args.Host, conf)
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
