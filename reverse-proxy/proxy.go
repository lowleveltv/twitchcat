package main

import (
  "crypto/tls"
  "crypto/x509"
  "encoding/pem"
  "fmt"
  "io"
  "log"
  "net"
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
  if err != nil {
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

func reverseConnect(front net.Conn, targetAddr string, targetPort string) {
  address := targetAddr + ":" + targetPort
  back, err := net.Dial("tcp4", address)
  if err != nil {
    fmt.Println(err)
    front.Write([]byte(err.Error()))
    front.Close()
    return
  }

  go io.Copy(front, back)
  io.Copy(back, front)
}

func handleConnections(listener net.Listener, targetAddr string, targetPort string) {
  for {
    conn, err := listener.Accept()
    if err != nil {
      fmt.Println("Error accepting connection:", err)
      continue
    }

    t := conn.(*tls.Conn)
    t.Handshake()
    peers := t.ConnectionState().PeerCertificates

    if len(peers) != 1 {
      fmt.Println("[!] Was not presented a cert by the connection")
      conn.Write([]byte("Failed to verify certificate, register at keys.lowlevel.tv.\n"))
      conn.Close()
      continue
    }

    username := peers[0].Subject.Organization[0]
    fmt.Printf("[!] %s connected\n", username)

    go reverseConnect(conn, targetAddr, targetPort)
  }
}

func main() {

  var args struct {
    CertFile         string
    KeyFile          string
    RootCAFile       string
    RemoteTargetAddr string
    RemoteTargetPort string
  }

  arg.MustParse(&args)

  fmt.Println("[+] Starting Twitch Chat Reverse Proxy")

  fmt.Println("[+] Loading key information")
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

  fmt.Println("[+] Loading RootCA certificate")
  pool, err := generateCertPool([]x509.Certificate{*rootCAcert})
  if err != nil {
    log.Println(err)
    return
  }

  config := &tls.Config{
    Certificates: []tls.Certificate{cer},
    ClientAuth:   tls.RequireAndVerifyClientCert,
    RootCAs:      pool,
    ClientCAs:    pool,
  }

  sock, err := tls.Listen("tcp", ":4444", config)
  if err != nil {
    log.Println(err)
    return
  }

  defer sock.Close()

  handleConnections(sock, args.RemoteTargetAddr, args.RemoteTargetPort)
}
