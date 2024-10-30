package main

import (
  "crypto/tls"
  "crypto/x509"
  "encoding/pem"
  "fmt"
  "log"
  "os"
  "bufio"
  "net"
  "strings"
  "sync"

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

type Client struct {
  conn net.Conn
  name string
  ch   chan string
}

func broadcastMessages(clients map[string]Client, messages chan string) {
  for msg := range messages {
    for _, client := range clients {
      select {
      case client.ch <- msg: // Send message to each client
      default:
        fmt.Printf("Message failed to send to %s\n", client.name)
      }
    }
  }
}

func handleClient(client Client, clients map[string]Client, messages chan string, wg *sync.WaitGroup) {
  defer wg.Done()

  scanner := bufio.NewScanner(client.conn)
  for scanner.Scan() {
    msg := scanner.Text()
    if strings.TrimSpace(msg) == "" {
      continue
    }
    broadcast := fmt.Sprintf("%s: %s", client.name, msg)
    fmt.Println(broadcast)
    messages <- broadcast
  }

  client.conn.Close()
  delete(clients, client.name)
  messages <- fmt.Sprintf("%s has left the chat", client.name)
}

func handleConnections(listener net.Listener, messages chan string, clients map[string]Client, wg *sync.WaitGroup) {
  for {
    conn, err := listener.Accept()
    if err != nil {
      fmt.Println("Error accepting connection:", err)
      continue
    }

    t := conn.(*tls.Conn)
    t.Handshake()
    peers := t.ConnectionState().PeerCertificates
        
    if (len(peers) != 1) {
      fmt.Println("[!] Was not presented a cert by the connection")
      conn.Close()
      continue
    }

    username := peers[0].Subject.Organization[0]

    client := Client{
      conn: conn,
      name: username,
      ch:   make(chan string),
    }

    clients[username] = client
    messages <- fmt.Sprintf("%s has joined the chat", username)

    go func(client Client) {
      for msg := range client.ch {
        fmt.Fprintln(client.conn, msg)
      }
    }(client)

    wg.Add(1)
    go handleClient(client, clients, messages, wg)
  }
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
    ClientCAs: pool,
  }

  sock, err := tls.Listen("tcp", ":4444", config)
  if err != nil {
    log.Println(err)
    return
  }

  defer sock.Close()

  messages := make(chan string)
  clients := make(map[string]Client)
  var wg sync.WaitGroup

  go broadcastMessages(clients, messages)

  fmt.Println("[-] Chatroom started on :4444")

  handleConnections(sock, messages, clients, &wg)

  wg.Wait()
  
}