package tlsutil

import (
  "os"
  "crypto/tls"
  "crypto/x509"
  "log"
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

