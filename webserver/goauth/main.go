package main

import (
	"fmt"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/pat"
	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/twitch"

	//"crypto/tls"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"

	"bytes"

	"encoding/pem"

  //"github.com/alexflint/go-arg"
)

// TODO: turn this into an env variable
var HASH_SALT = "this-is-a-secret-salt"

// TODO: CHANGE THIS LITERALLY RIGHT NOW
var store = sessions.NewCookieStore([]byte("thisisakey"))

func registerProviders() {
  goth.UseProviders(
    twitch.New(os.Getenv("TWITCH_CLIENTID"), os.Getenv("TWITCH_CLIENTSECRET"), "http://localhost:3000/auth/twitch/callback", ""),
  )
}


func generateUserCert(username string) (*bytes.Buffer, *bytes.Buffer, error) {
  rootCACertBytes, err := os.ReadFile("./key/rootCA.pem")
  if (err != nil) {
    fmt.Println(err)
    return nil, nil, err
  }

  rootCAPEMData, _ := pem.Decode(rootCACertBytes)
  rootCA, err := x509.ParseCertificate(rootCAPEMData.Bytes)
  if (err != nil) {
    fmt.Println(err)
    return nil, nil, err
  }


  rootCAPrivBytes, err := os.ReadFile("./key/rootCA.key")
  if (err != nil) {
    fmt.Println(err)
    return nil, nil, err
  }

  rootCAPrivData, _ := pem.Decode(rootCAPrivBytes)
  rootCAPriv, err := x509.ParsePKCS8PrivateKey(rootCAPrivData.Bytes)
  if (err != nil) {
    fmt.Println(err)
    return nil, nil, err
  }

  cert := &x509.Certificate {
    SerialNumber: big.NewInt(1),
    Subject: pkix.Name {
      Organization: []string{username},
      Country: []string{"US"},
      Province: []string{"San Francisco"},
      Locality: []string{"Doesnt Matter"},
      StreetAddress: []string{"asdfasdf"},
      PostalCode: []string{"12345"},
    },  
    NotBefore: time.Date(2020, time.October, 10, 23, 0,0,0, time.UTC),
    NotAfter: time.Date(2025, time.October, 10, 23, 0,0,0, time.UTC),
    
  }

  certPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
  if (err != nil) {
    fmt.Println(err)
    return nil, nil, err
  }

  certBytes, err := x509.CreateCertificate(rand.Reader, cert, rootCA, &certPrivateKey.PublicKey, rootCAPriv)
  if (err != nil) {
    return nil, nil, err
  }

  
  certPEM := new(bytes.Buffer)
  pem.Encode(certPEM, &pem.Block{
    Type: "CERTIFICATE",
    Bytes: certBytes,
  })

  certPrivPEM := new(bytes.Buffer)
  pem.Encode(certPrivPEM, &pem.Block{
    Type: "RSA PRIVATE KEY",
    Bytes: x509.MarshalPKCS1PrivateKey(certPrivateKey),
  })  

  return certPEM, certPrivPEM, nil

}

func createCallbackServer() *pat.Router {
  router := pat.New()

  router.Get("/key", func (res http.ResponseWriter, req *http.Request) {
    session, _ := store.Get(req, "session")
    if (session.Values["logged"] != true) {
      res.WriteHeader(http.StatusForbidden)
      res.Write([]byte("Not authenticated."))
    }

    username := session.Values["user"]
    userPub, userPriv, err := generateUserCert(username.(string))
    if (err != nil) {
      fmt.Println(err)
    }

    userFile, _ := os.CreateTemp("./", "*")
    userFile.Write(userPub.Bytes())
    userFile.Write(userPriv.Bytes())
    res.Header().Set("Content-Disposition", "attachment; filename="+ username.(string) + ".key")
    res.Header().Add("content-type", "application/pkcs8")
    http.ServeFile(res, req, userFile.Name())
    os.Remove(userFile.Name())

  });

  
  router.Get("/auth/{provider}/callback", func (res http.ResponseWriter, req *http.Request) {
    user, err := gothic.CompleteUserAuth(res, req);
    if err != nil {
      fmt.Println(err)
      return;
    }

    session, _ := store.Get(req, "session")
    session.Values["logged"] = true
    session.Values["user"] = user.Name
    
    err = session.Save(req, res)
    if (err != nil) {
      fmt.Println(err)
      res.WriteHeader(http.StatusInternalServerError)
      res.Write([]byte("Internal server error"))
      return
    }

    fmt.Println(session.Values)

    res.WriteHeader(http.StatusOK)
    res.Write([]byte("Hello, "))
    res.Write([]byte(user.Name))
    res.Write([]byte("!"))

  });

  router.Get("/auth/{provider}", func (res http.ResponseWriter, req *http.Request) {
    gothic.BeginAuthHandler(res, req);
  });




  return router
}

func main() {
  fmt.Println("Establishing providers...")
  registerProviders()
  fmt.Println("Starting callback server...")
  router := createCallbackServer()
  http.ListenAndServe(":3000", router)
}
