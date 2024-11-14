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

  "github.com/alexflint/go-arg"
)

var HASH_SALT = os.Getenv("TWITCHCAT_SALT")
var session_secret = os.Getenv("TWITCHCAT_SESSION_SECRET")
var store = sessions.NewCookieStore([]byte("this_is"))

var args struct {
  RootCACert string
  RootCAKey string
}

func registerProviders() {
  goth.UseProviders(
    twitch.New(os.Getenv("TWITCH_CLIENTID"), os.Getenv("TWITCH_CLIENTSECRET"), os.Getenv("TWITCH_REDIRECT"), ""),
  )
}


func generateUserCert(username string) (*bytes.Buffer, *bytes.Buffer, error) {
  rootCACertBytes, err := os.ReadFile(args.RootCACert)
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


  rootCAPrivBytes, err := os.ReadFile(args.RootCAKey)
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

  certPrivateKey, err := rsa.GenerateKey(rand.Reader, 1024)
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
      return
    } 

    username := session.Values["user"]
    if (username == nil) {
      res.WriteHeader(http.StatusForbidden)
      res.Write([]byte("Not authenticated."))
      return
    }

    userPub, userPriv, err := generateUserCert(username.(string))
    if (err != nil) {
      fmt.Println(err)
      return
    }

    userFile, _ := os.CreateTemp("./", "*")
    userFile.Write(userPub.Bytes())
    userFile.Write(userPriv.Bytes())
    res.Header().Set("Content-Disposition", "attachment; filename="+ username.(string) + ".key")
    res.Header().Add("Content-Type", "application/pkcs8")
    http.ServeFile(res, req, userFile.Name())
    os.Remove(userFile.Name())

  });

  
  router.Get("/auth/{provider}/callback", func (res http.ResponseWriter, req *http.Request) {
    user, err := gothic.CompleteUserAuth(res, req);
    if err != nil {
      fmt.Println(err)
      http.Redirect(res, req, "/auth/twitch", http.StatusMovedPermanently)
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

    // TODO: render a template
    res.WriteHeader(http.StatusOK)
    res.Header().Add("Content-Type", "text/html")
    res.Write([]byte("<html>Hello, "))
    res.Write([]byte(user.Name))
    res.Write([]byte("!<br><br>"))
    res.Write([]byte("<a href=\"/key\">Get Your Key!</a></html>"))

  });

  router.Get("/auth/{provider}", func (res http.ResponseWriter, req *http.Request) {
    gothic.BeginAuthHandler(res, req);
  });


  router.Get("/", func (res http.ResponseWriter, req *http.Request) {
    http.Redirect(res, req, "/auth/twitch", http.StatusMovedPermanently);
    return;
  })



  return router
}

func main() {
  arg.MustParse(&args)

  fmt.Println("Establishing providers...")
  registerProviders()
  fmt.Println("Starting callback server...")
  router := createCallbackServer()
  http.ListenAndServe(":3000", router)
}
