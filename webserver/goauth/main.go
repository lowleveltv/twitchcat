package main

import (
	"fmt"
	"net/http"
  "os"

	"github.com/gorilla/pat"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/twitch"
)

func registerProviders() {
  goth.UseProviders(
    twitch.New(os.Getenv("TWITCH_CLIENTID"), os.Getenv("TWITCH_CLIENTSECRET"), "http://localhost:3000/auth/twitch/callback", ""),
  )
}

func createCallbackServer() *pat.Router {
  router := pat.New()

  router.Get("/auth/{provider}/callback", func (res http.ResponseWriter, req *http.Request) {
    user, err := gothic.CompleteUserAuth(res, req);
    if err != nil {
      fmt.Println(err)
      return;
    }

    fmt.Println(user)

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
