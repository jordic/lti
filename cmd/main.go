package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/jordic/lti"
)

// This package allows to test the lib, acting as a webserver, and
// responding to a / endpoint... that should receive POST requests..

var (
	secret      = flag.String("secret", "", "Default secret for use during testing")
	consumer    = flag.String("consumer", "", "Def consumer")
	httpAddress = flag.String("http", "localhost:5001", "Listen to")
)

func main() {
	flag.Parse()

	http.HandleFunc("/", ltiHandler)
	log.Printf("Lis %s, waiting POST request.", *httpAddress)
	log.Fatal(http.ListenAndServe(*httpAddress, nil))

}

func ltiHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" {
		http.Error(w, "Only post", 500)
		return
	}

	p := lti.NewProvider(*secret, "http://localhost:5001/")

	ok, err := p.IsValid(r)
	if ok == false {
		fmt.Fprintf(w, "Invalid request...")
	}
	if err != nil {
		log.Printf("Invalid request %s", err)
		return
	}

	if ok == true {

		fmt.Fprintf(w, "Request Ok<br/>")
		data := fmt.Sprintf("User %s", p.Get("user_id"))
		fmt.Fprintf(w, data)

	}

}
