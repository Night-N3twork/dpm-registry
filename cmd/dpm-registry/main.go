package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	registry "dpm-registry"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "migrate-tarballs" {
		migrateTarballs(os.Args[2:])
		return
	}
	serve(os.Args[1:])
}

func loadConfig(path string) registry.Config {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	var config registry.Config
	if err := json.Unmarshal(data, &config); err != nil {
		log.Fatal(err)
	}
	return config
}

func migrateTarballs(args []string) {
	flags := flag.NewFlagSet("migrate-tarballs", flag.ExitOnError)
	configPath := flags.String("config", "config.json", "path to JSON configuration")
	flags.Parse(args)
	changed, err := registry.MigrateTarballs(loadConfig(*configPath))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("rewrote %d tarball URL(s)", changed)
}

func serve(args []string) {
	flags := flag.NewFlagSet("dpm-registry", flag.ExitOnError)
	configPath := flags.String("config", "config.json", "path to JSON configuration")
	address := flags.String("listen", ":4873", "listen address")
	flags.Parse(args)
	config := loadConfig(*configPath)
	handler, err := registry.NewHandler(config)
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{
		Addr:              *address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	log.Fatal(server.ListenAndServe())
}
