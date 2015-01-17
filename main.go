package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"reflect"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var (
	db *sql.DB
)

func loadDB() {
	// do we have a database already?
	var err error

	db, err = sql.Open("sqlite3", "./foo.db")
	if err != nil {
		log.Fatal(err)
	}

	sqlStmt := `
		create table if not exists certs (id integer not null primary key autoincrement, certificate text, comment varchar(75));
		create table if not exists key (id integer not null primary key autoincrement, key text, comment varchar(75));
		create table if not exists requests (id integer not null primary key autoincrement, csr text, comment varchar(75));
	        `
	if _, err = db.Exec(sqlStmt); err != nil {
		log.Fatal("%q: %s\n", err, sqlStmt)
	}
}

func usage() {
	fmt.Println("\tserve: serve the web application\n\tlist: list certificates")
}

func createKey() {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		log.Fatal(err)
	}

	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)

	sqlStmt := fmt.Sprintf("insert into key (key, comment) values ('%s', '')", pemdata)

	if _, err = db.Exec(sqlStmt); err != nil {
		log.Fatal("%q: %s\n", err, sqlStmt)
	}
}

func createCert() {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "CA Root",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now(),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	rows, err := db.Query("select * from key limit 1")
	if err != nil {
		log.Fatal("%q\n", err)
	}
	defer rows.Close()

	var id int
	var key string
	var comment string

	for rows.Next() {
		rows.Scan(&id, &key, &comment)
	}

	pemkey, _ := pem.Decode([]byte(key))
	parsedkey, err := x509.ParsePKCS1PrivateKey(pemkey.Bytes)

	fmt.Println(reflect.TypeOf(parsedkey))

	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, &parsedkey.PublicKey, parsedkey)
	if err != nil {
		log.Fatal("error: ", err)
	}

	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "BEGIN CERTIFICATE",
			Bytes: x509.MarshalPKIXPublicKey(cert),
		},
	)

	sqlStmt := fmt.Sprintf("insert into certs (certificate, comment) values ('%s', '')", pemdata)
	if _, err = db.Exec(sqlStmt); err != nil {
		log.Fatal("%q: %s\n", err, sqlStmt)
	}
}

func listCerts() {
	sqlStmt := "select * from certs"

	rows, err := db.Query(sqlStmt)
	if err != nil {
		log.Fatal("%q: %s\n", err, sqlStmt)
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var certificate string
		var comment string

		rows.Scan(&id, &certificate, &comment)
		log.Println(id, certificate, comment)
	}
}

func main() {
	loadDB()
	defer db.Close()

	if len(os.Args) < 2 {
		usage()
		return
	}

	cmd := os.Args[1]

	switch cmd {
	case "key":
		// TODO(xiu): add bits argument
		createKey()
	case "cert":
		createCert()
	case "serve":
		log.Fatal("Not implemented yet")
	case "help":
		usage()
	default:
		usage()
	}
}
