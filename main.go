package main

import (
	"email_pgp/analysis"
	"email_pgp/receiver"
	"email_pgp/sender"
	fl "flag"
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
)

var isSend, isReceive, keysOnly, analysisOnly bool

func init() {
	fl.BoolVar(&isSend, "send", false, "Sends the text in the file email.txt to your own email (Need login to Google account)")
	fl.BoolVar(&isReceive, "receive", false, "Receives all encrypted emails in your Gmail and decrypts them and saves them in text files (Need login to Google account)")
	fl.BoolVar(&keysOnly, "keys", false, "Generate all private and public keys for Alice and Bob and saves them in keys/ (Need to have a keys directory in root)")
	fl.BoolVar(&analysisOnly, "analysis", false, "Spins up a thread to measure the encryption time of RSA vs key length and another one to hopefully break the RSA private key")
	fl.Usage = func() {
		c := color.New(color.Bold)
		c.Println("NAME")
		fmt.Println("\tmailcrypt - a simple encryption / decryption for emails")
		c.Println("SYNOPSIS")
		fmt.Println("\tmailcrypt [options]")
		c.Println("DESCRIPTION")
		fmt.Println("\tThe mailcrypt program send an email from the file email.txt and lets the user to login to google\n\tand use the gmail account to send/receive emails")
		c.Println("OPTIONS")
		fmt.Println("\t-send - Sends the text in the file email.txt to your own email (Need login to Google account)")
		fmt.Println("\t-receive - Receives all encrypted emails in your Gmail and decrypts them and saves them in text files (Need login to Google account)")
		fmt.Println("\t-keysOnly - Generate all private and public keys for Alice and Bob and saves them in keys/ (Need to have a keys directory in root)")
		fmt.Println("\t-analysis - Spins up a thread to measure the encryption time of RSA vs key length and another one to hopefully break the RSA private key")
		os.Exit(0)
	}
}

func main() {
	fl.Parse()

	if analysisOnly {
		analysis.DoAnalysis()
		return
	}

	var enc string

	if isSend {
		enc = sender.SendMail(keysOnly)
	}

	if isSend && isReceive {
		println("Done sending and sleeping for 10 seconds to make sure msg is sent")
		time.Sleep(10 * time.Second)
	}

	if isReceive {
		receiver.ReceiveMail(keysOnly, enc)
	}

	if !isReceive && !isSend && !keysOnly && !analysisOnly {
		fl.PrintDefaults()
	}
}
