// autocollect.go - a simple command line tool to collect all autocrypt
// keys from a mailbox full of messages.
//
// jum@anubis.han.de

package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"

	"golang.org/x/crypto/openpgp/armor"

	"github.com/bytbox/go-mail"
	"github.com/luksen/maildir"
)

var (
	mbox    = flag.String("mbox", "", "mailbox to read")
	mailDir = flag.String("maildir", "", "maildir to read")
)

const DEBUG = false

func debug(format string, a ...interface{}) {
	if DEBUG {
		fmt.Printf(format, a...)
	}
}

func main() {
	var (
		mb  []mail.Message
		err error
	)
	flag.Parse()
	debug("mbox %v\n", *mbox)
	debug("maildir %v\n", *mailDir)
	if len(*mbox) > 0 {
		mb, err = ReadMboxFile(*mbox)
		if err != nil {
			panic(err)
		}
	}
	if len(*mailDir) > 0 {
		mb, err = ReadMaildir(maildir.Dir(*mailDir))
		if err != nil {
			panic(err)
		}
	}
	//debug("mb %#v\n", mb)
	keys := make(map[string][]byte)
	for _, m := range mb {
		h := autocryptHeader(&m)
		if h != nil {
			//debug("autocrypt %v\n", h.Value)
			f := parseAutoCryptHeader(h.Value)
			//debug("fields %v\n", f)
			//debug("addr: %v\n", f["addr"])
			//debug("keydata: \"%v\"\n", f["keydata"])
			blob, err := base64.RawStdEncoding.DecodeString(f["keydata"])
			if err != nil {
				panic(err)
			}
			keys[f["addr"]] = blob
		}
	}
	debug("keys %#v\n", keys)
	if len(keys) > 0 {
		w, err := armor.Encode(os.Stdout, "PGP PUBLIC KEY BLOCK", nil)
		if err != nil {
			panic(err)
		}
		for _, v := range keys {
			_, err = w.Write(v)
			if err != nil {
				panic(err)
			}
		}
		err = w.Close()
		if err != nil {
			panic(err)
		}
		os.Stdout.Write([]byte{'\n'})
	}
}

func autocryptHeader(m *mail.Message) *mail.Header {
	for _, h := range m.HeaderInfo.FullHeaders {
		if strings.ToLower(h.Key) == "autocrypt" {
			return &h
		}
	}
	return nil
}

var newlineRegex = regexp.MustCompile(`\n\s*`)

func parseAutoCryptHeader(v string) map[string]string {
	ret := make(map[string]string)
	s := newlineRegex.ReplaceAllString(v, "")
	for _, f := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ';'
	}) {
		pair := strings.FieldsFunc(strings.TrimSpace(f), func(r rune) bool {
			return r == '='
		})
		//debug("pairs %#v\n", pair)
		if len(pair) == 2 {
			ret[pair[0]] = pair[1]
		}
	}
	return ret
}
