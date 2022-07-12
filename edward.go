package main

import (
	"bytes"
	"crypto/rand"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"git.tcp.direct/kayos/common/entropy"
	"github.com/gen2brain/beeep"
	"github.com/mikesmitty/edkey"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
)

var (
	regex           string
	caseInsensitive bool
	keepGoing       bool
)
var (
	// var flagvar int
	globalCounter   int64
	start           time.Time
	re              *regexp.Regexp
	err             error
	mustHaveAllArgs bool
	mustHaveOneArg  bool
	args            []string
)

func init() {
	//	flag.IntVar(&flagvar, "flagname", 1234, "put an integer here")
	flag.StringVar(&regex, "regex", "", "regex pattern goes here")
	flag.BoolVar(&caseInsensitive, "i", false, "case-insensitive")
	flag.BoolVar(&keepGoing, "k", false, "Keep processing keys, even after a match")
	flag.BoolVar(&mustHaveAllArgs, "args", false, "must have all arguments as case insensitve string matches anywhere in the key")
	flag.BoolVar(&mustHaveOneArg, "arg", false, "must have one argument from list as case insensitve string matches anywhere in the key")

	flag.Parse()
	args = flag.Args()
	println(strings.Join(args, ","))

	start = time.Now()

	if !caseInsensitive {
		println("Case-sensitive: \x1b[32mYES\x1b[0m")
		re, err = regexp.Compile(regex)
	} else {
		println("Case-sensitive: \x1b[31mNO\x1b[0m")
		re, err = regexp.Compile("(?i)" + regex)
	}
	if keepGoing {
		println("Keep Going: \x1b[32mYES\x1b[0m")
	} else {
		println("Keep Going: \x1b[31mNO\x1b[0m")
	}

	if err != nil {
		os.Exit(1)
	}
}

func WaitForCtrlC() chan struct{} {
	var endWaiter sync.WaitGroup
	endWaiter.Add(1)
	var signalChannel chan os.Signal
	signalChannel = make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt)
	go func() {
		<-signalChannel
		endWaiter.Done()
	}()
	finChan := make(chan struct{})
	go func() {
		endWaiter.Wait()
		finChan <- struct{}{}
	}()
	return finChan
}

func prettyPrint(searchCandidate string, arg string, authorizedKey []byte) {
	var (
		foundPtr   = 0
		foundStart = 0
		foundEnd   = 0
	)
	for pos, char := range []byte(searchCandidate) {
		if foundPtr == -1 {
			continue
		}
		if char == []byte(arg)[foundPtr] && foundEnd == 0 {
			foundPtr++
			if foundPtr == 1 {
				foundStart = pos
			}
			if foundPtr == len(arg) {
				foundEnd = pos
				foundPtr = -1
			}
		} else {
			foundPtr = 0
			foundEnd = 0
		}
	}
	var newStr string
	var capped = false
	for n, a := range bytes.Split(authorizedKey, nil) {
		switch {
		case n == foundStart-1:
			newStr += string(a)
			newStr += "\x1b[32m"
		case n == foundEnd+1:
			newStr += "\x1b[0m"
			newStr += string(a)
			capped = true
		default:
			newStr += string(a)
		}
		// fallback if we didn't find the end of the needle for some reason
		if !capped && n == len(authorizedKey)-1 {
			newStr += "\x1b[0m"
		}
	}
	println(newStr + "\n")
}

func alert(hit string) {
	err = beeep.Notify("Vanity SSH", "found key for: "+hit,
		"/usr/share/icons/gnome/32x32/emblems/emblem-new.png")
	if err != nil {
		println("\x1b[31mError\u001B[0m: " + err.Error())
	}
}

func validate(searchCandidate string, privateKey []byte, authorizedKey []byte) bool {
	oneTime := &sync.Once{}
	switch {
	case mustHaveAllArgs:
		var sullied = false
		for _, arg := range args {
			if caseInsensitive {
				arg = strings.ToLower(arg)
			}
			if !strings.Contains(searchCandidate, arg) {
				sullied = true
				break
			}
		}
		if !sullied {
			alert(args[0])
			for _, ar := range args {
				println("\n\x1b[32mFOUND\x1b[0m: " + ar + "\n")
				prettyPrint(searchCandidate, ar, authorizedKey)
			}
			chooseKey(privateKey, authorizedKey, args[0]+"-plus-more")
			return true
		}
	case mustHaveOneArg:
		for _, arg := range args {
			if caseInsensitive {
				arg = strings.ToLower(arg)
			}
			if strings.Contains(searchCandidate, arg) {
				println("\n\x1b[32mFOUND\x1b[0m: " + arg + "\n")
				prettyPrint(searchCandidate, arg, authorizedKey)
				oneTime.Do(func() {
					alert(arg)
					chooseKey(privateKey, authorizedKey, arg)
				})
			}
		}
		return true
	case re.Match(authorizedKey):
		alert(regex)
		println("\n\x1b[32mFOUND\x1b[0m: " + regex + "\n")
		chooseKey(privateKey, authorizedKey, "regex")
		return true
	default:
		return false
	}
	return false
}

func chooseKey(privateKey ed25519.PrivateKey, authorizedKey []byte, winningNeedle string) {
	fmt.Printf("\033[2K\r%s%d", "SSH Keys Processed = ", globalCounter)
	fmt.Println("\nTotal execution time", time.Since(start))
	fmt.Printf("%s\n", privateKey)
	fmt.Printf("%s\n", authorizedKey)
	_ = os.Mkdir(winningNeedle, 0755)
	token := entropy.RandStr(5)
	_ = ioutil.WriteFile("keys/"+winningNeedle+"/id_"+token, privateKey, 0600)
	_ = ioutil.WriteFile("keys/"+winningNeedle+"/id_"+token+".pub", authorizedKey, 0644)
	if keepGoing == false {
		os.Exit(0)
	}
}

func findsshkeys() {
	for {
		globalCounter++
		pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
		publicKey, _ := ssh.NewPublicKey(pubKey)
		pemKey := &pem.Block{
			Type:  "OPENSSH PRIVATE KEY",
			Bytes: edkey.MarshalED25519PrivateKey(privKey),
		}
		privateKey := pem.EncodeToMemory(pemKey)
		authorizedKey := ssh.MarshalAuthorizedKey(publicKey)
		authorizedKey = bytes.Trim(authorizedKey, "\n") // Trim newline
		searchCandidate := string(authorizedKey)
		if caseInsensitive {
			searchCandidate = strings.ToLower(string(authorizedKey))
		}
		validate(searchCandidate, privateKey, authorizedKey)
	}
}

func main() {
	for i := 1; i <= runtime.NumCPU(); i++ {
		go findsshkeys()
	}

	fmt.Printf("Press Ctrl+C to end\n")
	finChan := WaitForCtrlC()
waitLoop:
	for {
		select {
		case <-finChan:
			break waitLoop
		default:
			fmt.Printf("\033[2K\r%s%d", "SSH Keys Processed = ", globalCounter)
			time.Sleep(250 * time.Millisecond)
		}
	}
	println("fin.")
}
