package nop

import (
	"bufio"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type Fuzz struct {
	where    string
	method   string
	redirect string
	ua       string
}

var fuzzCmd = &cobra.Command{
	Use:   "fuzz",
	Short: "Simple web fuzzer.",
	Run: func(cmd *cobra.Command, args []string) {
		url, _ := cmd.Flags().GetString("url")
		method, _ := cmd.Flags().GetString("method")
		redirect, _ := cmd.Flags().GetString("follow-redirect")
		delay, _ := cmd.Flags().GetString("delay")
		statuses, _ := cmd.Flags().GetString("visible-statuses")
		ua, _ := cmd.Flags().GetString("ua")
		wordfile, _ := cmd.Flags().GetString("dict")

		wordlist, err := os.Open(wordfile)
		if err != nil {
			fmt.Printf("\n\n[ERROR]: Cannot read word file: %s\n\n", wordfile)
			os.Exit(1)
		}

		wordScanner := bufio.NewScanner(wordlist)
		wordScanner.Split(bufio.ScanLines)

		// Default user agent
		if len(ua) >= 0 {
			ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:94.0) Gecko/20100101 Firefox/94.0"
		}

		for wordScanner.Scan() {
			var word string = wordScanner.Text()

			if len(word) > 0 && string(word[0]) != "#" {
				var fuzzer Fuzz = Fuzz{
					where:    strings.Replace(url, "[NOP]", word, -1),
					method:   method,
					redirect: redirect,
					ua:       ua,
				}

				status, bytes, hash := fuzzer.Contents()

				if len(statuses) > 0 {
					if len(strings.Split(statuses, strconv.Itoa(status))) >= 2 {
						fmt.Printf("- URL [%s]\n", strings.Replace(url, "[NOP]", word, -1))
						fmt.Printf("    %s: %s (%s)\n\n", strconv.Itoa(status), hash, strconv.Itoa(bytes))
					}
				} else {
					fmt.Printf("- URL [%s]\n", strings.Replace(url, "[NOP]", word, -1))
					fmt.Printf("    %s: %s (%s)\n\n", strconv.Itoa(status), hash, strconv.Itoa(bytes))
				}

				if len(delay) > 0 {
					v, err := strconv.Atoi(delay)
					if err != nil {
						fmt.Printf("\n\n[ERROR]: Cannot convert delay: %s\n\n", delay)
						os.Exit(1)
					}
					if v > 0 {
						time.Sleep(time.Duration(v) * time.Second)
					}
				}
			}

		}
	},
}

func (f *Fuzz) Contents() (int, int, string) {
	req, err := http.NewRequest(f.method, f.where, nil)
	if err != nil {
		panic(err)
	}
	req.Header.Set("User-Agent", f.ua)

	// to prevent EOF
	req.Close = true
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.ExpectContinueTimeout = 10 * time.Second
	tr.DisableKeepAlives = true
	tr.IdleConnTimeout = 10 * time.Second
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	var client *http.Client = &http.Client{}

	client.Timeout = 10 * time.Second
	client.Transport = tr
	if f.redirect == "false" {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, ""
	}

	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	bytes := len(b)

	var hash string = ""
	if f.method != "HEAD" {
		hasher := md5.New()
		hasher.Write([]byte(b))
		hash = hex.EncodeToString(hasher.Sum(nil))
	}

	return resp.StatusCode, bytes, hash
}

func init() {
	rootCmd.AddCommand(fuzzCmd)

	fuzzCmd.PersistentFlags().String("url", "", "URL with pointer [NOP]")
	fuzzCmd.PersistentFlags().String("method", "", "GET, POST, HEAD...")
	fuzzCmd.PersistentFlags().String("ua", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:94.0) Gecko/20100101 Firefox/94.0", "Custom user agent")
	fuzzCmd.PersistentFlags().String("delay", "", "Add delay for each request")
	fuzzCmd.PersistentFlags().String("visible-statuses", "", "Show just specific statuses like: 200,500,403")
	fuzzCmd.PersistentFlags().String("follow-redirect", "false", "Follow redirects like 301,302")
	fuzzCmd.PersistentFlags().String("dict", "", "Dictionary file")

	fuzzCmd.MarkPersistentFlagRequired("url")
	fuzzCmd.MarkPersistentFlagRequired("dict")
	fuzzCmd.MarkPersistentFlagRequired("method")
}
