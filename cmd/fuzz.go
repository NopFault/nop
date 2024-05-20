package nop

import (
	"bufio"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

type Fuzz struct {
	where     string
	method    string
	redirect  bool
	ua        string
	random_ua bool
}

var fuzzCmd = &cobra.Command{
	Use:   "fuzz",
	Short: "Simple web fuzzer.",
	Run: func(cmd *cobra.Command, args []string) {
		urlInput, _ := cmd.Flags().GetString("url")
		method, _ := cmd.Flags().GetString("method")
		redirect, _ := cmd.Flags().GetBool("follow-redirect")
		// delay, _ := cmd.Flags().GetString("delay")
		statuses, _ := cmd.Flags().GetString("visible-statuses")
		ua, _ := cmd.Flags().GetString("ua")
		random_ua, _ := cmd.Flags().GetBool("random-ua")
		wordfile, _ := cmd.Flags().GetString("dict")
		inCodeFile, _ := cmd.Flags().GetString("in-code")

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

		domain, ips := getIP(urlInput)

		fmt.Printf("---------[ NOP ]---------\n - Start fuzz on %s [%s]\n\n", domain, ips)

		var wg sync.WaitGroup

		// Use a buffered channel to limit the number of concurrent goroutines
		const maxConcurrentGoroutines = 10
		semaphore := make(chan struct{}, maxConcurrentGoroutines)

		for wordScanner.Scan() {
			var word string = wordScanner.Text()

			if len(word) > 0 && string(word[0]) != "#" {
				var fuzzer Fuzz = Fuzz{
					where:     strings.Replace(urlInput, "[NOP]", word, -1),
					method:    method,
					redirect:  redirect,
					random_ua: random_ua,
					ua:        ua,
				}

				wg.Add(1)
				semaphore <- struct{}{}

				go func(fuzzer Fuzz) {
					startingTime := time.Now()
					status, bytes, hash := fuzzer.Contents()

					if len(statuses) > 0 {
						if len(strings.Split(statuses, strconv.Itoa(status))) >= 2 {
							fmt.Printf("\n- URL [%s]\n", strings.ReplaceAll(urlInput, "[NOP]", word))
							fmt.Printf("    %s: %s (%s)\n", strconv.Itoa(status), hash, strconv.Itoa(len(bytes)))
							fmt.Printf("    Time: %s\n", time.Since(startingTime))
						}
					} else {
						fmt.Printf("\n- URL [%s]\n", strings.ReplaceAll(urlInput, "[NOP]", word))
						fmt.Printf("    %s: %s (%s)\n", strconv.Itoa(status), hash, strconv.Itoa(len(bytes)))
						fmt.Printf("    Time: %s\n", time.Since(startingTime))
					}

					if len(inCodeFile) > 0 {
						codeList, err := os.Open(inCodeFile)
						if err != nil {
							fmt.Printf("\n\n[ERROR]: Cannot read code file: %s\n\n", inCodeFile)
							os.Exit(1)
						}
						codeScanner := bufio.NewScanner(codeList)
						codeScanner.Split(bufio.ScanLines)

						for codeScanner.Scan() {
							response := string(bytes[:])
							codeText := codeScanner.Text()
							if strings.Contains(response, codeText) {
								fmt.Printf("\n    - Found snippet: [%s]\n", codeText)
							}
						}

					}
					defer func() { <-semaphore }()
					defer wg.Done()
				}(fuzzer)

				go func() {
					wg.Wait()
				}()
				//if len(delay) > 0 {
				//	v, err := strconv.Atoi(delay)
				//	if err != nil {
				//		fmt.Printf("\n\n[ERROR]: Cannot convert delay: %s\n\n", delay)
				//		os.Exit(1)
				//	}
				//	if v > 0 {
				//		time.Sleep(time.Duration(v) * time.Second)
				//	}
				//}
			}

		}
	},
}

func getIP(urlInput string) (string, string) {
	url, err := url.Parse(urlInput)
	if err != nil {
		log.Fatal(err)
	}
	var ips []string
	var domain string = strings.TrimPrefix(url.Hostname(), "www.")

	netIP, _ := net.LookupIP(domain)
	for _, ip := range netIP {
		if ipv4 := ip.To4(); ipv4 != nil {
			ips = append(ips, ipv4.String())
		}
		if ipv6 := ip.To16(); ipv6 != nil {
			ips = append(ips, ipv6.String())
		}
	}
	return domain, strings.Join(ips, ", ")
}

func getRandomUA() string {
	var agents []string = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36",
		"Mozilla/5.0 (Windows NT 5.1; rv:7.0.1) Gecko/201:00101 Firefox/7.0.1",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36",
		"Mozilla/5.0 (iPad; CPU OS 9_3_2 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13F69 Safari/601.1",
		"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0)",
		"Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393",
		"Mozilla/5.0 (Windows NT 6.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393",
		"Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:41.0) Gecko/20100101 Firefox/41.0",
		"Mozilla/5.0 (Linux; Android 13; SM-A536B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 13; SM-A536U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 12; moto g power (2022)) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 10; VOG-L29) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 11; Redmi Note 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (iPhone14,6; U; CPU iPhone OS 15_4 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/19E241 Safari/602.1",
		"Mozilla/5.0 (iPhone14,3; U; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/19A346 Safari/602.1",
		"Mozilla/5.0 (iPhone13,2; U; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/15E148 Safari/602.1",
		"Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Microsoft; RM-1152) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Mobile Safari/537.36 Edge/15.15254",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9",
		"Mozilla/5.0 (PlayStation; PlayStation 5/2.26) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0 Safari/605.1.15",
		"Mozilla/5.0 (PlayStation 4 3.11) AppleWebKit/537.73 (KHTML, like Gecko)",
		"Mozilla/5.0 (PlayStation Vita 3.61) AppleWebKit/537.73 (KHTML, like Gecko) Silk/3.2",
		"Mozilla/5.0 (Windows Phone 10.0; Android 4.2.1; Xbox; Xbox One) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2486.0 Mobile Safari/537.36 Edge/13.10586",
		"Mozilla/5.0 (Linux; U; en-US) AppleWebKit/528.5+ (KHTML, like Gecko, Safari/528.5+) Version/4.0 Kindle/3.0 (screen 600x800; rotate)",
		"Mozilla/5.0 (iPhone12,1; U; CPU iPhone OS 13_0 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/15E148 Safari/602.1",
	}

	nth := rand.Int() % len(agents)
	return agents[nth]
}

func (f *Fuzz) Contents() (int, []byte, string) {
	req, err := http.NewRequest(f.method, f.where, nil)
	if err != nil {
		panic(err)
	}

	if f.random_ua == true {
		req.Header.Set("User-Agent", getRandomUA())
	} else {
		req.Header.Set("User-Agent", f.ua)
	}

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
	if f.redirect == false {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, []byte{}, ""
	}

	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)

	var hash string = ""
	if f.method != "HEAD" {
		hasher := md5.New()
		hasher.Write([]byte(b))
		hash = hex.EncodeToString(hasher.Sum(nil))
	}

	return resp.StatusCode, b, hash
}

func init() {
	rootCmd.AddCommand(fuzzCmd)

	fuzzCmd.PersistentFlags().String("url", "", "URL with pointer [NOP]")
	fuzzCmd.PersistentFlags().String("method", "", "GET, POST, HEAD...")
	fuzzCmd.PersistentFlags().String("ua", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:94.0) Gecko/20100101 Firefox/94.0", "Custom user agent")
	fuzzCmd.PersistentFlags().String("delay", "", "Add delay for each request")
	fuzzCmd.PersistentFlags().String("visible-statuses", "", "Show just specific statuses like: 200,500,403")
	fuzzCmd.PersistentFlags().Bool("follow-redirect", false, "Follow redirects like 301,302")
	fuzzCmd.PersistentFlags().String("dict", "", "Dictionary file")
	fuzzCmd.PersistentFlags().Bool("random-ua", false, "Dictionary file")
	fuzzCmd.PersistentFlags().String("in-code", "", "To search some data in code")

	fuzzCmd.MarkPersistentFlagRequired("url")
	fuzzCmd.MarkPersistentFlagRequired("dict")
	fuzzCmd.MarkPersistentFlagRequired("method")
}
