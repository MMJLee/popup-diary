package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const reset = "\033[0m"
const blink = "\033[6m"
const red = "\033[31m"
const green = "\033[32m"
const yellow = "\033[33m"
const blue = "\033[33m"
const magenta = "\033[35m"
const cyan = "\033[36m"
const white = "\033[37m"
const grey = "\033[90m"
const bred = "\033[91m"
const bgreen = "\033[92m"
const byellow = "\033[93m"
const bblue = "\033[94m"
const bmagenta = "\033[95m"
const bcyan = "\033[96m"
const bwhite = "\033[97m"

type Entry struct {
	day  string
	time time.Time
}

func main() {
	now := time.Now()

	clearTerminal()
	pPrint("Popup-Diary - please enter your pass key\n", bwhite+blink)
	pPrint("> ", bwhite+blink)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	passKey := strings.TrimSpace(scanner.Text())
	clearTerminal()

	start := verifyKey(passKey)
	if start.IsZero() {
		createKey(now, passKey)
		start = now
	}

	entries := setupEntries(now)
	colors := [12]string{red, green, yellow, blue, magenta, cyan, bred, bgreen, byellow, bblue, bmagenta, bcyan}

	// READ PAST ENTRIES
	pPrint("Popup-Diary", bwhite+blink)
	for i, entry := range entries {
		if start.Before(entry.time) {
			randomIndex, err := rand.Int(rand.Reader, big.NewInt(12))
			if err != nil {
				log.Fatalf("Error creating random int: %v", err)
			}
			entryTime := entry.time.Format("2006-01-02")
			if b, err := os.ReadFile(entryTime + ".txt"); err == nil {
				pPrint("\n"+entryTime+" ("+entry.day+")\n", colors[randomIndex.Int64()])
				for _, line := range strings.Split(string(b), "\n") {
					if ds, err := decryptString(line, passKey); err == nil {
						printLine(ds)
					}
				}
			} else {
				if i == 11 {
					pPrint(entryTime+" ("+entry.day+")\n", colors[randomIndex.Int64()])
				}
			}
		}
	}

	// OPEN TODAY'S ENTRY
	file, err := os.OpenFile(now.Format("2006-01-02")+".txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer file.Close()

	absRegex := regexp.MustCompile(`^[0-9]{4}[-][0-9]{2}[-][0-9]{2}$`) // YYYY-MM-DD
	relRegex := regexp.MustCompile(`^([0-9]{1,}[dwmyDWMY])+$`)         // #Yy#Mm#Ww#Dd
	for {
		randomIndex, err := rand.Int(rand.Reader, big.NewInt(12))
		if err != nil {
			log.Fatalf("Error creating random int: %v", err)
		}
		now = time.Now()
		msgTime := now.Format("[3:04 PM] ")
		pPrint(msgTime, blink)

		scanner.Scan()
		message := scanner.Text()
		if strings.TrimSpace(message) == "" {
			break
		} else if strings.ToUpper(message) == "HELP" {
			pPrint("\nenter on a new line to exit", bwhite)
			pPrint("\nYYYY-MM-DD ex: 2024-04-20 for absolute search", bwhite)
			pPrint("\n##dD/wW/mM/yY ex: 24D, 3M for relative search", bwhite)
			pPrint("\nrelative search can be chained ex: 2W2D, evaluated left to right", bwhite)
			pPrint("\ndelete all text files in directory to restart your diary\n", bwhite)
		} else if absRegex.MatchString(message) { // GET ENTRY BY ABSOLUTE TIME
			t := calculateTimeToken(now, message)
			if b, err := os.ReadFile(message + ".txt"); err == nil {
				pPrint("\n"+message+" ("+t+")\n", colors[randomIndex.Int64()])
				lines := strings.Split(string(b), "\n")
				for _, line := range lines {
					if ds, err := decryptString(line, passKey); err == nil {
						printLine(ds)
					}
				}
			}
		} else if relRegex.MatchString(message) { // GET ENTRY BY RELATIVE TIME
			t := parseTimeToken(now, message).Format("2006-01-02")
			if b, err := os.ReadFile(t + ".txt"); err == nil {
				pPrint("\n"+t+" ("+strings.ToUpper(message)+")\n", colors[randomIndex.Int64()])
				for _, line := range strings.Split(string(b), "\n") {
					if ds, err := decryptString(line, passKey); err == nil {
						printLine(ds)
					}
				}
			}
		} else if eb, err := encryptString(msgTime+message, passKey); err == nil { // WRITE TO FILE
			if _, err = file.WriteString(eb + "\n"); err != nil {
				log.Fatalf("Error writing to file: %v", err)
			}
		}
	}
	os.Exit(0)
}

func clearTerminal() {
	var cmd *exec.Cmd
	switch myOS := runtime.GOOS; myOS {
	case "darwin":
		os.Exit(1)
	case "linux":
		cmd = exec.Command("clear")
	default:
		cmd = exec.Command("cmd", "/c", "cls")
	}
	cmd.Stdout = os.Stdout
	cmd.Run()
}

func setupEntries(now time.Time) [12]Entry {
	today := Entry{"TODAY", now}
	yesterday := Entry{"1D", now.AddDate(0, 0, -1)}
	oneWeekAgo := Entry{"1W", now.AddDate(0, 0, -7)}
	oneMonthAgo := Entry{"1M", now.AddDate(0, 0, -28)}
	oneYearAgo := Entry{"1Y", now.AddDate(0, 0, -364)}
	twoYearsAgo := Entry{"2Y", now.AddDate(0, 0, -728)}
	threeYearsAgo := Entry{"3Y", now.AddDate(0, 0, -1092)}
	fiveYearsAgo := Entry{"5Y", now.AddDate(0, 0, -1827)}
	tenYearsAgo := Entry{"10Y", now.AddDate(0, 0, -3647)}
	twentyYearsAgo := Entry{"20Y", now.AddDate(0, 0, -7301)}
	thirtyYearsAgo := Entry{"30Y", now.AddDate(0, 0, -14602)}
	fiftyYearsAgo := Entry{"50Y", now.AddDate(0, 0, -18249)}
	return [12]Entry{fiftyYearsAgo, thirtyYearsAgo, twentyYearsAgo, tenYearsAgo, fiveYearsAgo, threeYearsAgo, twoYearsAgo, oneYearAgo, oneMonthAgo, oneWeekAgo, yesterday, today}
}

func createKey(now time.Time, passKey string) {
	file, err := os.OpenFile("start.txt", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer file.Close()
	if eb, err := encryptString(now.Format("2006-01-02"), passKey); err == nil { // WRITE TO FILE
		if _, err = file.WriteString(eb + "\n"); err != nil {
			log.Fatalf("Error writing to file: %v", err)
		}
	}
}

func verifyKey(passKey string) time.Time {
	if b, err := os.ReadFile("start.txt"); err == nil {
		if ds, err := decryptString(string(b), passKey); err == nil {
			absRegex := regexp.MustCompile(`^[0-9]{4}[-][0-9]{2}[-][0-9]{2}$`) // YYYY-MM-DD
			if absRegex.MatchString(ds) {
				then, err := time.Parse("2006-01-02", string(ds))
				if err != nil {
					log.Fatalf("Error parsing start time: %v", err)
				}
				return then
			}
		}
		os.Exit(1)
	}
	return time.Time{}
}

func decryptString(cryptoText string, keyString string) (plainTextString string, err error) {
	encrypted, err := base64.URLEncoding.DecodeString(cryptoText)
	if err != nil {
		return "", err
	}
	if len(encrypted) < aes.BlockSize {
		return "", fmt.Errorf("cipherText too short. It decodes to %v bytes but the minimum length is 16", len(encrypted))
	}
	decrypted, err := decryptAES(hashTo32Bytes(keyString), encrypted)
	if err != nil {
		return "", err
	}
	decryptedStr := string(decrypted)
	if decryptedStr[0:1] != "[" && decryptedStr[0:1] != "2" {
		os.Exit(1)
	}
	return decryptedStr, nil
}

func decryptAES(key, data []byte) ([]byte, error) {
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(data, data)
	return data, nil
}

func encryptString(plainText string, keyString string) (cipherTextString string, err error) {
	key := hashTo32Bytes(keyString)
	encrypted, err := encryptAES(key, []byte(plainText))
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(encrypted), nil
}

func encryptAES(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// create two 'windows' in to the output slice.
	output := make([]byte, aes.BlockSize+len(data))
	iv := output[:aes.BlockSize]
	encrypted := output[aes.BlockSize:]
	// populate the IV slice with random data.
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	// note that encrypted is still a window in to the output slice
	stream.XORKeyStream(encrypted, data)
	return output, nil
}

func hashTo32Bytes(input string) []byte {
	data := sha256.Sum256([]byte(input))
	return data[0:]
}

func parseTimeToken(now time.Time, tokenStr string) time.Time {
	r := regexp.MustCompile(`([0-9]{1,})([dwmyDWMY])`)
	matches := r.FindAllString(tokenStr, -1)
	years, months, days := 0, 0, 0
	for _, token := range matches {
		unit := token[len(token)-1:]
		qty, err := strconv.Atoi(token[:len(token)-1])
		if err != nil {
			log.Fatalf("Error parsing time token: %v", err)
		}
		switch unit {
		case "Y", "y":
			years -= qty
		case "M", "m":
			months -= qty
		case "W", "w":
			days -= 7 * qty
		case "D", "d":
			days -= qty
		}
	}
	return now.AddDate(years, months, days)
}

func calculateTimeToken(now time.Time, dateStr string) string {
	then, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		log.Fatalf("Error calculating time token: %v", err)
	}
	days := int(now.Sub(then).Hours() / 24)
	switch {
	case days%365 < 1:
		return strconv.Itoa(days/365) + "Y"
	case days%30 < 1:
		return strconv.Itoa(days/30) + "M"
	case days%7 < 1:
		return strconv.Itoa(days/7) + "W"
	default:
		return strconv.Itoa(days) + "D"
	}
}

func printLine(line string) {
	index := strings.Index(line, "]") + 1
	pPrint(line[:index], grey)
	pPrint(line[index:]+"\n", white)
}

func pPrint(text string, color string) {
	fmt.Print(color + text + reset)
}
