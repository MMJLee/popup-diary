package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const help = "help"
const prompt = "prompt"
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

var colors [12]string = [12]string{red, green, yellow, blue, magenta, cyan, bred, bgreen, byellow, bblue, bmagenta, bcyan}

var now time.Time = time.Now()
var times [11]time.Time = [11]time.Time{
	now.AddDate(0, 0, -18249),
	now.AddDate(0, 0, -14602),
	now.AddDate(0, 0, -7301),
	now.AddDate(0, 0, -3647),
	now.AddDate(0, 0, -1827),
	now.AddDate(0, 0, -1092),
	now.AddDate(0, 0, -728),
	now.AddDate(0, 0, -364),
	now.AddDate(0, 0, -28),
	now.AddDate(0, 0, -7),
	now.AddDate(0, 0, -1),
}

func main() {
	clearTerminal()
	pPrint("Popup-Diary - Enter your pass key\n", bwhite)
	pPrint("> ", bwhite+blink)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	passKey := strings.TrimSpace(scanner.Text())
	clearTerminal()

	start := verifyKey(passKey)
	if start.IsZero() {
		start = createKey(now, passKey)
	}

	// READ PAST ENTRIES
	pPrint("Popup-Diary\n", bwhite)
	for _, time := range times {
		if start.Before(time) {
			readTxt(time.Format("2006-01-02"), passKey)
		}
	}

	// READ TODAY'S ENTRY
	nowTime := now.Format("2006-01-02")
	b, _ := os.ReadFile(nowTime + ".txt")
	printFile(calcHeader(now, nowTime), b, passKey)

	// OPEN TODAY'S ENTRY
	file, err := os.OpenFile(nowTime+".txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Panicf("main: error opening today's txt: %v", err)
	}
	defer file.Close()

	absRegex := regexp.MustCompile(`^[0-9]{4}[-][0-9]{2}[-][0-9]{2}$`) // YYYY-MM-DD
	relRegex := regexp.MustCompile(`^([0-9]{1,}[dwmyDWMY])+$`)         // #Yy#Mm#Ww#Dd
	for {
		now = time.Now()
		pPrint("> ", blink)
		scanner.Scan()
		message := scanner.Text()

		if strings.TrimSpace(message) == "" { // EXIT
			break
		} else if strings.ToLower(message) == help { // GET HELP
			printHelp()
		} else if strings.ToLower(message) == prompt { // GET RANDOM PROMPT
			var prompt string
			for {
				prompt = getPrompt()
				pPrint("[ PROMPT ] "+prompt+"\n", bwhite)
				pPrint("(Enter for a new prompt)\n", bwhite)
				pPrint("> ", blink)
				scanner.Scan()
				message := scanner.Text()
				if strings.TrimSpace(message) != "" {
					writePromptToFile(file, prompt, passKey)
					writeEntryToFile(file, message, passKey)
					break
				}
			}
		} else if absRegex.MatchString(message) { // GET ENTRY BY ABSOLUTE TIME
			readTxt(message, passKey)
		} else if relRegex.MatchString(message) { // GET ENTRY BY RELATIVE TIME
			t := parseToken(now, message).Format("2006-01-02")
			readTxt(t, passKey)
		} else {
			writeEntryToFile(file, message, passKey)
		}
	}
	os.Exit(0)
}

func writeEntryToFile(file *os.File, message string, passKey string) {
	writeToFile(file, time.Now().Format("[03:04 PM] ")+message, passKey)
}
func writePromptToFile(file *os.File, message string, passKey string) {
	writeToFile(file, "[ PROMPT ] "+message, passKey)
}
func writeToFile(file *os.File, message string, passKey string) {
	es := encryptString(message, passKey)
	if _, err := file.WriteString(es + "\n"); err != nil {
		log.Panicf("writeToFile: error writing to file: %v", err)
	}
}

func printFile(header string, content []byte, passKey string) {
	pPrint(header, colors[rand.Intn(len(colors))])
	for _, line := range strings.Split(string(content), "\n") {
		ds := decryptString(line, passKey)
		if ds != "" && ds[0:1] != "[" && ds[10:11] != "]" {
			log.Panic("printFile: wrong decryption")
		}
		index := strings.Index(ds, "]") + 1
		pPrint(ds[:index], grey)
		pPrint(ds[index:]+"\n", white)
	}
}
func readTxt(fileName string, passKey string) {
	b, err := os.ReadFile(fileName + ".txt")
	if err != nil {
		log.Panicf("readTxt: error reading txt file: %v", err)
	}
	printFile(calcHeader(now, fileName), b, passKey)
}

func parseToken(now time.Time, tokenStr string) time.Time {
	r := regexp.MustCompile(`([0-9]{1,})([dwmyDWMY])`)
	matches := r.FindAllString(tokenStr, -1)
	years, months, days := 0, 0, 0
	for _, token := range matches {
		unit := token[len(token)-1:]
		qty, err := strconv.Atoi(token[:len(token)-1])
		if err != nil {
			log.Panicf("parseToken: error parsing quantity: %v", err)
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

func calcHeader(now time.Time, dateStr string) string {
	then, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		log.Panicf("calcHeader: error parsing time string: %v", err)
	}
	days := int(now.Sub(then).Hours() / 24)
	var token string
	switch {
	case days == 0:
		token = "TODAY"
	case days%365 <= 1:
		token = strconv.Itoa(days/365) + "Y"
	case days%30 <= 1:
		token = strconv.Itoa(days/30) + "M"
	case days%7 <= 1:
		token = strconv.Itoa(days/7) + "W"
	default:
		token = strconv.Itoa(days) + "D"
	}
	return then.Weekday().String()[0:3] + " " + dateStr + " (" + token + ")\n"
}

func clearTerminal() {
	var cmd *exec.Cmd
	switch myOS := runtime.GOOS; myOS {
	case "darwin":
		log.Panic("clearTerminal: unsupported OS")
	case "linux":
		cmd = exec.Command("clear")
	default:
		cmd = exec.Command("cmd", "/c", "cls")
	}
	cmd.Stdout = os.Stdout
	cmd.Run()
}

func createKey(now time.Time, passKey string) time.Time {
	file, err := os.OpenFile("start.txt", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Panicf("createKey: error opening start.txt: %v", err)
	}
	defer file.Close()
	es := encryptString(now.Format("2006-01-02"), passKey)
	if _, err = file.WriteString(es + "\n"); err != nil {
		log.Panicf("createKey: error writing to file: %v", err)
	}
	return now
}

func verifyKey(passKey string) time.Time {
	b, err := os.ReadFile("start.txt")
	if err != nil {
		log.Panicf("verifyKey: error reading start.txt: %v", err)
	}
	ds := decryptString(string(b), passKey)
	absRegex := regexp.MustCompile(`^[0-9]{4}[-][0-9]{2}[-][0-9]{2}$`) // YYYY-MM-DD
	if absRegex.MatchString(ds) {
		then, err := time.Parse("2006-01-02", string(ds))
		if err != nil {
			log.Panicf("verifyKey: error parsing key time: %v", err)
		}
		return then
	} else {
		log.Panic("verifyKey: error matching key time")
	}
	return time.Time{}
}

func encryptString(str string, key string) string {
	block, err := aes.NewCipher(hashTo32Bytes(key))
	if err != nil {
		log.Panicf("encryptString: error creating cipher: %v", err)
	}
	// create two 'windows' in to the output slice.
	output := make([]byte, aes.BlockSize+len([]byte(str)))
	iv := output[:aes.BlockSize]
	encrypted := output[aes.BlockSize:]
	// populate the IV slice with random data.
	if _, err = io.ReadFull(crand.Reader, iv); err != nil {
		log.Panicf("encryptString: error reading random data: %v", err)
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	// note that encrypted is still a window in to the output slice
	stream.XORKeyStream(encrypted, []byte(str))
	return base64.URLEncoding.EncodeToString(output)
}

func decryptString(str string, key string) string {
	encrypted, err := base64.URLEncoding.DecodeString(str)
	if err != nil {
		log.Panicf("decryptString: error decoding string: %v", err)
	}
	if len(encrypted) < aes.BlockSize {
		return ""
	}
	iv := encrypted[:aes.BlockSize]
	encrypted = encrypted[aes.BlockSize:]

	block, err := aes.NewCipher(hashTo32Bytes(key))
	if err != nil {
		log.Panicf("decryptString: error creating cipher: %v", err)
	}
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(encrypted, encrypted)
	return string(encrypted)
}

func hashTo32Bytes(input string) []byte {
	data := sha256.Sum256([]byte(input))
	return data[0:]
}

func pPrint(text string, color string) {
	fmt.Print(color + text + reset)
}

func printHelp() {
	pPrint("\nPress enter on a new line to exit", bwhite)
	pPrint("\nYYYY-MM-DD ex: 2024-04-20 for absolute search", bwhite)
	pPrint("\n##dD/wW/mM/yY ex: 24D, 3M for relative search", bwhite)
	pPrint("\nRelative searchs can be chained ex: 2W2D, evaluated left to right", bwhite)
	pPrint("\nPrompt to get a prompt to write about", bwhite)
	pPrint("\nDelete all text files in directory to restart your diary\n", bwhite)
}

func getPrompt() string {
	var prompts = []string{
		"What are three things that made you smile today?",
		"What is a challenge you faced this week and how did you overcome it?",
		"What is a goal you have for the next month?",
		"Write about a time you felt proud of yourself.",
		"What is something you are looking forward to?",
		"What is a lesson you learned this year?",
		"Write about a person who has inspired you.",
		"What is a quality you admire in others?",
		"What is a quality you admire in yourself?",
		"What is something you wish you had done differently?",
		"Write about a place that holds special meaning to you.",
		"What is a book or movie that has impacted you?",
		"What is a risk you took and what was the outcome?",
		"Write about a time you felt grateful.",
		"What is a skill you want to learn?",
		"What is a memory that makes you happy?",
		"Write about a time you felt brave.",
		"What is a tradition you enjoy?",
		"What is a hobby you enjoy?",
		"Write about a time you felt calm and at peace.",
	}
	return prompts[rand.Intn(len(prompts))]
}
