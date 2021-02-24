// ==============================================================
// Copyright 2020 FireEye, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
// ==============================================================

package goauditparser

import (
	"bufio"
	b64 "encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sbwhitecap/tqdm"
	. "github.com/sbwhitecap/tqdm/iterators"
)

const version string = "1.0.0"

type ThreadReturn_Parse struct {
	threadnum int
	xmlfile   string
	xmlsize   int64
	message   string
}

type RowValue struct {
	colid int
	value string
}

func GoAuditParser_Start(options Options) {

	// Get input files
	input_st, err_st := os.Stat(options.InputPath)
	var files []os.FileInfo
	// Check if input is a single existing file
	if !os.IsNotExist(err_st) && !input_st.IsDir() {
		files = []os.FileInfo{input_st}
		options.InputPath = filepath.Dir(options.InputPath)
		// Read Input Directory
	} else {
		dirfiles, err_r := ioutil.ReadDir(options.InputPath)

		if err_r != nil {
			fmt.Println(options.Warnbox + "ERROR - Could not read input as an existing file or directory '" + options.InputPath + "'.")
			log.Fatal(err_r)
		}

		if len(dirfiles) == 0 {
			fmt.Println(options.Warnbox + "ERROR - No files found in input directory '" + options.InputPath + "'.")
			return
		}

		// Ingest split files too
		splitfiles, err_r2 := ioutil.ReadDir(filepath.Join(options.InputPath, "xmlsplit"))
		if err_r2 == nil {
			files = append(files, splitfiles...)
		}

		files = dirfiles
	}

	//Remove directories
	for i := 0; i < len(files); i++ {
		if files[i].IsDir() {
			files = append(files[0:i], files[i+1:len(files)]...)
			i--
		}
	}

	//Check for JSON Config File
	inputConfigFile := filepath.Join(options.InputPath, "_GAPParseCache.json")
	if options.Verbose > 0 {
		fmt.Println(options.Box + "Reading the parse config file '" + inputConfigFile + "'...")
	}
	fi, err_s := os.Stat(inputConfigFile)
	//If config file exists, create the file
	if os.IsNotExist(err_s) || fi.Size() == 0 {
		//Create config file
		if options.Verbose > 0 {
			fmt.Println(options.Warnbox + "NOTICE - Parse config file '" + inputConfigFile + "' does not exist or is empty. Creating new one...")
		}
		file, err_c := os.Create(inputConfigFile)
		if err_c != nil {
			fmt.Println(options.Box + "ERROR - Could not create the parse config file '" + inputConfigFile + "'")
			log.Fatal(err_c)
		}
		n := Parse_Config_JSON{}
		n.Version = version
		b, _ := json.Marshal(n)
		file.Write(b)
		file.Close()
	}
	//Read JSON from config file
	file, err_o := os.Open(inputConfigFile)
	if err_o != nil {
		fmt.Println(options.Warnbox + "ERROR - Could not open the parse config file '" + inputConfigFile + "'")
		log.Fatal(err_o)
	}
	b, err_i := ioutil.ReadAll(file)
	if err_i != nil {
		fmt.Println(options.Warnbox + "ERROR - Could not read contents from the parse config file '" + inputConfigFile + "'.")
		log.Fatal(err_i)
	}
	var config Parse_Config_JSON
	err_j := json.Unmarshal(b, &config)
	if err_j != nil {
		fmt.Println(options.Warnbox + "ERROR - Could not parse JSON from parse config file '" + inputConfigFile + "'. Please fix or delete the file and try again.")
		log.Fatal(err_j)
	}
	file.Close()
	if config.Version != version {
		fmt.Println(options.Box + "Updating old parse config file from v" + config.Version + " to v" + version + "...")
		//Write new JSON to file
		newFile, err_c := os.Create(inputConfigFile)
		config.Version = version
		if err_c != nil {
			fmt.Println(options.Warnbox + "ERROR - Could not create new version of the parse config file '" + inputConfigFile + "'.")
			log.Fatal(err_c)
		}
		b, _ := json.Marshal(config)
		file.Write(b)
		newFile.Close()
	}

	absOutputPath, err_a := filepath.Abs(options.OutputPath)
	if err_a != nil {
		fmt.Println(options.Warnbox + "ERROR - Could not get absolute file path for '" + options.OutputPath + "'.")
		log.Fatal(err_a)
	}
	var configOutDirIndex int
	config, configOutDirIndex = InputConfig_GetOutDirIndex(absOutputPath, config)

	c_Success := 0
	c_Cached := 0
	c_Failed := 0
	c_Empty := 0
	c_Issues := 0

	//Auto extract
	if options.Config.AutoExtract {
		//Iterate through each file
		archives := []os.FileInfo{}
		for i := 0; i < len(files); i++ {
			filename := filepath.Base(files[i].Name())

			if strings.ToLower(filepath.Ext(filename)) == ".zip" || strings.ToLower(filepath.Ext(filename)) == ".mans" {
				archives = append(archives, files[i])
				files = append(files[:i], files[i+1:]...)
				i--
				continue
			} else if filename == "_GAPParseCache.json" {
				files = append(files[:i], files[i+1:]...)
				i--
				continue
			}
		}

		//Unarchive any files
		if len(archives) > 0 {
			newfiles := GoAuditExtract_Start(options, archives, config, configOutDirIndex)
			for i, newfile := range newfiles {
				found := false
				for j, oldfile := range files {
					if oldfile.Name() == newfile.Name() {
						found = true
						files[j] = newfiles[i]
						break
					}
				}
				if !found {
					files = append(files, newfiles[i])
				}
			}
		}
	}

	//Check if any files remain
	if len(files) == 0 {
		fmt.Println(options.Box + "All identified file(s) already parsed.")
		return
	}

	extramsg := ""

	//Remove non xml files and previously parsed files
	for i := 0; i < len(files); i++ {

		if options.ForceReparse || options.WipeOutput {
			continue
		}
		if strings.HasSuffix(files[i].Name(), ".json") {
			files = append(files[:i], files[i+1:]...)
			i--
			continue
		}

		var fileconfig Parse_Config_XMLFile
		config, fileconfig = InputConfig_GetXMLParseConfig(files[i], configOutDirIndex, config)

		if ExtraFunc5(options, fileconfig) {
			//do not remove file even if it was previously parsed
		} else if fileconfig.Status == "parsed" {
			files = append(files[:i], files[i+1:]...)
			i--
			c_Cached++
		} else if fileconfig.Status == "split" {
			files = append(files[:i], files[i+1:]...)
			i--
			c_Cached++
		} else if fileconfig.Status == "ignored/issues" {
			files = append(files[:i], files[i+1:]...)
			i--
			c_Issues++
		} else if fileconfig.Status == "ignored/empty" {
			files = append(files[:i], files[i+1:]...)
			i--
			c_Empty++
		}
	}

	//Auto split
	if options.Config.AutoSplitFiles {
		//Check all files
		splitfiles := []os.FileInfo{}
		for i := 0; i < len(files); i++ {
			if strings.Contains(files[i].Name(), "_spxml") || strings.Contains(files[i].Name(), "stateagentinspector") || strings.Contains(files[i].Name(), "eventbuffer") {
				continue
			}
			if files[i].Size() >= int64(options.XMLSplitByteSize) {
				splitfiles = append(splitfiles, files[i])
				files = append(files[:i], files[i+1:]...)
				i--
			}
		}

		//Split all big files
		if len(splitfiles) > 0 {
			options.SubTaskFiles = splitfiles
			options.XMLSplitOutputDir = filepath.Join(options.InputPath, "xmlsplit")
			subTaskFiles := GoAuditXMLSplitter_Start(options)
			options.SubTaskFiles = nil
			for i := 0; i < len(subTaskFiles); i++ {
				alreadyExists := false
				for _, file := range files {
					if subTaskFiles[i].Name() == file.Name() {
						alreadyExists = true
						subTaskFiles = append(subTaskFiles[:i], subTaskFiles[i+1:]...)
						i--
						break
					}
				}
				if alreadyExists {
					continue
				}
				config, _ = InputConfig_GetXMLParseConfig(subTaskFiles[i], configOutDirIndex, config)
			}
			for i := 0; i < len(splitfiles); i++ {
				config = ParseConfigUpdateXMLParse(configOutDirIndex, splitfiles[i], "File was split.", ExtraFunc6(options), config)
			}
			files = append(files, subTaskFiles...)
		}
		ParseConfigSave(config, options)
		debug.FreeOSMemory()
	}

	//"Extra" functions used for addons
	var es1 ExtraStruct1
	if ExtraEnabled() {
		config, es1, extramsg = ExtraFunc1(options, files, config, configOutDirIndex)
	}

	threadindex := 0
	threadtotal := len(files)
	threadpadding := len(strconv.Itoa(threadtotal))
	threadbuffer := map[int]string{}

	//Start time of timer
	start := time.Now()

	if len(files) != 0 {

		c := make(chan ThreadReturn_Parse)
		if options.Threads < 1 {
			options.Threads = 1
		}
		if len(files) < options.Threads {
			options.Threads = len(files)
		}

		c_tqdm := make(chan bool)
		c_debug := make(chan map[int]string)

		if options.Verbose == 0 {
			go TQDM(len(files), options, options.Box+"Parsing XML audits to CSV into '"+options.OutputPath+"'"+extramsg, c_tqdm)
		} else {
			fmt.Println(options.Box + "Parsing XML audits to CSV into '" + options.OutputPath + "'" + extramsg)
			go Debug(options, c_debug)
		}

		threadMessages := []string{}

		//Count bytes until next parse config file save
		var filesize_total int64 = 0
		var filesize_max int64 = 500000000

		//Start threads
		for i := 0; i < len(files); i++ {
			if i >= options.Threads {
				done := <-c
				delete(threadbuffer, done.threadnum)
				if options.Verbose == 0 {
					c_tqdm <- true
				} else {
					c_debug <- threadbuffer
				}
				threadMessages = append(threadMessages, done.message)
				config = ParseConfigUpdateXMLParse(configOutDirIndex, files[done.threadnum], done.message, ExtraFunc6(options), config)
				filesize_total += done.xmlsize
				if filesize_total > filesize_max {
					filesize_total = 0
					err_s := ParseConfigSave(config, options)
					if err_s != nil {
						fmt.Println(options.Warnbox + "WARNING - Could not update '_GAPParseCache.json'. " + err_s.Error())
					}
					debug.FreeOSMemory()
				}
			}
			fileconfig := Parse_Config_XMLFile{}
			config, fileconfig = InputConfig_GetXMLParseConfig(files[i], configOutDirIndex, config)
			go GoAuditParser_Thread(fileconfig, es1, options, i, c)
			threadbuffer[i] = files[i].Name() + "||" + time.Now().Format("2006-01-02T15:04:05-0700")
			threadindex++
			if options.Verbose > 0 {
				c_debug <- threadbuffer
				fmt.Printf(options.Box+"Parsing %"+strconv.Itoa(threadpadding)+"d/%"+strconv.Itoa(threadpadding)+"d %6.2f%% "+filepath.Base(files[i].Name())+"...\n", threadindex, threadtotal, (float32(threadindex)/float32(threadtotal))*100.0)
			}
		}

		//Wait for last few threads
		for i := 0; i < options.Threads; i++ {
			done := <-c
			delete(threadbuffer, done.threadnum)
			if options.Verbose == 0 {
				c_tqdm <- true
			} else {
				c_debug <- threadbuffer
			}
			threadMessages = append(threadMessages, done.message)
			config = ParseConfigUpdateXMLParse(configOutDirIndex, files[done.threadnum], done.message, ExtraFunc6(options), config)
			if filesize_total > filesize_max || i == options.Threads-1 {
				filesize_total = 0
				err_s := ParseConfigSave(config, options)
				if err_s != nil {
					fmt.Println(options.Warnbox + "WARNING - Could not update '_GAPParseCache.json'. " + err_s.Error())
				}
				debug.FreeOSMemory()
			}
		}

		for _, msg := range threadMessages {
			if strings.Contains(msg, "parsed successfully") {
				c_Success++
				if options.Verbose > 0 {
					fmt.Println(msg)
				}
			} else if strings.Contains(msg, "Could not rename") {
				c_Failed++
				fmt.Println(msg)
			} else if strings.Contains(msg, "Could not parse file") {
				c_Failed++
				fmt.Println(msg)
			} else if strings.Contains(msg, "already exists") {
				c_Cached++
				if options.Verbose > 0 {
					fmt.Println(msg)
				}
			} else if strings.Contains(msg, "Issues file") {
				c_Issues++
				if options.Verbose > 0 {
					fmt.Println(msg)
				}
			} else if strings.Contains(msg, "is empty") {
				c_Empty++
				fmt.Println(msg)
			} else if strings.Contains(msg, "does not exist") {
				c_Failed++
				fmt.Println(msg)
			} else {
				if options.Verbose > 0 {
					fmt.Println(msg)
				}
			}
		}
	}

	elapsed := time.Since(start)
	time.Sleep(10 * time.Millisecond)

	fmt.Println(options.Box + "Parse Statistics:")
	fmt.Println(options.Box+" - Parsed: ", c_Success)
	fmt.Println(options.Box+" - Failed: ", c_Failed)
	fmt.Println(options.Box+" - Cached: ", c_Cached)
	fmt.Println(options.Box+" - Empty:  ", c_Empty)
	fmt.Println(options.Box+" - Issues: ", c_Issues)

	fmt.Printf(options.Box+"Parsed %d file(s) in %s.", len(files), elapsed.Truncate(time.Millisecond).String())
	if options.Timeline || !options.MinimizedOutput {
		fmt.Printf("\n")
	}
}

func TQDM(total int, options Options, message string, c_tqdm chan bool) {
	tqdm.With(Interval(0, total), message, func(v interface{}) (brk bool) {
		<-c_tqdm
		return
	})
}

func Debug(options Options, c_debug chan map[int]string) {
	var stats map[int]string
	last := time.Now()
	for {
		select {
		case stats = <-c_debug:
			if len(stats) == 0 {
				break
			}
			last = time.Now()
			continue
		default:
			//Check if 30s has passed
			if time.Now().After(last.Add(time.Second * 30)) {
				last = time.Now()
				if options.Verbose < 3 && len(stats) != 0 {
					fmt.Println(options.Box + time.Now().Format("2006-01-02 15:04:05") + " - " + strconv.Itoa(len(stats)) + " file(s) are being processed:")
					lines := []string{}
					for _, v := range stats {
						filename := strings.Split(v, "||")[0]
						timestamp := strings.Split(v, "||")[1]
						t, _ := time.Parse("2006-01-02T15:04:05-0700", timestamp)
						lines = append(lines, fmt.Sprintf(options.Box+"  %s - %s", fmtDuration(time.Since(t)), filename))
					}
					sort.Strings(lines)
					for _, s := range lines {
						fmt.Println(s)
					}
				}
			}
			continue
		}
	}
}

//https://stackoverflow.com/questions/47341278/how-to-format-a-duration
func fmtDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}

func GoAuditParser_Thread(fileconfig Parse_Config_XMLFile, es1 ExtraStruct1, options Options, threadNum int, c chan ThreadReturn_Parse) {

	xmlFileSize := fileconfig.InputFileSize
	xmlFileName := fileconfig.InputFileName
	xmlFilePath := filepath.Join(options.InputPath, xmlFileName)
	//Check if file is a split file
	if _, err_s := os.Stat(xmlFilePath); os.IsNotExist(err_s) {
		xmlFilePath = filepath.Join(filepath.Join(options.InputPath, "xmlsplit"), xmlFileName)
		if _, err_s2 := os.Stat(xmlFilePath); os.IsNotExist(err_s2) {
			c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + "ERROR - File '" + filepath.Join(options.InputPath, xmlFileName) + "' does not exist."}
			return
		}
	}
	csvFilePath := options.OutputPath
	csvFilePathTemp := ""
	csvFilePathHasAuditType := false

	//Perform extra addon functions
	var es2 ExtraStruct2
	if ExtraEnabled() {
		es2 = ExtraFunc2(options, fileconfig)
	}

	AUDIT_NORMAL := 1
	AUDIT_EVENTBUFFER := 2
	AUDIT_STATEAGENTINSPECTOR := 3
	auditXMLStyle := 0

	//Get First 2 Lines of Audit
	f, err_f := os.Open(xmlFilePath)
	if err_f != nil {
		c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + "ERROR - File '" + xmlFilePath + "' does not exist."}
		return
	}
	scanner := bufio.NewScanner(f)
	row_count := 0
	itemListLine := ""
	for scanner.Scan() {
		row_count++
		itemListLine = strings.TrimSpace(scanner.Text())
		if row_count == 1 && !strings.HasPrefix(itemListLine, "<?xml") {
			f.Close()
			c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not parse file '` + xmlFileName + `'. Unexpected 1st Line: ` + itemListLine}
			return
		}
		if row_count == 2 {
			itemListLine = strings.ToLower(itemListLine)
			if strings.HasPrefix(itemListLine, "<issuelist") {
				f.Close()
				c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `NOTICE - Issues file '` + xmlFileName + `' ignored.`}
				return
			} else if !strings.HasPrefix(itemListLine, "<itemlist") {
				f.Close()
				c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not parse file '` + xmlFileName + `'. Unexpected 2nd Line: ` + itemListLine}
				return
			}
			auditXMLStyle = AUDIT_NORMAL
			if strings.Contains(itemListLine, `generator="eventbuffer"`) {
				auditXMLStyle = AUDIT_EVENTBUFFER
			}
			if strings.Contains(itemListLine, `generator="stateagentinspector"`) {
				auditXMLStyle = AUDIT_STATEAGENTINSPECTOR
			}
		}
		if row_count >= 3 {
			break
		}
	}
	f.Close()
	if auditXMLStyle == 0 {
		c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not parse file '` + xmlFileName + `'. Unexpected XML schema.`}
		return
	}

	//Determine filename parts
	hostname := ""
	agentid := ""
	payload := ""
	auditType := ""

	if auditXMLStyle == AUDIT_NORMAL {
		//Get AuditType from 2nd Line
		if row_count != 3 {
			c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + "WARNING - File '" + xmlFileName + "' is empty."}
			return
		}
		regAuditType := regexp.MustCompile(`<([^ >]+)[ >]`)
		regAuditTypeSubmatch := regAuditType.FindStringSubmatch(itemListLine)
		if len(regAuditTypeSubmatch) <= 1 || regAuditTypeSubmatch[1] == "" {
			c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not parse file '` + xmlFileName + `'. Could not identify audit type from line: '` + itemListLine}
			return
		}
		auditType = regAuditTypeSubmatch[1]
	}

	basefilename := strings.TrimSuffix(xmlFileName, ".xml")

	parts := strings.Split(basefilename, "-")
	//For non-standarized naming schemes
	if strings.Contains(basefilename, ".urn_uuid_") || (len(parts) < 4) {
		hostname = "HOSTNAMEPLACEHOLDER"
		agentid = "AGENTIDPLACEHOLDER0000"

		regGrabstuff2Parent := regexp.MustCompile(`([A-Za-z0-9]{22})_(.+)`)
		regGrabstuff2ParentSubmatch := regGrabstuff2Parent.FindStringSubmatch(filepath.Base(options.InputPath))
		if len(regGrabstuff2ParentSubmatch) > 1 {
			hostname = regGrabstuff2ParentSubmatch[2]
			agentid = regGrabstuff2ParentSubmatch[1]
		}

		if len(options.ParseAltHostname) > 0 {
			hostname = options.ParseAltHostname
		}
		if len(options.ParseAltAgentID) > 0 {
			agentid = options.ParseAltAgentID
		}
		if strings.Contains(basefilename, "_spxml") {
			payload = strings.TrimSuffix(strings.TrimPrefix(basefilename, "HOSTNAMEPLACEHOLDER-AGENTIDPLACEHOLDER0000-"), "-UNCONFIRMED")
		} else {
			payload = strings.ReplaceAll(basefilename, "-", "_")
		}

		//For standardized naming scheme
	} else {
		hostname = strings.Join(parts[0:len(parts)-3], "-")
		agentid = parts[len(parts)-3]
		payload = parts[len(parts)-2]
		if len(options.ParseAltHostname) > 0 {
			hostname = options.ParseAltHostname
		}
		if len(options.ParseAltAgentID) > 0 {
			agentid = options.ParseAltAgentID
		}
		if options.ParseCSVFormat == 2 {
			indx := strings.Index(payload, "_spxml")
			if indx != -1 {
				payload = "0" + payload[indx:]
			} else {
				payload = "0"
			}
		}
	}
	csvFilePath = filepath.Join(csvFilePath, hostname+"-"+agentid+"-"+payload+"-")

	if options.Verbose > 3 {
		fmt.Println("\nAudit Style:", auditXMLStyle)
	}

	//xmlFile, err_o := os.Open(xmlFilePath)
	if auditXMLStyle == AUDIT_NORMAL {

		//Perform extra addon functions
		if ExtraEnabled() {
			es2 = ExtraFunc3(options, fileconfig, es2)
		}

		useScanner := xmlFileSize >= 100000000 // 100 MB
		var lines []string
		var scanner *bufio.Scanner
		var file *os.File

		if useScanner {
			var err_f error
			file, err_f = os.Open(xmlFilePath)
			if err_f != nil {
				c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + "ERROR - File " + xmlFilePath + "' does not exist."}
				return
			}
			//https://stackoverflow.com/questions/21124327/how-to-read-a-text-file-line-by-line-in-go-when-some-lines-are-long-enough-to-ca
			scanner = bufio.NewScanner(file)
			buf := make([]byte, 0, 64*1024)
			scanner.Buffer(buf, 1024*1024*20)

		} else {
			content, err_o := ioutil.ReadFile(xmlFilePath)
			if err_o != nil {
				c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + "ERROR - Could not open file '" + xmlFilePath + "' to split. " + err_o.Error()}
				return
			}
			lines = strings.Split(string(content), "\n")
		}

		var csvFileTemp *os.File

		regAuditOpen := regexp.MustCompile(`^[ \t]*<([^ >]+)[ >]`)
		regAuditCloseORFieldSubClose := regexp.MustCompile(`^[ \t]*</([^ >]+)>`)
		regAuditCreated := regexp.MustCompile(`created="([^"]+)"`)
		regAuditUID := regexp.MustCompile(`uid="([^"]+)"`)
		regFieldSLClose := regexp.MustCompile(`^[ \t]*<([-_A-Za-z0-9]+) ?/>$`)               //  <remoteIpAddress />
		regFieldSL := regexp.MustCompile(`^[ \t]*<([-_A-Za-z0-9]+)>(.*)</[-_A-Za-z0-9]+>$`)  //  <remoteIpAddress>10.34.155.235</remoteIpAddress>
		regFieldMLOpenORFieldSubOpen := regexp.MustCompile(`^[ \t]*<([-_A-Za-z0-9]+)>(.*)$`) //  <httpHeader>POST /wsman HTTP/1.1
		regFieldMLClose := regexp.MustCompile(`^([^<>]*)</([-_A-Za-z0-9]+)>$`)               //</httpHeader>
		regFieldSubOpen := regexp.MustCompile(`^[ \t]*<([-_A-Za-z0-9]+)>$`)

		STATES := map[int]string{}
		STATES[0] = "STATE_HEADER"
		STATES[1] = "STATE_EXPECTING_AUDITITEMOPEN_OR_ITEMLISTCLOSE_OR_DEBUGOPEN"
		STATES[2] = "STATE_EXPECTING_FIELDOPEN_OR_AUDITITEMCLOSE"
		STATES[3] = "STATE_EXPECTING_AUDITITEMOPEN_OR_FIELDCLOSE"
		STATES[4] = "STATE_EXPECTING_FIELDCLOSE"
		STATES[5] = "STATE_FINISHED"
		STATES[6] = "STATE_EXPECTING_DEBUGCLOSE"

		STATE_HEADER := 0
		STATE_EXPECTING_AUDITITEMOPEN_OR_ITEMLISTCLOSE_OR_DEBUGOPEN := 1
		STATE_EXPECTING_FIELDOPEN_OR_AUDITITEMCLOSE := 2
		STATE_EXPECTING_AUDITITEMOPEN_OR_FIELDCLOSE := 3
		STATE_EXPECTING_FIELDCLOSE := 4
		STATE_FINISHED := 5
		STATE_EXPECTING_DEBUGCLOSE := 6

		state := STATE_HEADER

		headers := map[string]int{}          // map["ColumnHeader"]ColumnID
		rows := []map[int]*strings.Builder{} // []map[ColumnID]"Value"
		row := map[int]*strings.Builder{}    // map[ColumnID]"Value"

		lineCount := 0

		headerPathParts := []string{}

		multilineHeader := ""

		include_value := true

		var byteindex uint64 = 0
		bytepadding := len(strconv.FormatInt(xmlFileSize, 10))
		lastupdate := time.Now()

		//For every line in file
		for {

			if options.Verbose > 2 && time.Now().After(lastupdate.Add(time.Second*5)) {
				lastupdate = time.Now()
				fmt.Printf(options.Box+time.Now().Format("2006-01-02 15:04:05")+" - %"+strconv.Itoa(bytepadding)+"d/%s %6.2f%% "+filepath.Base(xmlFilePath)+"\n", byteindex, strconv.FormatInt(xmlFileSize, 10), (float32(byteindex)/float32(xmlFileSize))*100.0)
			}

			var line string
			if useScanner {
				if !scanner.Scan() {
					break
				}
				line = scanner.Text()
			} else {
				if lineCount == len(lines) {
					break
				}
				line = lines[lineCount]
			}
			byteindex += uint64(len(line))
			line = strings.TrimSuffix(line, "\r")
			lineCount++

			if options.Verbose > 3 {
				fmt.Println("==========================")
				fmt.Println("File Name:       ", xmlFileName)
				fmt.Println("File Progress:   ", fmt.Sprintf("%d/%s %6.2f%%", byteindex, strconv.FormatInt(xmlFileSize, 10), (float32(byteindex)/float32(xmlFileSize))*100.0))
				fmt.Println("Line Number:     ", lineCount)
				fmt.Println("State:           ", state, STATES[state])
				fmt.Println("Header Parts:    ", strings.Join(headerPathParts, "."))
				fmt.Println("MultiLine Header:", multilineHeader)
				fmt.Println("Include Value:   ", include_value)
				fmt.Println("Raw Line:        ", line)
				uEnc := b64.URLEncoding.EncodeToString([]byte(line))
				fmt.Println("Base64 Line:     ", uEnc)

			}

			// <?xml version="1.0" encoding="UTF-8"?>
			if state == STATE_HEADER && lineCount == 1 {
				line = strings.TrimSpace(line)
				if !strings.HasPrefix(line, "<?xml ") {
					if useScanner {
						file.Close()
					}
					c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not parse file '` + xmlFileName + `'. Unexpected 1st Line: ` + line}
					return
				}
				continue
			}
			// <itemList generator="eventbuffer" generatorVersion="29.7.8" itemSchemaLocation="http://schemas.mandiant.com/2013/11/stateagentinspectoritem.xsd" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="http://schemas.mandiant.com/2013/11/stateagentinspectoritem.xsd">
			if state == STATE_HEADER && lineCount == 2 {
				line = strings.ToLower(strings.TrimSpace(line))
				if strings.HasPrefix(line, "<issuelist") {
					if useScanner {
						file.Close()
					}
					c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `NOTICE - Issues file '` + xmlFileName + `' ignored.`}
					return
				} else if !strings.HasPrefix(line, "<itemlist") {
					if useScanner {
						file.Close()
					}
					c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not parse file '` + xmlFileName + `'. Unexpected 2nd Line: ` + line}
					return
				}
				state = STATE_EXPECTING_AUDITITEMOPEN_OR_ITEMLISTCLOSE_OR_DEBUGOPEN
				continue
			}

			if state == STATE_EXPECTING_AUDITITEMOPEN_OR_ITEMLISTCLOSE_OR_DEBUGOPEN {

				if es1.ExtraBool1 {
					include_value = false
				}

				if len(row) != 0 {
					rows = append(rows, row)
				}
				row = map[int]*strings.Builder{}
				headerPathParts = []string{}

				comp := strings.ToLower(strings.TrimSpace(line))

				//END
				if comp == "</itemlist>" {
					//Finish up...
					state = STATE_FINISHED
					break
				}
				//DEBUG
				// <Debug created="2020-10-05T18:01:05Z" uid="473bc9ba-fc52-437e-8610-1bf6c4aabd93">
				//  <Message>
				//Wow6432Node\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup: Registry key not found</Message>
				// </Debug>
				if strings.HasPrefix(comp, "<debug") {
					//Finish up...
					state = STATE_EXPECTING_DEBUGCLOSE
					continue
				}
				//Check if audit type ^<([^ >]+)[ >]
				m := regAuditOpen.FindStringSubmatch(line)
				if len(m) <= 1 {
					if useScanner {
						file.Close()
					}
					c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not parse file '` + xmlFileName + `'. Expected '^<([^ >]+)[ >]' or '</itemList>' on line ` + strconv.Itoa(lineCount) + `: ` + line}
					return
				}

				if !csvFilePathHasAuditType {
					csvFilePathHasAuditType = true
					csvFilePath += auditType + ".csv"
					csvFilePathTemp = csvFilePath + ".incomplete"

					_, o_err := os.Stat(csvFilePath)
					if !options.ForceReparse && !options.WipeOutput && !os.IsNotExist(o_err) {
						if useScanner {
							file.Close()
						}
						c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Box + `NOTICE - Parsed audit for file '` + xmlFileName + `' already exists. Use '-f' flag to force reparse.`}
						return
					}
					var err error
					csvFileTemp, err = os.Create(csvFilePathTemp)
					if err != nil {
						if useScanner {
							file.Close()
						}
						csvFileTemp.Close()
						c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not parse file '` + xmlFileName + `'. Could not create file '` + csvFilePathTemp + `'. ` + err.Error()}
						return
					}
				}

				//Get AuditItem Attributes
				mC := regAuditCreated.FindStringSubmatch(line)
				mUID := regAuditUID.FindStringSubmatch(line)

				if len(mC) > 1 {
					add_value_to_row_normal("FireEyeGeneratedTime", mC[1], headerPathParts, headers, row, options, true, include_value)
				}
				if ExtraEnabled() {
					include_value = ExtraFunc4(options, es1, es2, line, headerPathParts, headers, row, include_value)
				} else if len(mUID) > 1 {
					add_value_to_row_normal("Audit UID", mUID[1], headerPathParts, headers, row, options, true, include_value)
				}
				state = STATE_EXPECTING_FIELDOPEN_OR_AUDITITEMCLOSE
				continue
			}

			if state == STATE_EXPECTING_FIELDOPEN_OR_AUDITITEMCLOSE || state == STATE_EXPECTING_AUDITITEMOPEN_OR_FIELDCLOSE {

				if state == STATE_EXPECTING_AUDITITEMOPEN_OR_FIELDCLOSE {
					//regFieldMLClose         := regexp.MustCompile(`^([^<^>]*)</([-_A-Za-z0-9]+)>$`)                  //  </httpHeader>
					m := regFieldMLClose.FindStringSubmatch(line)
					//Check if line is multi-line field close
					if len(m) > 2 {
						value := m[1]
						header := m[2]
						if strings.TrimSpace(value) != "" {
							headerPathParts = headerPathParts[:len(headerPathParts)-1]
							if header != multilineHeader {
								c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not parse file '` + xmlFileName + `'. MultiLine Field Close '(.*)</([A-Za-z0-9]+)>$' Header ` + header + ` did not match Open Header '` + multilineHeader + `' on line ` + strconv.Itoa(lineCount) + `: ` + line}
								return
							}
							add_value_to_row_normal(multilineHeader, value, headerPathParts, headers, row, options, false, include_value)
							multilineHeader = ""
							state = STATE_EXPECTING_FIELDOPEN_OR_AUDITITEMCLOSE
							continue
						}
						//check if line is multi-line field mid
					} else if !strings.Contains(line, "<") {
						headerPathParts = headerPathParts[:len(headerPathParts)-1]
						add_value_to_row_normal(multilineHeader, line+"\n", headerPathParts, headers, row, options, false, include_value)
						state = STATE_EXPECTING_FIELDCLOSE
						continue
					}
					//If line is not a multi-line field, it must be a new audit
				}

				//regAuditCloseORFieldSubClose := regexp.MustCompile(`^[ \t]*</([^ >]+)[ >]`)
				m1 := regAuditCloseORFieldSubClose.FindStringSubmatch(line)
				if len(m1) > 1 {
					endTag := m1[1]
					if options.Verbose > 3 {
						fmt.Println("EndTag:      ", endTag, "HeaderPathParts:", headerPathParts)
					}
					//Check if end of row item
					if len(headerPathParts) == 0 && endTag == auditType {
						state = STATE_EXPECTING_AUDITITEMOPEN_OR_ITEMLISTCLOSE_OR_DEBUGOPEN
						continue
						//Check if end of field group
					} else if len(headerPathParts) != 0 && endTag == headerPathParts[len(headerPathParts)-1] {
						headerPathParts = headerPathParts[:len(headerPathParts)-1]
						continue
					} else {
						if len(headerPathParts) == 0 {
							if useScanner {
								file.Close()
							}
							csvFileTemp.Close()
							c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not parse file '` + xmlFileName + `'. Expected AuditItem Close Tag '</` + auditType + `>' on line ` + strconv.Itoa(lineCount) + `: ` + line}
							return
						} else {
							if useScanner {
								file.Close()
							}
							csvFileTemp.Close()
							c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not parse file '` + xmlFileName + `'. Expected SubField Close Tag '</` + headerPathParts[len(headerPathParts)-1] + `>' on line ` + strconv.Itoa(lineCount) + `: ` + line}
							return
						}
					}
				}
				//regFieldSLClose         := regexp.MustCompile(`^[ \t]*<([-_A-Za-z0-9]+) ?/>$`)                   //  <remoteIpAddress />
				m2 := regFieldSLClose.FindStringSubmatch(line)
				if len(m2) > 1 {
					header := m2[1]
					value := ""
					add_value_to_row_normal(header, value, headerPathParts, headers, row, options, true, include_value)
					continue
				}

				//regFieldSL              := regexp.MustCompile(`^[ \t]*<([-_A-Za-z0-9]+)>(.*)</[-_A-Za-z0-9]+>$`) //  <remoteIpAddress>10.34.155.235</remoteIpAddress>
				m3 := regFieldSL.FindStringSubmatch(line)
				if len(m3) > 2 {
					header := m3[1]
					value := m3[2]
					add_value_to_row_normal(header, value, headerPathParts, headers, row, options, true, include_value)
					continue
				}

				//regFieldMLOpenORFieldSubOpen          := regexp.MustCompile(`^[ \t]*<([-_A-Za-z0-9]+)>(.*)$`                   //  <httpHeader>POST /wsman HTTP/1.1
				m4 := regFieldMLOpenORFieldSubOpen.FindStringSubmatch(line)
				if len(m4) > 2 {
					multilineHeader = m4[1]
					value := m4[2]
					if strings.TrimSpace(value) != "" {
						add_value_to_row_normal(multilineHeader, value, headerPathParts, headers, row, options, true, include_value)
						state = STATE_EXPECTING_FIELDCLOSE
						continue
					}
					headerPathParts = append(headerPathParts, multilineHeader)
					state = STATE_EXPECTING_AUDITITEMOPEN_OR_FIELDCLOSE
					continue
				}

				//regFieldSubOpen         := regexp.MustCompile(`^[ \t]*<([-_A-Za-z0-9]+)>$`)
				m5 := regFieldSubOpen.FindStringSubmatch(line)
				if len(m5) > 1 {
					header := m5[1]
					headerPathParts = append(headerPathParts, header)
					continue
				}

				errmsg := `Expected AuditItem Close Tag '</` + auditType + `>'`
				if len(headerPathParts) == 0 {
					errmsg = `Expected SubField Close Tag '</` + auditType + `>'`
				}
				if useScanner {
					file.Close()
				}
				csvFileTemp.Close()
				c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not parse file '` + xmlFileName + `'. ` + errmsg + `, SingleLine Field Close '^[ \t]*<([-_A-Za-z0-9]+) ?/>$', SingleLine Field '^[ \t]*<([-_A-Za-z0-9]+)>(.*)</[-_A-Za-z0-9]+>$', MultiLine Field Open '^[ \t]*<([-_A-Za-z0-9]+)>(.+)$', or MultiLine SubField Open '^[ \t]*<([-_A-Za-z0-9]+)>$' on line ` + strconv.Itoa(lineCount) + `: ` + line}
				return
			}

			if state == STATE_EXPECTING_FIELDCLOSE {
				//regFieldMLClose         := regexp.MustCompile(`(.*)</([-_A-Za-z0-9]+)>$`)                        //</httpHeader>
				m := regFieldMLClose.FindStringSubmatch(line)
				if len(m) > 2 {
					value := m[1]
					header := m[2]
					if header != multilineHeader {
						if useScanner {
							file.Close()
						}
						csvFileTemp.Close()
						c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not parse file '` + xmlFileName + `'. MultiLine Field Close '(.*)</([A-Za-z0-9]+)>$' Header ` + header + ` did not match Open Header '` + multilineHeader + `' on line ` + strconv.Itoa(lineCount) + `: ` + line}
						return
					}
					add_value_to_row_normal(multilineHeader, value, headerPathParts, headers, row, options, false, include_value)
					multilineHeader = ""
					state = STATE_EXPECTING_FIELDOPEN_OR_AUDITITEMCLOSE
				} else {
					add_value_to_row_normal(multilineHeader, line+"\n", headerPathParts, headers, row, options, false, include_value)
				}
				continue

			}

			if state == STATE_EXPECTING_DEBUGCLOSE {
				if strings.ToLower(strings.TrimSpace(line)) == "</debug>" {
					//Finish up...
					state = STATE_EXPECTING_AUDITITEMOPEN_OR_ITEMLISTCLOSE_OR_DEBUGOPEN
				}
				continue
			}

			if useScanner {
				file.Close()
			}
			csvFileTemp.Close()
			c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `INTERNAL ERROR - Could not parse file '` + xmlFileName + `'. Unexpected state ` + strconv.Itoa(state) + ` on line ` + strconv.Itoa(lineCount) + `: ` + line}
			return

		}
		/*
		   headers := map[string]int{} // map["ColumnHeader"]ColumnID
		   rows := []map[int]string{}  // []map[ColumnID]"Value"
		   row  := map[int]string{}    // map[ColumnID]"Value"
		*/

		if useScanner {
			file.Close()
		}

		if len(rows) == 0 {
			csvFileTemp.Close()
			os.Remove(csvFilePathTemp)
			c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `WARNING - File '` + xmlFileName + `' is empty.`}
			return
		}

		csvHeaders := []string{}

		//Add mandatory headers
		for _, h := range options.Config.HeadersMandatory {
			if _, exists := headers[h]; exists {
				csvHeaders = append(csvHeaders, h)
			} else {
				csvHeaders = append(csvHeaders, h)
			}
		}

		//Add optional headers if they exist
		for _, h := range options.Config.HeadersOptional {
			if _, exists := headers[h]; exists {
				csvHeaders = append(csvHeaders, h)
			}
		}

		//Get audit-specific config if it exists
		configindex := -1
		for i, c := range options.Config.AuditHeaderConfigs {
			if strings.ToLower(c.ItemName) == strings.ToLower(auditType) {
				configindex = i
				break
			}
		}

		//Add audit-specific header order
		if configindex != -1 {
			for _, h := range options.Config.AuditHeaderConfigs[configindex].HeaderOrder {
				csvHeaders = append(csvHeaders, h)
			}

		}

		//Add remaining headers if allowed
		if !options.Config.OmitUnlisted {
			remainingHeaders := []string{}
			for h, _ := range headers {
				found := false
				for _, h2 := range csvHeaders {
					if h2 == h {
						found = true
						break
					}
				}
				if found {
					continue
				} else {
					remainingHeaders = append(remainingHeaders, h)
				}
			}

			//Case insensitive sort
			sort.Slice(remainingHeaders, func(i, j int) bool {
				return strings.ToLower(remainingHeaders[i]) < strings.ToLower(remainingHeaders[j])
			})

			//Remove specified headers
			if configindex != -1 {
				for _, h := range options.Config.AuditHeaderConfigs[configindex].HeadersOmitted {
					for i, h2 := range remainingHeaders {
						if h2 == h {
							remainingHeaders = append(remainingHeaders[0:i], remainingHeaders[i+1:len(remainingHeaders)]...)
						}
					}
				}
			}

			for _, h := range remainingHeaders {
				csvHeaders = append(csvHeaders, h)
			}
		}

		//Create rows
		csvRows := [][]string{}
		for _, row := range rows {
			csvRow := make([]string, len(csvHeaders))
			for i, header := range csvHeaders {
				if header == "Hostname" {
					csvRow[i] = hostname
					continue
				}
				if header == "AgentID" {
					csvRow[i] = agentid
					continue
				}
				colID, exists1 := headers[header]
				if !exists1 {
					csvRow[i] = ""
					continue
				}
				value, exists2 := row[colID]
				if exists2 {
					csvRow[i] = value.String()
				}
			}
			csvRows = append(csvRows, csvRow)
		}

		//LOG file fix
		if strings.ToLower(auditType) == "log" {
			col_index_arg := -1
			col_index_msg := -1
			for i := 0; i < len(csvHeaders); i++ {
				if csvHeaders[i] == "args.arg" {
					col_index_arg = i
					continue
				} else if csvHeaders[i] == "msg" {
					col_index_msg = i
					continue
				}
			}
			//If we found both expected headers, continue
			if col_index_arg != -1 && col_index_msg != -1 {
				csvHeaders = append(csvHeaders, "msg_full")
				for i := 0; i < len(csvRows); i++ {
					sep := "\n"
					if options.ReplaceNewLineFeeds {
						sep = "|"
					}
					args := strings.Split(csvRows[i][col_index_arg], sep)
					msg := csvRows[i][col_index_msg]
					for j := 0; j < len(args); j++ {
						msg = strings.Replace(msg, "^"+strconv.Itoa(j+1), strings.TrimSuffix(args[j], "\r"), 1)
					}
					csvRows[i] = append(csvRows[i], msg)
				}
			}
		}

		//Truncate cell values to 32k if ExcelFriendly
		if options.ExcelFriendly {
			for i := 0; i < len(csvRows); i++ {
				for j := 0; j < len(csvRows[0]); j++ {
					if len(csvRows[i][j]) > 32000 {
						csvRows[i][j] = csvRows[i][j][0:32000] + "..."
					}
				}
			}
		}

		//Write file out with 1mil lines only if ExcelFriendly
		if options.ExcelFriendly && len(csvRows) > 999999 {
			csvFileTemp.Close()
			splitfilepathtemp := filepath.Join(options.OutputPath, hostname+"-"+agentid+"-"+payload+"_spcsv1-"+auditType+".csv.incomplete")
			splitfilepath := filepath.Join(options.OutputPath, hostname+"-"+agentid+"-"+payload+"_spcsv1-"+auditType+".csv")
			var err_c error
			csvFileTemp, err_c = os.Create(splitfilepathtemp)
			if err_c != nil {
				c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not create temp split file '` + filepath.Base(splitfilepathtemp) + `' to normal file '` + filepath.Base(splitfilepath) + `'. ` + err_c.Error()}
				return
			}
			csvout := csv.NewWriter(csvFileTemp)
			for i := 0; i < len(csvRows); i += 999999 {
				isLastChunk := i+999999 > len(csvRows)
				if isLastChunk {
					csvout.Write(csvHeaders)
					csvout.WriteAll(csvRows[i:])
					break
				}
				csvout.Write(csvHeaders)
				csvout.WriteAll(csvRows[i : i+999999])
				csvout.Flush()
				csvFileTemp.Close()
				err_r := os.Rename(splitfilepathtemp, splitfilepath)
				if err_r != nil {
					c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not rename temp file '` + filepath.Base(splitfilepathtemp) + `' to normal file '` + filepath.Base(splitfilepath) + `'. ` + err_r.Error()}
					return
				}

				splitfilepathtemp = filepath.Join(options.OutputPath, hostname+"-"+agentid+"-"+payload+"_spcsv"+strconv.Itoa((i/999999)+2)+"-"+auditType+".csv.incomplete")
				splitfilepath = filepath.Join(options.OutputPath, hostname+"-"+agentid+"-"+payload+"_spcsv"+strconv.Itoa((i/999999)+2)+"-"+auditType+".csv")
				var err_c error
				csvFileTemp, err_c = os.Create(splitfilepathtemp)
				if err_c != nil {
					c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not create temp split file '` + filepath.Base(splitfilepathtemp) + `' to normal file '` + filepath.Base(splitfilepath) + `'. ` + err_c.Error()}
					return
				}
				csvout = csv.NewWriter(csvFileTemp)
			}
			csvout.Flush()
			csvFileTemp.Close()
			err_r := os.Rename(splitfilepathtemp, splitfilepath)
			if err_r != nil {
				c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not rename temp file '` + filepath.Base(csvFilePathTemp) + `' to normal file '` + filepath.Base(csvFilePath) + `'. ` + err_r.Error()}
				return
			}
			//Write entire file out not split at all
		} else {
			csvout := csv.NewWriter(csvFileTemp)
			csvout.Write(csvHeaders)
			csvout.WriteAll(csvRows)
			csvout.Flush()
			csvFileTemp.Close()
			err_r := os.Rename(csvFilePathTemp, csvFilePath)
			if err_r != nil {
				c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not rename temp file '` + filepath.Base(csvFilePathTemp) + `' to normal file '` + filepath.Base(csvFilePath) + `'. ` + err_r.Error()}
				return
			}
		}

	} else if (auditXMLStyle == AUDIT_EVENTBUFFER || auditXMLStyle == AUDIT_STATEAGENTINSPECTOR) && !es1.ExtraBool1 {

		eventTypes := map[string]int{}   // map[EventType]EventTypeID
		allHeaders := []map[string]int{} // [EventTypeID]map["ColumnHeader"]ColumnID
		tables := [][][]RowValue{}       // [EventTypeID][Row][ColumnID]Value
		row := []RowValue{}              // [ColumnID]Value

		if auditXMLStyle == AUDIT_EVENTBUFFER {
			xmlFile, err_o := os.Open(xmlFilePath)
			if err_o != nil {
				c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not parse file '` + xmlFileName + `'. ` + err_o.Error()}
				return
			}

			//https://stackoverflow.com/questions/21124327/how-to-read-a-text-file-line-by-line-in-go-when-some-lines-are-long-enough-to-ca
			scanner := bufio.NewScanner(xmlFile)
			buf := make([]byte, 0, 64*1024)
			scanner.Buffer(buf, 1024*1024*20)
			rowCount := 0

			regEventOpen := regexp.MustCompile(`^[ \t]*<eventItem.*>$`) //<eventItem sequence_num="1670535298" uid="6209762">
			regEventOpenSN := regexp.MustCompile(`sequence_num="(\d+)"`)
			regEventOpenUID := regexp.MustCompile(`uid="(\d+)"`)
			regEventOpenHITS := regexp.MustCompile(`hits="([^"]+)"`)
			regEventClose := regexp.MustCompile(`^[ \t]*</eventItem>$`)                     //</eventItem>
			regTypeOpen := regexp.MustCompile(`^[ \t]*<([A-Za-z0-9]+)>$`)                   // <urlMonitorEvent>
			regTypeClose := regexp.MustCompile(`^[ \t]*</([A-Za-z0-9]+)>$`)                 // </urlMonitorEvent>
			regFieldSLClosed := regexp.MustCompile(`^[ \t]*<([A-Za-z0-9]+) ?/>$`)           //  <remoteIpAddress />
			regFieldSL := regexp.MustCompile(`^[ \t]*<([A-Za-z0-9]+)>(.*)</[A-Za-z0-9]+>$`) //  <remoteIpAddress>10.34.155.235</remoteIpAddress>
			regFieldMLOpen := regexp.MustCompile(`^[ \t]*<([A-Za-z0-9]+)>(.*)`)             //  <httpHeader>POST /wsman HTTP/1.1
			regFieldMLClose := regexp.MustCompile(`(.*)</([A-Za-z0-9]+)>$`)                 //</httpHeader>

			STATE_HEADER := 0
			STATE_EXPECTING_EVENTOPEN_OR_END := 1
			STATE_EXPECTING_TYPEOPEN := 2
			STATE_EXPECTING_FIELDOPEN_OR_TYPECLOSE := 3
			STATE_EXPECTING_FIELDCLOSED := 4
			STATE_EXPECTING_EVENTCLOSE := 5
			STATE_FINISHED := 6

			state := STATE_HEADER

			eventType := ""
			eventTypeID := -1
			fieldType := ""

			attr_uid := ""
			attr_sequence_num := ""
			attr_ext1 := ""
			attr_ext2 := ""

			//For every line in file
			for scanner.Scan() {
				rowCount++
				line := scanner.Text()
				// <?xml version="1.0" encoding="UTF-8"?>
				if state == STATE_HEADER && rowCount == 1 {
					line = strings.TrimSpace(line)
					if !strings.HasPrefix(line, "<?xml ") {
						xmlFile.Close()
						c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not parse file '` + xmlFileName + `'. Unexpected 1st Line: ` + line}
						return
					}
					continue
				}
				// <itemList generator="eventbuffer" generatorVersion="29.7.8" itemSchemaLocation="http://schemas.mandiant.com/2013/11/stateagentinspectoritem.xsd" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="http://schemas.mandiant.com/2013/11/stateagentinspectoritem.xsd">
				if state == STATE_HEADER && rowCount == 2 {
					line = strings.TrimSpace(line)
					if !strings.HasPrefix(line, "<itemList ") {
						xmlFile.Close()
						c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not parse file '` + xmlFileName + `'. Unexpected 2nd Line: ` + line}
						return
					}
					state = STATE_EXPECTING_EVENTOPEN_OR_END
					continue
				}

				if state == STATE_EXPECTING_EVENTOPEN_OR_END {

					if len(row) != 0 {
						tables[eventTypeID] = append(tables[eventTypeID], row)
					}
					row = []RowValue{}

					//END
					if line == "</itemList>" {
						//Finish up...
						state = STATE_FINISHED
						break
					}
					//Check if <eventItem.*>
					m := regEventOpen.FindStringSubmatch(line)
					if len(m) < 1 {
						xmlFile.Close()
						c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not parse file '` + xmlFileName + `'. Expected '^[ \t]*<eventItem.*>' or '</itemList>' on line ` + strconv.Itoa(rowCount) + `: ` + line}
						return
					}

					//Reset and get attributes
					attr_uid = ""
					attr_sequence_num = ""
					attr_ext1 = ""
					attr_ext2 = ""
					mSN := regEventOpenSN.FindStringSubmatch(line)
					mUID := regEventOpenUID.FindStringSubmatch(line)
					mHITS := regEventOpenHITS.FindStringSubmatch(line)
					if len(mSN) > 1 {
						attr_sequence_num = mSN[1]
					}
					if len(mUID) > 1 {
						attr_uid = mUID[1]
					}
					if len(mHITS) > 1 {
						temp := mHITS[1]
						//Ex. "[f5565076-4567-4f91-bf69-2f654e245a20, 06743fce-d219-4945-bdc8-1bc34213c25c, 84b7dbf8-98e8-42fe-a3bc-5e48bacae0ab] [e5db9997-94b2-45ba-9ed4-3d5a8bb35717, 1bca5ad3-f24c-45f3-8bc8-9680cc0b59cb, c9cbda93-30e6-48f9-8000-c28b3fbc2786] [0b11c953-df78-42b4-ad10-2222d2367356, 3304e31d-ca63-49e5-b75c-dbae36ac0d18, c98f827b-bd27-4143-8f80-af9ae27a8134]"
						temp = strings.Replace(temp, "] [", "|", -1)
						temp = strings.Replace(temp, " ", "", -1)
						temp = strings.Replace(temp, "]", "", -1)
						temp = strings.Replace(temp, "[", "", -1)
						ext1 := []string{}
						ext2 := []string{}
						//Now looks like: "f5565076-4567-4f91-bf69-2f654e245a20,06743fce-d219-4945-bdc8-1bc34213c25c,84b7dbf8-98e8-42fe-a3bc-5e48bacae0ab|e5db9997-94b2-45ba-9ed4-3d5a8bb35717,1bca5ad3-f24c-45f3-8bc8-9680cc0b59cb,c9cbda93-30e6-48f9-8000-c28b3fbc2786|0b11c953-df78-42b4-ad10-2222d2367356,3304e31d-ca63-49e5-b75c-dbae36ac0d18,c98f827b-bd27-4143-8f80-af9ae27a8134"
						for _, ext1_item := range strings.Split(temp, "|") {
							ext1 = append(ext1, `"`+strings.Split(ext1_item, ",")[0]+`"`)
							tempdata := []string{}
							for _, ext2_item := range strings.Split(ext1_item, ",") {
								tempdata = append(tempdata, `"`+ext2_item+`"`)
							}
							ext2 = append(ext2, "["+strings.Join(tempdata, ",")+"]")
						}
						attr_ext1 = "[" + strings.Join(ext1, ",") + "]"
						attr_ext2 = "[" + strings.Join(ext2, ",") + "]"
					}
					state = STATE_EXPECTING_TYPEOPEN
					continue
				}

				if state == STATE_EXPECTING_TYPEOPEN {
					m := regTypeOpen.FindStringSubmatch(line)
					if len(m) < 2 {
						xmlFile.Close()
						c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not parse file '` + xmlFileName + `'. Expected Event Type '^[ \t]*<([A-Za-z0-9]+)>' on line ` + strconv.Itoa(rowCount) + `: ` + line}
						return
					}
					eventType = UpperCamelCase(m[1])
					val, exists := eventTypes[eventType]
					if !exists {
						eventTypeID = len(eventTypes)
						eventTypes[eventType] = eventTypeID
						tables = append(tables, [][]RowValue{})
						allHeaders = append(allHeaders, map[string]int{})
						allHeaders[eventTypeID]["Hostname"] = 0
						allHeaders[eventTypeID]["AgentID"] = 1
					} else {
						eventTypeID = val
					}

					if attr_uid != "" {
						row = add_value_to_row_eventbuffer("UID", attr_uid, allHeaders[eventTypeID], row, options, true)
					}
					if attr_sequence_num != "" {
						row = add_value_to_row_eventbuffer("Sequence Number", attr_sequence_num, allHeaders[eventTypeID], row, options, true)
					}
					if attr_ext1 != "" {
						row = add_value_to_row_eventbuffer(ExtraFunc7(options, 1), attr_ext1, allHeaders[eventTypeID], row, options, true)
					}
					if attr_ext2 != "" {
						row = add_value_to_row_eventbuffer(ExtraFunc7(options, 2), attr_ext2, allHeaders[eventTypeID], row, options, true)
					}

					state = STATE_EXPECTING_FIELDOPEN_OR_TYPECLOSE
					continue
				}

				if state == STATE_EXPECTING_FIELDOPEN_OR_TYPECLOSE {
					//regTypeClose   := regexp.MustCompile(`[ \t]*</([A-Za-z0-9]+)>$`)                   // </urlMonitorEvent>
					m1 := regTypeClose.FindStringSubmatch(line)
					if len(m1) > 1 {
						eventCloseType := UpperCamelCase(m1[1])
						if eventType != eventCloseType {
							xmlFile.Close()
							c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not parse file '` + xmlFileName + `'. Event Type Close did not match '` + eventType + `' on line ` + strconv.Itoa(rowCount) + `: ` + line}
							return
						}
						state = STATE_EXPECTING_EVENTCLOSE
						continue
					}
					//regFieldSL       := regexp.MustCompile(`[ \t]*<([A-Za-z0-9]+)>(.*)</[A-Za-z0-9]+>$`)     //  <remoteIpAddress>10.34.155.235</remoteIpAddress>
					m2 := regFieldSL.FindStringSubmatch(line)
					if len(m2) > 1 {
						field := UpperCamelCase(m2[1])
						value := m2[2]
						if field == "Timestamp" {
							field = "EventBufferTime_" + eventType
						}
						if field == "Hostname" {
							field = "DNSHostname"
						}
						row = add_value_to_row_eventbuffer(field, value, allHeaders[eventTypeID], row, options, true)
						state = STATE_EXPECTING_FIELDOPEN_OR_TYPECLOSE
						continue
					}

					//regFieldMLOpen   := regexp.MustCompile(`[ \t]*<([A-Za-z0-9]+)>(.*)`)                 //  <httpHeader>POST /wsman HTTP/1.1
					m3 := regFieldMLOpen.FindStringSubmatch(line)
					if len(m3) > 1 {
						field := UpperCamelCase(m3[1])
						value := m3[2]
						if field == "Timestamp" {
							field = "EventBufferTime_" + eventType
						}
						if field == "Hostname" {
							field = "DNSHostname"
						}
						row = add_value_to_row_eventbuffer(field, value, allHeaders[eventTypeID], row, options, true)
						fieldType = field
						state = STATE_EXPECTING_FIELDCLOSED
						continue
					}

					//regFieldSLClosed := regexp.MustCompile(`^[ \t]*<([A-Za-z0-9]+) ?/>$`)     //  <remoteIpAddress />
					m4 := regFieldSLClosed.FindStringSubmatch(line)
					if len(m4) > 1 {
						field := UpperCamelCase(m4[1])
						if field == "Timestamp" {
							field = "EventBufferTime_" + eventType
						}
						if field == "Hostname" {
							field = "DNSHostname"
						}
						row = add_value_to_row_eventbuffer(field, "", allHeaders[eventTypeID], row, options, true)
						state = STATE_EXPECTING_FIELDOPEN_OR_TYPECLOSE
						continue
					}

					xmlFile.Close()
					c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not parse file '` + xmlFileName + `'. Expected Record Close '^[ \t]*<(/[A-Za-z0-9]+)>$', SingleLine Field '^[ \t]*<([A-Za-z0-9]+)>(.*)</[A-Za-z0-9]+>$', Closed SingleLine Field '', or MultiLine Field Open '^[ \t]*<([A-Za-z0-9]+)>(.*)' on line ` + strconv.Itoa(rowCount) + `: ` + line}
					return
				}

				if state == STATE_EXPECTING_FIELDCLOSED {
					//regFieldMLClose  := regexp.MustCompile(`(.*)</([A-Za-z0-9]+)>$`)                //</httpHeader>
					m := regFieldMLClose.FindStringSubmatch(line)
					if len(m) > 1 {
						value := m[1]
						field := UpperCamelCase(m[2])
						if field == "Timestamp" {
							field = "EventBufferTime_" + eventType
						}
						if field == "Hostname" {
							field = "DNSHostname"
						}
						if fieldType != field {
							c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not parse file '` + xmlFileName + `'. MultiLine Field Type Close '(.*)</([A-Za-z0-9]+)>$' did not match '` + fieldType + `' on line ` + strconv.Itoa(rowCount) + `: ` + line}
							return
						}
						row = add_value_to_row_eventbuffer(field, value, allHeaders[eventTypeID], row, options, false)
						state = STATE_EXPECTING_FIELDOPEN_OR_TYPECLOSE
					} else {
						row = add_value_to_row_eventbuffer(fieldType, line, allHeaders[eventTypeID], row, options, false)
						state = STATE_EXPECTING_FIELDCLOSED
					}
					continue

				}

				if state == STATE_EXPECTING_EVENTCLOSE {
					//regEventClose    := regexp.MustCompile(`[ \t]*</eventItem>$`)                     //</eventItem>
					m := regEventClose.FindStringSubmatch(line)
					if len(m) == 1 {
						state = STATE_EXPECTING_EVENTOPEN_OR_END
						continue
					}
					xmlFile.Close()
					c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not parse file '` + xmlFileName + `'. Expected Event Close '^[ \t]*</eventItem>$' on line ` + strconv.Itoa(rowCount) + `: ` + line}
					return
				}
				xmlFile.Close()
				c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `INTERNAL ERROR - Could not parse file '` + xmlFileName + `'. Unexpected state ` + strconv.Itoa(state) + `on line ` + strconv.Itoa(rowCount) + `: ` + line}
				return
			}
			xmlFile.Close()
		} else {

			xmlFile, err_o := os.Open(xmlFilePath)
			if err_o != nil {
				c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not parse file '` + xmlFileName + `'. - Could not open file '` + xmlFilePath + `'. ` + err_o.Error()}
				return
			}

			scanner := bufio.NewScanner(xmlFile)
			buf := make([]byte, 0, 64*1024)
			scanner.Buffer(buf, 1024*1024*20)
			rowCount := 0

			regEventOpen := regexp.MustCompile(`^[ \t]*<eventItem.*>$`) // <eventItem sequence_num="1670535298" uid="6209762">
			regEventOpenSN := regexp.MustCompile(`sequence_num="(\d+)"`)
			regEventOpenUID := regexp.MustCompile(`uid="(\d+)"`)
			regEventOpenHITS := regexp.MustCompile(`hits="([^"]+)"`)
			regTimestamp := regexp.MustCompile(`^[ \t]*<timestamp>(.*)</timestamp>$`) //  <timestamp>2019-09-06T11:50:23.220Z</timestamp>
			regTimestampClosed := regexp.MustCompile(`^[ \t]*<timestamp />$`)         //  <timestamp />
			regType := regexp.MustCompile(`^[ \t]*<eventType>(.*)</eventType>$`)      //  <eventType>dnsLookupEvent</eventType>
			regDetailsOpen := regexp.MustCompile(`^[ \t]*<details>$`)                 //  <details>
			regDetailOpen := regexp.MustCompile(`^[ \t]*<detail>$`)                   //   <detail>
			regName := regexp.MustCompile(`^[ \t]*<name>(.*)</name>$`)                //    <name>pid</name>
			regValueSL := regexp.MustCompile(`^[ \t]*<value>(.*)</value>$`)           //    <value>19052</value>
			regValueSLClosed := regexp.MustCompile(`^[ \t]*<value ?/>$`)              //    <value />
			regValueMLOpen := regexp.MustCompile(`^[ \t]*<value>(.*)$`)               //    <value>POST /wsman HTTP/1.1
			regValueMLClose := regexp.MustCompile(`^(.*)</value>$`)                   //</value>
			regDetailClose := regexp.MustCompile(`^[ \t]*</detail>$`)                 //   </detail>
			regDetailsClose := regexp.MustCompile(`^[ \t]*</details>$`)               //  </details>
			regEventClose := regexp.MustCompile(`^[ \t]*</eventItem>$`)               // </eventItem>

			STATE_HEADER := 0
			STATE_EXPECTING_EVENTOPEN_OR_END := 1
			STATE_EXPECTING_TIMESTAMP := 2
			STATE_EXPECTING_EVENTTYPE := 3
			STATE_EXPECTING_DETAILSOPEN := 4
			STATE_EXPECTING_DETAILOPEN_OR_DETAILSCLOSE := 5
			STATE_EXPECTING_DETAILNAME := 6
			STATE_EXPECTING_DETAILVALUE := 7
			STATE_EXPECTING_DETAILVALUECLOSE := 8
			STATE_EXPECTING_DETAILCLOSE := 9
			STATE_EXPECTING_EVENTCLOSE := 10
			STATE_FINISHED := 11

			state := STATE_HEADER

			eventType := ""
			eventTypeID := -1

			attr_uid := ""
			attr_sequence_num := ""
			attr_ext1 := ""
			attr_ext2 := ""

			field_timestamp := ""
			field_name := ""

			//For every line in file
			for scanner.Scan() {
				rowCount++
				line := scanner.Text()
				// <?xml version="1.0" encoding="UTF-8"?>
				if state == STATE_HEADER && rowCount == 1 {
					line = strings.TrimSpace(line)
					if !strings.HasPrefix(line, "<?xml ") {
						xmlFile.Close()
						c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not parse file '` + xmlFileName + `'. Unexpected 1st Line: ` + line}
						return
					}
					continue
				}
				// <itemList generator="eventbuffer" generatorVersion="29.7.8" itemSchemaLocation="http://schemas.mandiant.com/2013/11/stateagentinspectoritem.xsd" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="http://schemas.mandiant.com/2013/11/stateagentinspectoritem.xsd">
				if state == STATE_HEADER && rowCount == 2 {
					line = strings.TrimSpace(line)
					if !strings.HasPrefix(line, "<itemList ") {
						xmlFile.Close()
						c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not parse file '` + xmlFileName + `'. Unexpected 2nd Line: ` + line}
						return
					}
					state = STATE_EXPECTING_EVENTOPEN_OR_END
					continue
				}

				if state == STATE_EXPECTING_EVENTOPEN_OR_END {

					if len(row) != 0 {
						tables[eventTypeID] = append(tables[eventTypeID], row)
					}
					row = []RowValue{}

					//END
					if line == "</itemList>" {
						//Finish up...
						state = STATE_FINISHED
						break
					}
					//regEventOpen     := regexp.MustCompile(`^[ \t]*<eventItem.*>$`)                         // <eventItem sequence_num="1670535298" uid="6209762">
					m := regEventOpen.FindStringSubmatch(line)
					if len(m) < 1 {
						xmlFile.Close()
						c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not parse file '` + xmlFileName + `'. Expected '^[ \t]*<eventItem.*>' or '</itemList>' on line ` + strconv.Itoa(rowCount) + `: ` + line}
						return
					}

					//Reset and get attributes
					attr_uid = ""
					attr_sequence_num = ""
					attr_ext1 = ""
					attr_ext2 = ""
					field_timestamp = ""
					mSN := regEventOpenSN.FindStringSubmatch(line)
					mUID := regEventOpenUID.FindStringSubmatch(line)
					mHITS := regEventOpenHITS.FindStringSubmatch(line)
					if len(mSN) > 1 {
						attr_sequence_num = mSN[1]
					}
					if len(mUID) > 1 {
						attr_uid = mUID[1]
					}
					if len(mHITS) > 1 {
						temp := mHITS[1]
						//Ex. "[f5565076-4567-4f91-bf69-2f654e245a20, 06743fce-d219-4945-bdc8-1bc34213c25c, 84b7dbf8-98e8-42fe-a3bc-5e48bacae0ab] [e5db9997-94b2-45ba-9ed4-3d5a8bb35717, 1bca5ad3-f24c-45f3-8bc8-9680cc0b59cb, c9cbda93-30e6-48f9-8000-c28b3fbc2786] [0b11c953-df78-42b4-ad10-2222d2367356, 3304e31d-ca63-49e5-b75c-dbae36ac0d18, c98f827b-bd27-4143-8f80-af9ae27a8134]"
						temp = strings.Replace(temp, "] [", "|", -1)
						temp = strings.Replace(temp, " ", "", -1)
						temp = strings.Replace(temp, "]", "", -1)
						temp = strings.Replace(temp, "[", "", -1)
						ext1 := []string{}
						ext2 := []string{}
						//Now looks like: "f5565076-4567-4f91-bf69-2f654e245a20,06743fce-d219-4945-bdc8-1bc34213c25c,84b7dbf8-98e8-42fe-a3bc-5e48bacae0ab|e5db9997-94b2-45ba-9ed4-3d5a8bb35717,1bca5ad3-f24c-45f3-8bc8-9680cc0b59cb,c9cbda93-30e6-48f9-8000-c28b3fbc2786|0b11c953-df78-42b4-ad10-2222d2367356,3304e31d-ca63-49e5-b75c-dbae36ac0d18,c98f827b-bd27-4143-8f80-af9ae27a8134"
						for _, ext1_item := range strings.Split(temp, "|") {
							ext1 = append(ext1, `"`+strings.Split(ext1_item, ",")[0]+`"`)
							tempdata := []string{}
							for _, ext2_item := range strings.Split(ext1_item, ",") {
								tempdata = append(tempdata, `"`+ext2_item+`"`)
							}
							ext2 = append(ext2, "["+strings.Join(tempdata, ",")+"]")
						}
						attr_ext1 = "[" + strings.Join(ext1, ",") + "]"
						attr_ext2 = "[" + strings.Join(ext2, ",") + "]"
					}
					state = STATE_EXPECTING_TIMESTAMP
					continue
				}

				if state == STATE_EXPECTING_TIMESTAMP {
					//regTimestamp     := regexp.MustCompile(`^[ \t]*<timestamp>(.*)</timestamp>$`)           //  <timestamp>2019-09-06T11:50:23.220Z</timestamp>
					m := regTimestamp.FindStringSubmatch(line)
					if len(m) < 2 {
						m2 := regTimestampClosed.FindStringSubmatch(line)
						if len(m2) < 1 {
							xmlFile.Close()
							c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not parse file '` + xmlFileName + `'. Expected Timestamp '^[ \t]*<timestamp>(.*)</timestamp>$' or '^[ \t]*<timestamp />$' on line ` + strconv.Itoa(rowCount) + `: ` + line}
							return
						}
						field_timestamp = ""
					} else {
						field_timestamp = m[1]
					}
					state = STATE_EXPECTING_EVENTTYPE
					continue
				}

				if state == STATE_EXPECTING_EVENTTYPE {
					//regType          := regexp.MustCompile(`^[ \t]*<eventType>(.*)</eventType>$`)           //  <eventType>dnsLookupEvent</eventType>
					m := regType.FindStringSubmatch(line)
					if len(m) < 2 {
						xmlFile.Close()
						c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not parse file '` + xmlFileName + `'. Expected Event Type '^[ \t]*<eventType>(.*)</eventType>$' on line ` + strconv.Itoa(rowCount) + `: ` + line}
						return
					}
					eventType = UpperCamelCase(m[1])
					val, exists := eventTypes[eventType]
					if !exists {
						eventTypeID = len(eventTypes)
						eventTypes[eventType] = eventTypeID
						tables = append(tables, [][]RowValue{})
						allHeaders = append(allHeaders, map[string]int{})
						allHeaders[eventTypeID]["Hostname"] = 0
						allHeaders[eventTypeID]["AgentID"] = 1
					} else {
						eventTypeID = val
					}

					if attr_uid != "" {
						row = add_value_to_row_eventbuffer("UID", attr_uid, allHeaders[eventTypeID], row, options, true)
					}
					if attr_sequence_num != "" {
						row = add_value_to_row_eventbuffer("Sequence Number", attr_sequence_num, allHeaders[eventTypeID], row, options, true)
					}
					if attr_ext1 != "" {
						row = add_value_to_row_eventbuffer(ExtraFunc7(options, 1), attr_ext1, allHeaders[eventTypeID], row, options, true)
					}
					if attr_ext2 != "" {
						row = add_value_to_row_eventbuffer(ExtraFunc7(options, 2), attr_ext2, allHeaders[eventTypeID], row, options, true)
					}
					if field_timestamp != "" {
						row = add_value_to_row_eventbuffer("EventBufferTime_"+eventType, field_timestamp, allHeaders[eventTypeID], row, options, true)
					}

					state = STATE_EXPECTING_DETAILSOPEN
					continue
				}

				if state == STATE_EXPECTING_DETAILSOPEN {
					//regDetailsOpen   := regexp.MustCompile(`^[ \t]*<details>$`)                             //  <details>
					m := regDetailsOpen.FindStringSubmatch(line)
					if len(m) == 0 {
						xmlFile.Close()
						c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not parse file '` + xmlFileName + `'. Expected Details Open Tag '^[ \t]*<details>$' on line ` + strconv.Itoa(rowCount) + `: ` + line}
						return
					}
					state = STATE_EXPECTING_DETAILOPEN_OR_DETAILSCLOSE
					continue
				}

				if state == STATE_EXPECTING_DETAILOPEN_OR_DETAILSCLOSE {
					//regDetailsClose  := regexp.MustCompile(`^[ \t]*</details>$`)                            //  </details>
					m := regDetailsClose.FindStringSubmatch(line)
					if len(m) != 0 {
						state = STATE_EXPECTING_EVENTCLOSE
						continue
					}

					//regDetailOpen    := regexp.MustCompile(`^[ \t]*<detail>$`)                              //   <detail>
					m2 := regDetailOpen.FindStringSubmatch(line)
					if len(m2) == 0 {
						xmlFile.Close()
						c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not parse file '` + xmlFileName + `'. Expected Details Open Tag '^[ \t]*<details>$' or Details Close Tag '^[ \t]*</details>$' on line ` + strconv.Itoa(rowCount) + `: ` + line}
						return
					}
					state = STATE_EXPECTING_DETAILNAME
					continue
				}

				if state == STATE_EXPECTING_DETAILNAME {
					//regName          := regexp.MustCompile(`^[ \t]*<name>(.*)</name>$`)                     //    <name>pid</name>
					m := regName.FindStringSubmatch(line)

					if len(m) < 2 {
						xmlFile.Close()
						c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not parse file '` + xmlFileName + `'. Expected Detail Name '^[ \t]*<name>(.*)</name>$ on line ` + strconv.Itoa(rowCount) + `: ` + line}
						return
					}
					field_name = UpperCamelCase(m[1])
					if field_name == "Hostname" {
						field_name = "DNSHostname"
					}
					state = STATE_EXPECTING_DETAILVALUE
					continue
				}

				if state == STATE_EXPECTING_DETAILVALUE {
					//regValueSL       := regexp.MustCompile(`^[ \t]*<value>(.*)</value>$`)                   //    <value>19052</value>
					m := regValueSL.FindStringSubmatch(line)
					if len(m) == 2 {
						value := m[1]
						row = add_value_to_row_eventbuffer(field_name, value, allHeaders[eventTypeID], row, options, true)
						field_name = ""
						state = STATE_EXPECTING_DETAILCLOSE
						continue
					}

					//regValueSLClosed := regexp.MustCompile(`^[ \t]*<value ?/>$`)                             //    <value />
					m3 := regValueSLClosed.FindStringSubmatch(line)
					if len(m3) == 1 {
						row = add_value_to_row_eventbuffer(field_name, "", allHeaders[eventTypeID], row, options, true)
						field_name = ""
						state = STATE_EXPECTING_DETAILCLOSE
						continue
					}

					//regValueMLOpen   := regexp.MustCompile(`^[ \t]*<value>(.*)$`)                           //    <value>POST /wsman HTTP/1.1
					m2 := regValueMLOpen.FindStringSubmatch(line)
					if len(m2) < 2 {
						xmlFile.Close()
						c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not parse file '` + xmlFileName + `'. Expected Detail Value SingleLine '^[ \t]*<value>(.*)</value>$' or MultiLine Open '^[ \t]*<value>(.*)$' on line ` + strconv.Itoa(rowCount) + `: ` + line}
						return
					}
					value := m2[1]
					row = add_value_to_row_eventbuffer(field_name, value, allHeaders[eventTypeID], row, options, true)
					state = STATE_EXPECTING_DETAILVALUECLOSE
					continue
				}

				if state == STATE_EXPECTING_DETAILVALUECLOSE {
					//regValueMLClose  := regexp.MustCompile(`^(.*)</value>$`)                                //</value>
					m := regValueMLClose.FindStringSubmatch(line)
					if len(m) == 0 {
						row = add_value_to_row_eventbuffer(field_name, line, allHeaders[eventTypeID], row, options, false)
						state = STATE_EXPECTING_DETAILVALUECLOSE
						continue
					}
					value := m[1]
					row = add_value_to_row_eventbuffer(field_name, value, allHeaders[eventTypeID], row, options, false)
					state = STATE_EXPECTING_DETAILCLOSE
					continue
				}

				if state == STATE_EXPECTING_DETAILCLOSE {
					//regDetailClose   := regexp.MustCompile(`^[ \t]*</detail>$`)                             //   </detail>
					m := regDetailClose.FindStringSubmatch(line)
					if len(m) == 0 {
						xmlFile.Close()
						c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not parse file '` + xmlFileName + `'. Expected Detail Close Tag '^[ \t]*</detail>$' on line ` + strconv.Itoa(rowCount) + `: ` + line}
						return
					}
					state = STATE_EXPECTING_DETAILOPEN_OR_DETAILSCLOSE
					continue

				}

				if state == STATE_EXPECTING_EVENTCLOSE {
					//regEventClose    := regexp.MustCompile(`^[ \t]*</eventItem>$`)                          // </eventItem>
					m := regEventClose.FindStringSubmatch(line)
					if len(m) == 0 {
						xmlFile.Close()
						c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not parse file '` + xmlFileName + `'. Expected Event Close Tag '^[ \t]*</eventItem>$' on line ` + strconv.Itoa(rowCount) + `: ` + line}
						return
					}

					state = STATE_EXPECTING_EVENTOPEN_OR_END
					continue
				}

				xmlFile.Close()
				c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `INTERNAL ERROR - Could not parse file '` + xmlFileName + `'. Unexpected state ` + strconv.Itoa(state) + ` on line ` + strconv.Itoa(rowCount) + `: ` + line}
				return
			}
			xmlFile.Close()
		}

		//Create the split files
		if len(tables) == 0 {
			c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `WARNING - File '` + xmlFileName + `' is empty.`}
			return
		}

		for eventType, eventTypeID := range eventTypes {

			headers := allHeaders[eventTypeID]
			rows := tables[eventTypeID]

			csvHeaders := []string{}

			//Add mandatory headers
			for _, h := range options.Config.HeadersMandatory {
				if _, exists := headers[h]; exists {
					csvHeaders = append(csvHeaders, h)
				} else {
					csvHeaders = append(csvHeaders, h)
				}
			}

			//Add optional headers if they exist
			for _, h := range options.Config.HeadersOptional {
				if _, exists := headers[h]; exists {
					csvHeaders = append(csvHeaders, h)
				} else if h == "EventBufferType" {
					csvHeaders = append(csvHeaders, h)
				}
			}

			//Get audit-specific config if it exists
			configindex := -1
			for i, c := range options.Config.AuditHeaderConfigs {
				if strings.ToLower(c.ItemName) == strings.ToLower("EventItem_"+eventType) {
					configindex = i
					break
				}
			}

			//Add audit-specific header order
			if configindex != -1 {
				for _, h := range options.Config.AuditHeaderConfigs[configindex].HeaderOrder {
					csvHeaders = append(csvHeaders, h)
				}

			}

			//Add remaining headers if allowed
			if !options.Config.OmitUnlisted {
				remainingHeaders := []string{}
				for h, _ := range headers {
					found := false
					for _, h2 := range csvHeaders {
						if h2 == h {
							found = true
							break
						}
					}
					if found {
						continue
					} else {
						remainingHeaders = append(remainingHeaders, h)
					}
				}

				//Case insensitive sort
				sort.Slice(remainingHeaders, func(i, j int) bool {
					return strings.ToLower(remainingHeaders[i]) < strings.ToLower(remainingHeaders[j])
				})

				//Remove specified headers
				if configindex != -1 {
					for _, h := range options.Config.AuditHeaderConfigs[configindex].HeadersOmitted {
						for i, h2 := range remainingHeaders {
							if h2 == h {
								remainingHeaders = append(remainingHeaders[0:i], remainingHeaders[i+1:len(remainingHeaders)]...)
							}
						}
					}
				}

				for _, h := range remainingHeaders {
					csvHeaders = append(csvHeaders, h)
				}
			}

			//Create rows
			csvRows := [][]string{csvHeaders}
			for j, _ := range rows {
				csvRow := make([]string, len(csvHeaders))
				for i, header := range csvHeaders {
					if header == "EventBufferType" {
						csvRow[i] = eventType
						continue
					}
					if header == "Hostname" {
						csvRow[i] = hostname
						continue
					}
					if header == "AgentID" {
						csvRow[i] = agentid
						continue
					}
					colID, exists := headers[header]
					if !exists {
						csvRow[i] = ""
						continue
					}
					for _, rowvalue := range rows[j] {
						if rowvalue.colid == colID {
							csvRow[i] = rowvalue.value
							break
						}
					}
				}
				csvRows = append(csvRows, csvRow)
			}

			//Truncate cell values to 32k if ExcelFriendly
			if options.ExcelFriendly {
				for i := 0; i < len(csvRows); i++ {
					for j := 0; j < len(csvRows[0]); j++ {
						if len(csvRows[i][j]) > 32000 {
							csvRows[i][j] = csvRows[i][j][0:32000] + "..."
						}
					}
				}
			}

			//Write file out with 1mil lines only if ExcelFriendly
			if options.ExcelFriendly && len(csvRows) > 999999 {

				splitfilepathtemp := filepath.Join(options.OutputPath, hostname+"-"+agentid+"-"+payload+"_spcsv1-EventItem_"+eventType+".csv.incomplete")
				splitfilepath := filepath.Join(options.OutputPath, hostname+"-"+agentid+"-"+payload+"_spcsv1-EventItem_"+eventType+".csv")

				csvFileTemp, err_c := os.Create(splitfilepathtemp)
				if err_c != nil {
					c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not create temp split file '` + filepath.Base(splitfilepathtemp) + `' to normal file '` + filepath.Base(splitfilepath) + `'. ` + err_c.Error()}
					return
				}
				csvout := csv.NewWriter(csvFileTemp)
				for i := 0; i < len(csvRows); i += 999999 {
					isLastChunk := i+999999 > len(csvRows)
					if isLastChunk {
						csvout.Write(csvHeaders)
						csvout.WriteAll(csvRows[i:])
						break
					}
					csvout.Write(csvHeaders)
					csvout.WriteAll(csvRows[i : i+999999])
					csvout.Flush()
					csvFileTemp.Close()
					err_r := os.Rename(splitfilepathtemp, splitfilepath)
					if err_r != nil {
						c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not rename temp file '` + filepath.Base(splitfilepathtemp) + `' to normal file '` + filepath.Base(splitfilepath) + `'. ` + err_r.Error()}
						return
					}

					splitfilepathtemp = filepath.Join(options.OutputPath, hostname+"-"+agentid+"-"+payload+"_spcsv"+strconv.Itoa((i/999999)+2)+"-EventItem_"+eventType+".csv.incomplete")
					splitfilepath = filepath.Join(options.OutputPath, hostname+"-"+agentid+"-"+payload+"_spcsv"+strconv.Itoa((i/999999)+2)+"-EventItem_"+eventType+".csv")
					var err_c error
					csvFileTemp, err_c = os.Create(splitfilepathtemp)
					if err_c != nil {
						c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not create temp split file '` + filepath.Base(splitfilepathtemp) + `' to normal file '` + filepath.Base(splitfilepath) + `'. ` + err_c.Error()}
						return
					}
					csvout = csv.NewWriter(csvFileTemp)
				}
				csvout.Flush()
				csvFileTemp.Close()
				err_r := os.Rename(splitfilepathtemp, splitfilepath)
				if err_r != nil {
					c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not rename temp file '` + filepath.Base(csvFilePathTemp) + `' to normal file '` + filepath.Base(csvFilePath) + `'. ` + err_r.Error()}
					return
				}
				//Write entire file out not split at all
			} else {
				csvFilePathEvent := csvFilePath + "EventItem_" + eventType + ".csv"
				csvFilePathEventTemp := csvFilePathEvent + ".incomplete"

				_, o_err := os.Stat(csvFilePath)
				if !options.ForceReparse && !options.WipeOutput && !os.IsNotExist(o_err) {
					continue
				}

				csvFileTemp, err_c := os.Create(csvFilePathEventTemp)
				if err_c != nil {
					c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not parse file '` + xmlFileName + `'. Could not create file '` + csvFilePathEventTemp + `'. ` + err_c.Error()}
					return
				}

				csvout := csv.NewWriter(csvFileTemp)
				csvout.WriteAll(csvRows)
				csvout.Flush()
				csvFileTemp.Close()
				err_r := os.Rename(csvFilePathEventTemp, csvFilePathEvent)
				if err_r != nil {
					c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Warnbox + `ERROR - Could not rename temp file '` + filepath.Base(csvFilePathTemp) + `' to normal file '` + filepath.Base(csvFilePath) + `'. ` + err_r.Error()}
					return
				}
			}

		}
	}
	c <- ThreadReturn_Parse{threadNum, xmlFileName, xmlFileSize, options.Box + `NOTICE - File '` + xmlFileName + `' parsed successfully.`}
}

func add_value_to_row_normal(header string, value string, headerPathParts []string, headers map[string]int, row map[int]*strings.Builder, options Options, existingGetsNewLine bool, include_value bool) {

	if !include_value {
		return
	}

	//Add path prefix to header
	if len(headerPathParts) > 0 {
		header = strings.Join(headerPathParts, ".") + "." + header
	}

	//Check to see if value is timestamp
	value = parse_time(value)

	//Check to see if new lines should be replaced
	if options.ReplaceNewLineFeeds {
		newlinechar := "|"
		value = strings.Replace(value, "\r\n", newlinechar, -1)
		value = strings.Replace(value, "\n", newlinechar, -1)
		value = strings.Replace(value, "\r", newlinechar, -1)
	}

	//Check if header already exists
	colID, headerExists := headers[header]
	if !headerExists {
		//Add header
		colID = len(headers)
		headers[header] = colID
	}

	//Check if value already exists
	_, valueExists := row[colID]
	if valueExists {
		if existingGetsNewLine {
			if options.ReplaceNewLineFeeds {
				value = "|" + value
			} else {
				value = "\r\n" + value
			}
		}
		row[colID].WriteString(value)
	} else {
		row[colID] = &strings.Builder{}
		row[colID].WriteString(value)
	}
}

func add_value_to_row_eventbuffer(header string, value string, headers map[string]int, row []RowValue, options Options, existingValueGetsNewLine bool) []RowValue {

	//Check to see if value is timestamp
	value = parse_time(value)

	//Check to see if new lines should be replaced
	if options.ReplaceNewLineFeeds {
		newlinechar := "|"
		value = strings.Replace(value, "\r\n", newlinechar, -1)
		value = strings.Replace(value, "\n", newlinechar, -1)
		value = strings.Replace(value, "\r", newlinechar, -1)
	}

	//Check if header already exists
	colID, headerExists := headers[header]
	if !headerExists {
		//Add header
		colID = len(headers)
		headers[header] = colID
	}

	//Determine if header exists already
	found := false
	for index, rowvalue := range row {
		if rowvalue.colid == colID {
			if existingValueGetsNewLine {
				if options.ReplaceNewLineFeeds {
					value = "|" + value
				} else {
					value = "\r\n" + value
				}
			}
			row[index].value += value
			found = true
			break
		}
	}

	//If header doesn't exist already
	if !found {
		rowValue := RowValue{}
		rowValue.colid = colID
		rowValue.value = value
		row = append(row, rowValue)
	}

	return row
}

//Parses a time value
func parse_time(timevalue string) string {
	length := len(timevalue)
	//2019-12-19T11:11:45.299Z
	if (length == 23 || length == 24) && timevalue[4] == '-' && timevalue[7] == '-' && timevalue[13] == ':' && timevalue[16] == ':' && timevalue[19] == '.' {
		return timevalue[0:10] + " " + timevalue[11:23]
	}
	//2019-12-19T11:11:45Z
	if (length == 19 || length == 20) && timevalue[4] == '-' && timevalue[7] == '-' && timevalue[13] == ':' && timevalue[16] == ':' {
		return timevalue[0:10] + " " + timevalue[11:19]
	}
	return timevalue
}
