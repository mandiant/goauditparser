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
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Timeline_Config_JSON struct {
	Version                    string   `json:"Version"`
	DontOverwrite              bool     `json:"Dont_Overwrite_With_New_Update"`
	TimeOutputFormat           string   `json:"Time_Output_Format"`
	IncludeSummaryHeaders      bool     `json:"Include_Summary_Headers"`
	UniqueRowPerTimestamp      bool     `json:"Unique_Row_Per_Timestamp"`
	IncludeTimestamplessAudits bool     `json:"Include_Timestampless_Audits"`
	ExtraFieldsOrder           []string `json:"Extra_Fields_Order"`
	Audits                     []struct {
		Name            string   `json:"Name"`
		FilenameSuffix  string   `json:"Filename_Suffix"`
		TimestampFields []string `json:"Timestamp_Fields"`
		SummaryFields   []string `json:"Summary_Fields"`
		ExtraFields     []string `json:"Extra_Fields"`
	} `json:"Audit_Timeline_Configs"`
}

func GoAuditTimeliner_Start(options Options) {

	if options.Verbose > 0 {
		fmt.Println(options.Box + "Starting timeline of CSV data...")
	}
	if !options.TimelineFilterEmpty {
		fmt.Println(options.Box + "Time Filters: ")
		for _, t := range options.TimelineFilters {
			fmt.Println(options.Box + "  + " + t[0].Format("2006-01-02 15:04:05") + " - " + t[1].Format("2006-01-02 15:04:05"))
		}
	}

	//Read Input Directory
	files, err_r := ioutil.ReadDir(options.OutputPath)
	if err_r != nil {
		fmt.Println(options.Warnbox + "ERROR - Could not read output directory '" + options.OutputPath + "'.")
		log.Fatal(err_r)
	}

	//Ignore unwanted files
	for i := 0; i < len(files); i++ {
		name := filepath.Base(files[i].Name())
		if strings.HasPrefix(name, "_Timeline_") || !strings.HasSuffix(name, ".csv") {
			files = append(files[:i], files[i+1:]...)
			i--
			continue
		}
	}

	if len(files) == 0 {
		fmt.Println(options.Warnbox + "ERROR - Could not identify any files in output directory '" + options.OutputPath + "'.")
		return
	}

	//Create Output File
	outputFilePath := options.TimelineOutputFile
	if outputFilePath == "" {
		outputFilePath = filepath.Join(options.OutputPath, "_Timeline_<DATE>_<TIME>.csv")
	}
	currentTime := time.Now()
	outputFilePath = strings.ReplaceAll(outputFilePath, "<DATE>", currentTime.Format("2006-01-02"))
	outputFilePath = strings.ReplaceAll(outputFilePath, "<TIME>", currentTime.Format("1504"))

	if options.Verbose > 0 {
		fmt.Println(options.Box + "Creating output timeline file '" + outputFilePath + "'...")
	}
	outputFile, err_c := os.Create(outputFilePath)
	if err_c != nil {
		fmt.Println(options.Warnbox + "ERROR - Could not create timeline file '" + outputFilePath + "'.")
		log.Fatal(err_c)
	}
	writer := csv.NewWriter(outputFile)

	//Check for JSON Config File
	if options.Verbose > 0 {
		fmt.Println(options.Box + "Reading timeline config file '" + options.TimelineConfigFile + "'...")
	}
	_, err_s := os.Stat(options.TimelineConfigFile)
	//If timelinefile file exists, create the file
	if os.IsNotExist(err_s) {
		//Create timeline config file
		fmt.Println(options.Warnbox + "NOTICE - Timeline config file '" + options.TimelineConfigFile + "' does not exist. Creating new one...")
		file, err_c := os.Create(options.TimelineConfigFile)
		if err_c != nil {
			fmt.Println(options.Box + "ERROR - Could not create file '" + options.TimelineConfigFile + "'.")
			log.Fatal(err_c)
		}
		file.WriteString(GetTimelineConfigTemplate())
		file.Close()
	}

	//Read JSON from timeline config file
	file, err_o := os.Open(options.TimelineConfigFile)
	if err_o != nil {
		fmt.Println(options.Warnbox + "ERROR - Could not open file '" + options.TimelineConfigFile + "'.")
		log.Fatal(err_o)
	}
	b, err_i := ioutil.ReadAll(file)
	if err_i != nil {
		fmt.Println(options.Warnbox + "ERROR - Could not read contents from '" + options.TimelineConfigFile + "'.")
		log.Fatal(err_i)
	}
	var config Timeline_Config_JSON
	err_j := json.Unmarshal(b, &config)
	if err_j != nil {
		fmt.Println(options.Warnbox + "ERROR - Could not read parse JSON from '" + options.TimelineConfigFile + "'.")
		log.Fatal(err_j)
	}
	file.Close()
	if config.Version != version {
		if !config.DontOverwrite {
			fmt.Println(options.Box + "Updating old timeline config v" + config.Version + " to v" + version + "...")
			//Write new JSON to timeline file
			newFile, err_c := os.Create(options.TimelineConfigFile)
			if err_c != nil {
				fmt.Println(options.Warnbox + "ERROR - Could not create new version of file '" + options.TimelineConfigFile + "'")
				log.Fatal(err_c)
			}
			newFile.WriteString(GetTimelineConfigTemplate())
			newFile.Close()
			//Parse in-memory config file
			err_j := json.Unmarshal([]byte(GetTimelineConfigTemplate()), &config)
			if err_j != nil {
				fmt.Println(options.Warnbox + "ERROR - Could not parse pre-made JSON. Please contact the developer.'")
				log.Fatal(err_j)
			}
		} else {
			fmt.Println(options.Warnbox + "NOTICE - New timeline configuration version is available, but the JSON property 'Dont_Overwrite_With_New_Update' is set to 'true'.")
			time.Sleep(time.Second * 1)
		}
	}
	//Set options specific format override
	if options.MinimizedOutput {
		config.IncludeSummaryHeaders = true
		config.UniqueRowPerTimestamp = false
		config.IncludeTimestamplessAudits = true
	}

	//Create index map of timeline configs
	audit2index := map[string]int{}
	for i, audit := range config.Audits {
		audit2index[audit.FilenameSuffix] = i
	}

	//Create index map of extra headers
	extra2index := map[string]int{}
	for i, extraHeader := range config.ExtraFieldsOrder {
		extra2index[extraHeader] = i
	}

	//Create headers
	headers := []string{"Timestamp", "Timestamp Description", "Summary", "Source"}
	headers = append(headers, config.ExtraFieldsOrder...)

	type TimeRow struct {
		Source               string
		Timestamp            string
		TimestampDescription map[string]bool
		SummaryColumns       map[string]map[string]bool
		ExtraColumns         map[string]map[string]map[string]bool
		Count                int
	}

	//Master table of data
	rows := map[string]*TimeRow{}

	//Start time of timer
	start := time.Now()
	c_tqdm := make(chan bool)
	go TQDM(len(files), options, options.Box+"Timelining", c_tqdm)

	threadMessages := []string{}

	//Iterate through files in directory
	for _, file := range files {

		//Find audit type
		//fileSplit := strings.Split(file.Name(),"-")
		auditType := strings.TrimSuffix(file.Name(), ".csv")
		auditExists := false
		for k, _ := range audit2index {
			if strings.HasSuffix(auditType, k) {
				auditExists = true
				auditType = k
				break
			}
		}
		if !auditExists {
			threadMessages = append(threadMessages, options.Warnbox+"WARNING - No configuration matching the suffix of file '"+file.Name()+"'.")
			c_tqdm <- true
			continue
		}
		auditConfigIndex, _ := audit2index[auditType]
		auditConfig := config.Audits[auditConfigIndex]
		//Open CSV file
		fullPath := filepath.Join(options.OutputPath, file.Name())
		opencsvfile, err_o := os.Open(fullPath)
		if err_o != nil {
			fmt.Println(options.Warnbox + "ERROR - Could not open file '" + fullPath + "'.")
			log.Fatal(err_o)
		}
		csvreader := csv.NewReader(opencsvfile)
		headers, err_r := csvreader.Read()
		if err_r != nil {
			if err_r == io.EOF {
				threadMessages = append(threadMessages, options.Warnbox+"WARNING - Could not read data as CSV for file '"+file.Name()+"'.")
			} else {
				threadMessages = append(threadMessages, options.Warnbox+"WARNING - Empty CSV file: '"+file.Name()+"'")
			}
			c_tqdm <- true
			continue
		}

		//Determine available time headers
		timeColIndexes := []int{}
		timeColNames := []string{}
		for _, timeHeader := range auditConfig.TimestampFields {
			originalHeader := timeHeader
			convertedHeader := timeHeader
			if strings.Contains(timeHeader, ">") {
				originalHeader = strings.Split(timeHeader, ">")[0]
				convertedHeader = strings.Split(timeHeader, ">")[1]
			}
			for iCol, header := range headers {
				if originalHeader == header {
					timeColIndexes = append(timeColIndexes, iCol)
					parts := strings.Split(convertedHeader, ".") //Make "FileItem.Created" just "Created"
					lastPart := parts[len(parts)-1]
					timeColNames = append(timeColNames, lastPart)
				}
			}
		}
		if options.Verbose > 2 {
			fmt.Println(options.Box + "- Identified the following Timestamp Headers: \"" + strings.Join(timeColNames, ",") + "\"")
		}
		//Determine available summary headers
		summaryColIndexes := []int{}
		summaryColNames := []string{}
		for _, summaryHeader := range auditConfig.SummaryFields {
			originalHeader := summaryHeader
			convertedHeader := summaryHeader
			if strings.Contains(summaryHeader, ">") {
				originalHeader = strings.Split(summaryHeader, ">")[0]
				convertedHeader = strings.Split(summaryHeader, ">")[1]
			}
			for iCol, header := range headers {
				if originalHeader == header {
					summaryColIndexes = append(summaryColIndexes, iCol)
					summaryColNames = append(summaryColNames, convertedHeader)
				}
			}
		}
		if options.Verbose > 2 {
			fmt.Println(options.Box + "- Identified the following Summary Headers: \"" + strings.Join(summaryColNames, ",") + "\"")
		}
		//Determine available extra headers
		extraColIndexes := [][]int{}
		extraColAllNames := [][]string{} //Name Parts: [["Status", "crontabMinute", "crontabHour", "crontabDayOfMonth"], etc.]
		extraColNames := []string{}      //Full Name:  ["Status||crontabMinute||crontabHour||crontabDayOfMonth", etc.]
		for _, extraHeader := range auditConfig.ExtraFields {
			//"Md5sum>MD5"
			//"extraHeader>convertedHeader"
			convertedHeader := extraHeader
			if strings.Contains(extraHeader, ">") {
				convertedHeader = strings.Split(extraHeader, ">")[1]
				extraHeader = strings.Split(extraHeader, ">")[0]
			}
			for iCol, header := range headers {
				found := false
				cols := []int{}
				names := []string{}
				for _, extraHeaderPart := range strings.Split(extraHeader, "||") {
					if extraHeaderPart == header {
						cols = append(cols, iCol)
						names = append(names, extraHeaderPart)
						found = true
					}
				}
				if found {
					extraColAllNames = append(extraColAllNames, names)
					extraColNames = append(extraColNames, convertedHeader)
					extraColIndexes = append(extraColIndexes, cols)
				}
			}
		}
		if options.Verbose > 2 {
			fmt.Println(options.Box + "- Identified the following Extra Headers: \"" + strings.Join(extraColNames, ",") + "\"")
		}
		//Iterate through the CSV rows
		iRow := -1

		source := auditType
		for {
			//Read row
			iRow++
			row, err_r := csvreader.Read()
			if err_r != nil {
				if err_r != io.EOF {
					threadMessages = append(threadMessages, options.Warnbox+"WARNING - Could not read row index "+strconv.Itoa(iRow)+" of file '"+fullPath+"'.", err_r.Error())
				}
				break
			}

			//Identify all timestamps
			//map[Time]map[Description]true
			times := map[string]map[string]bool{}
			//Get Timestamps and Descriptions
			for i, iCol := range timeColIndexes {
				timestamp := row[iCol]
				description := timeColNames[i]
				//Add event if no time filter
				if options.TimelineFilterEmpty {
					if _, exists := times[timestamp]; !exists {
						times[timestamp] = map[string]bool{}
					}
					times[timestamp][description] = true
					//Check if timestamp is in the provided time filters
				} else {
					t, err_t1 := time.Parse("2006-01-02 15:04:05", timestamp)
					var err_t2 error
					if err_t1 != nil {
						t, err_t2 = time.Parse("2006-01-02 15:04:05.000", timestamp)
					}
					if err_t2 != nil && options.Verbose > 0 {
						fmt.Println(options.Warnbox+"WARNING -", err_t1)
					}
					for _, f := range options.TimelineFilters {
						if err_t1 == nil && f[0].Before(t) && f[1].After(t) {
							if _, exists := times[timestamp]; !exists {
								times[timestamp] = map[string]bool{}
							}
							times[timestamp][description] = true
							break
						}
					}
				}
			}
			if len(times) == 0 {
				if config.IncludeTimestamplessAudits && options.TimelineFilterEmpty {
					times["N/A"] = map[string]bool{}
					times["N/A"]["N/A"] = true
				} else {
					continue
				}
			}

			//Identify all summary values
			//map[Header]map[Value]true
			summaries := map[string]map[string]bool{}
			//Get Summary Values
			for i, iCol := range summaryColIndexes {
				value := row[iCol]
				if len(value) == 0 {
					continue
				}
				header := summaryColNames[i]
				if _, exists := summaries[header]; !exists {
					summaries[header] = map[string]bool{}
				}
				summaries[header][value] = true
			}

			//Identify all extra values
			//map[Header]map[ActualHeader]map[Value]true
			//map["Status||crontabMinute||crontabHour"]map["crontabMinute"]map["01"] = true
			extras := map[string]map[string]map[string]bool{}
			//Get Extra Values
			for i, iCols := range extraColIndexes {
				for _, iCol := range iCols {
					value := row[iCol]
					if len(value) == 0 {
						continue
					}
					header := extraColNames[i]
					for _, actualHeader := range extraColAllNames[i] {
						if _, exists := extras[header]; !exists {
							extras[header] = map[string]map[string]bool{}
						}
						if _, exists := extras[header][actualHeader]; !exists {
							extras[header][actualHeader] = map[string]bool{}
						}
						extras[header][actualHeader][value] = true
					}
				}
			}

			//Create a row for each unique timestamp
			for timeValue, descriptions := range times {
				//Create a unique string for hashmap
				mergedSummary := ""
				for _, valueMap := range summaries {
					for value, _ := range valueMap {
						mergedSummary += value
					}
				}
				mergedExtras := ""
				for _, valueMap := range extras {
					for _, valueMap2 := range valueMap {
						for value, _ := range valueMap2 {
							mergedExtras += value
						}
					}
				}
				mergedHostnames := "" //Should only ever be one hostname!
				valueHostname, exists := extras["Hostname"]
				if exists {
					for value, _ := range valueHostname {
						mergedHostnames += value
					}
				}
				uniqueStr := timeValue + source + mergedSummary + mergedExtras + mergedHostnames
				//Check if row already exists!
				tRow, rowExists := rows[uniqueStr]
				if rowExists {
					for description, _ := range descriptions {
						tRow.TimestampDescription[description] = true
					}
					tRow.Count++
					rows[uniqueStr] = tRow
				} else {
					tRow = &TimeRow{
						source,       //Source                  string
						timeValue,    //Timestamp               string
						descriptions, //TimestampDescription    map[string]bool
						summaries,    //SummaryColumns          map[string]map[string]bool
						extras,       //ExtraColumns            map[string]map[string]bool
						0,            //Count                   int
					}
					rows[uniqueStr] = tRow
				}
			}
		}
		opencsvfile.Close()
		threadMessages = append(threadMessages, options.Box+"NOTICE - Successfully timelined file '"+filepath.Base(file.Name())+"'.")
		c_tqdm <- true
	}

	time.Sleep(10 * time.Millisecond)
	for _, msg := range threadMessages {
		if strings.Contains(msg, "Successfully timelined") {
			if options.Verbose > 0 {
				fmt.Println(msg)
			}
		} else {
			fmt.Println(msg)
		}
	}

	fmt.Println(options.Box + "Finalizing timeline...")

	if options.Verbose > 0 {
		fmt.Println(options.Box+"- Determined", len(rows), "timeline rows.")
	}
	if len(rows) == 0 {
		writer.Flush()
		outputFile.Close()
		fmt.Println(`[!] WARNING - No rows identified for the timeline. Possible reasons:
    1. The specified audit data does not have any timestamps.
    2. The specified output path does not contain any audit data.
    3. The timeline configuration file "` + options.TimelineConfigFile + `" isn't set up properly.`)
		fmt.Printf(`[!] If the issue persists, please contact the GoAuditParser developer.`)
		if !options.MinimizedOutput {
			fmt.Printf("\n")
		}
		return
	}

	debug.FreeOSMemory()

	//Sort
	uniqueStrings := []string{}
	for str, _ := range rows {
		uniqueStrings = append(uniqueStrings, str)
	}
	if !options.TimelineDeduplicate {
		if options.Verbose > 0 {
			fmt.Println(options.Box + "Sorting timeline...")
		}
		sort.Strings(uniqueStrings)
		debug.FreeOSMemory()
	}

	//Write each row to file
	if options.Verbose > 0 {
		fmt.Println(options.Box + "Assembling timeline...")
	}
	table := [][]string{}
	for _, str := range uniqueStrings {
		row := rows[str]
		//Source
		source := row.Source
		auditConfigIndex, _ := audit2index[source]
		auditConfig := config.Audits[auditConfigIndex]
		//Timestamp
		timestamp := row.Timestamp
		//Timestamp Description
		descriptions := []string{}
		for tdesc, _ := range row.TimestampDescription {
			descriptions = append(descriptions, tdesc)
		}
		sort.Strings(descriptions)
		description := strings.Join(descriptions, " && ")
		//Summary
		summaries := []string{}
		for _, header := range auditConfig.SummaryFields {
			convertedHeader := header
			if strings.Contains(header, ">") {
				convertedHeader = strings.Split(header, ">")[1]
			}

			valueMap, exists := row.SummaryColumns[convertedHeader]
			if !exists {
				continue
			}
			if config.IncludeSummaryHeaders {
				for value, _ := range valueMap {
					summaries = append(summaries, convertedHeader+": "+value)
				}
			} else {
				for value, _ := range valueMap {
					summaries = append(summaries, value)
				}
			}
		}
		summary := strings.Join(summaries, " || ")
		//Extras
		extras := make([]string, len(config.ExtraFieldsOrder))
		for _, extraHeader := range auditConfig.ExtraFields {
			//"Md5sum>MD5"
			//"extraHeader>convertedHeader"
			convertedHeader := extraHeader
			if strings.Contains(extraHeader, ">") {
				convertedHeader = strings.Split(extraHeader, ">")[1]
				extraHeader = strings.Split(extraHeader, ">")[0]
			}
			valueMap, exists := row.ExtraColumns[convertedHeader]
			if !exists {
				continue
			}
			i := extra2index[convertedHeader]

			//Get sorted array of extra field subheaders
			actualHeaders := []string{}
			for actualHeader, _ := range valueMap {
				actualHeaders = append(actualHeaders, actualHeader)
			}
			sort.Strings(actualHeaders)

			extraValue := ""
			for _, actualHeader := range actualHeaders {
				actualHeaderMap := valueMap[actualHeader]
				for value, _ := range actualHeaderMap {
					valueForField := value
					if config.IncludeSummaryHeaders && (strings.HasPrefix(convertedHeader, "Extra") || convertedHeader == "SubAuditType") {
						valueForField = actualHeader + ": " + value
					}
					extraValue = strings.Join([]string{extraValue, valueForField}, " || ")
				}
			}
			extraValue = strings.TrimPrefix(extraValue, " || ")
			extras[i] = extraValue
		}
		//If config file tells us to have a unique row per timestamp description
		if config.UniqueRowPerTimestamp {
			for _, tdesc := range descriptions {
				//Write row per timestamp description
				outRow := append([]string{timestamp, tdesc, summary, source}, extras...)
				if options.ExcelFriendly {
					truncate32k(outRow)
				}
				table = append(table, outRow)
			}
		} else {
			//Write row per timestamp
			outRow := append([]string{timestamp, description, summary, source}, extras...)
			if options.ExcelFriendly {
				truncate32k(outRow)
			}
			table = append(table, outRow)
		}
	}

	debug.FreeOSMemory()

	if options.TimelineDeduplicate {

		fmt.Println(options.Box + "Deduplicating timeline...")

		//Deduplicate rows
		uniqueRows := map[string]bool{}
		uniqueOrder := []int{}

		//Process Contents
		for j, _ := range table {
			mergedRow := strings.Join(table[j], "")
			if _, exists := uniqueRows[mergedRow]; exists {
				continue
			}
			uniqueRows[mergedRow] = true
			uniqueOrder = append(uniqueOrder, j)
		}

		newContents := [][]string{}
		for _, index := range uniqueOrder {
			row := table[index]
			newContents = append(newContents, row)
		}
		table = newContents

		debug.FreeOSMemory()

		if options.Verbose > 0 {
			fmt.Println(options.Box + "Sorting timeline...")
		}

		//Sort rows
		sortableHeaderIndexes := []int{}
		for _, sHeader := range []string{"Summary", "Timestamp"} {
			for j, fHeader := range headers {
				if sHeader == fHeader {
					sortableHeaderIndexes = append(sortableHeaderIndexes, j)
					break
				}
			}
		}
		for _, sortableHeaderIndex := range sortableHeaderIndexes {
			table = QuickSort_StringTable_ByColumn_NoHeader(table, sortableHeaderIndex)
		}

		debug.FreeOSMemory()
	}

	if options.TimelineSOD {
		fmt.Println(options.Box + "Converting timeline to SOD format...")
		for i, _ := range headers {
			if headers[i] == "Timestamp" {
				headers[i] = "Timestamp (UTC)"
			} else if headers[i] == "Summary" {
				headers[i] = "Event Description"
			} else if headers[i] == "User" {
				headers[i] = "Owner / Associated User"
			} else if headers[i] == "AgentID" {
				headers[i] = "Agent ID"
			} else if headers[i] == "MD5" {
				headers[i] = "Associated MD5"
			}
		}
		desiredorder := []string{"Date Added", "Timestamp (UTC)", "Timestamp Description", "Hostname", "Agent ID", "Attribution", "Event Description", "Notes", "Owner / Associated User", "Associated MD5", "Associated SHA1", "Size", "Source IP", "Source Domain", "Destination IP", "Desintation Domain", "Data Theft", "MD5 HBI"}
		table, headers = StringTable_SetColumnOrder(headers, desiredorder, table)

		debug.FreeOSMemory()
	}

	lasttimelinefilename := outputFilePath
	//Split file if we are at 1mil rows for excel friendly mode
	if options.ExcelFriendly && len(table) > 999999 {
		fmt.Println(options.Box + "Writing Excel-friendly timeline(s)...")
		//lineCount % 1000000 == 0) {
		for i := 0; i < len(table); i += 999999 {
			isLastChunk := i+999999 > len(table)
			if isLastChunk {
				writer.WriteAll(append([][]string{headers}, table[i:]...))
				break
			}
			writer.WriteAll(append([][]string{headers}, table[i:i+999999]...))
			//Close previous timeline file
			writer.Flush()
			outputFile.Close()
			//Create new timeline file

			ap, _ := filepath.Abs(lasttimelinefilename)
			if options.Verbose > 0 || options.MinimizedOutput {
				fmt.Println(options.Box + "Timeline file: " + ap)
			}
			outputFilePathNew := strings.TrimSuffix(outputFilePath, ".csv") + "_" + strconv.Itoa((i/999999)+1) + ".csv"
			lasttimelinefilename = outputFilePathNew
			if options.Verbose > 0 {
				fmt.Println(options.Box + "Splitting output at " + strconv.Itoa((i/999999)+1) + "mil rows to timeline file '" + outputFilePathNew + "'...")
			}
			var err_c error
			outputFile, err_c = os.Create(outputFilePathNew)
			if err_c != nil {
				fmt.Println(options.Warnbox + "ERROR - Could not create timeline split file '" + outputFilePathNew + "'.")
				log.Fatal(err_c)
			}
			writer = csv.NewWriter(outputFile)
		}
	} else {
		fmt.Println(options.Box + "Writing timeline...")
		writer.WriteAll(append([][]string{headers}, table...))
	}

	writer.Flush()
	outputFile.Close()
	ap, _ := filepath.Abs(lasttimelinefilename)
	if options.Verbose > 0 || options.MinimizedOutput {
		fmt.Println(options.Box + "Timeline file: " + ap)
	}

	elapsed := time.Since(start)
	time.Sleep(10 * time.Millisecond)

	fmt.Printf(options.Box+"Timelined %d file(s) in %s.", len(files), elapsed.Truncate(time.Millisecond).String())
	if options.Timeline || !options.MinimizedOutput {
		fmt.Printf("\n")
	}

}

func QuickSort_StringTable_ByColumn_NoHeader(table [][]string, columnIndex int) [][]string {
	//Get Length of stack
	length := len(table)

	//Base Case: If there is one item remaining, let's return it alone.
	if length <= 1 {
		listCopy := make([][]string, length)
		copy(listCopy, table)
		return listCopy
	}

	//Recursive Case: Pick a random index within length of stack
	m := table[rand.Intn(length)][columnIndex]

	//Make three partitions, with "middle" containing any similar items
	less := make([][]string, 0, length)
	middle := make([][]string, 0, length)
	more := make([][]string, 0, length)

	//Iterate through every item in stack, comparing items to selected random index,
	// and put into appropriate new array (sorting)
	for i := 0; i < length; i++ {
		row := table[i]
		value := table[i][columnIndex]
		switch {
		case (value > m):
			less = append(less, row)
		case (value == m):
			middle = append(middle, row)
		case (value < m):
			more = append(more, row)
		}
	}

	//Recursively sort the new partitions
	less, more = QuickSort_StringTable_ByColumn_NoHeader(less, columnIndex), QuickSort_StringTable_ByColumn_NoHeader(more, columnIndex)

	//Concatenate the sorted partitions
	more = append(more, middle...)
	more = append(more, less...)

	//Return sorted partition (or completely sorted stack if this is the first function call)
	return more
}

func StringTable_SetColumnOrder(headers []string, desiredorder []string, table [][]string) ([][]string, []string) {

	for destColIndex, _ := range desiredorder {
		sourceColIndex := -1
		for colIndex, _ := range headers {
			if headers[colIndex] == desiredorder[destColIndex] {
				sourceColIndex = colIndex
				break
			}
		}

		isDateAdded := desiredorder[destColIndex] == "Date Added"
		isTimestampDesc := desiredorder[destColIndex] == "Timestamp Description"

		//If column doesn't exist
		if sourceColIndex == -1 {
			//Add header
			headers = append(headers[:destColIndex], append([]string{desiredorder[destColIndex]}, headers[destColIndex:]...)...)
			//Add empty cell to each row in table
			value := ""
			if isDateAdded {
				value = time.Now().Format("2006-01-02")
			}
			for i := 0; i < len(table); i++ {
				table[i] = append(table[i][:destColIndex], append([]string{value}, table[i][destColIndex:]...)...)
			}

			//If column does exist
		} else {
			//Remove header
			headers = append(headers[:sourceColIndex], headers[sourceColIndex+1:]...)
			//Add header
			headers = append(headers[:destColIndex], append([]string{desiredorder[destColIndex]}, headers[destColIndex:]...)...)

			sourceIndex := -1
			for i, _ := range headers {
				if headers[i] == "Source" {
					sourceIndex = i
					break
				}
			}
			for i := 0; i < len(table); i++ {
				value := table[i][sourceColIndex]

				if isTimestampDesc {
					source := ""
					if sourceIndex != -1 {
						source = table[i][sourceIndex]
						if strings.HasPrefix(source, "EventItem_") {
							source = "EventItem"
						}
					}

					value = source + ":" + strings.ReplaceAll(value, " && ", " ")
				}
				//Remove value
				table[i] = append(table[i][:sourceColIndex], table[i][sourceColIndex+1:]...)
				//Add value
				table[i] = append(table[i][:destColIndex], append([]string{value}, table[i][destColIndex:]...)...)
			}
		}
	}
	return table, headers
}

func truncate32k(arr []string) {
	for i, _ := range arr {
		if len(arr[i]) > 32000 {
			arr[i] = arr[i][0:32000] + "..."
		}
	}
}
