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
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func GoAuditEventSplitter_Start(options Options) {
	//Set Random seed for GUIDs
	rand.Seed(time.Now().UnixNano())

	// Make output directory if it doesn't exist
	if _, err := os.Stat(options.EventBufferSplitDir); os.IsNotExist(err) {
		if err = os.MkdirAll(options.EventBufferSplitDir, os.ModePerm); err != nil {
			fmt.Println(options.Warnbox + "ERROR - Could not create output directory '" + options.EventBufferSplitDir + "'.")
			log.Fatal(err)
		}
	} else if options.WipeOutput {
		outputfiles, _ := ioutil.ReadDir(options.EventBufferSplitDir)
		if len(outputfiles) > 0 {
			fmt.Println(options.Box + "Deleting all pre-existing XML files in the output directory '" + options.EventBufferSplitDir + "' as specified with the '-wo' flag.")
			for _, file := range outputfiles {
				var filename = file.Name()
				if strings.HasSuffix(filename, ".xml") {
					fmt.Println(options.Box + "Removing pre-existing XML file '" + filename + "'...")
					os.Remove(filepath.Join(options.EventBufferSplitDir, filename))
				}
			}
		}
	}

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

	fmt.Println(options.Box + "Splitting eventbuffer and stateagentinspector audits...")
	for _, file := range files {
		//skip files already split        // Split EventBuffer Files
		if filepath.Ext(file.Name()) == ".issues" || strings.HasSuffix(strings.TrimSuffix(filepath.Base(file.Name()), filepath.Ext(file.Name())), "issues") {
			continue
		}
		if strings.Contains(file.Name(), "-eventbuffer") {
			fmt.Println(options.Box + "Splitting '" + file.Name() + "'...")
			originalFileName := filepath.Join(options.InputPath, file.Name())
			originalFile, err_o := os.Open(originalFileName)
			if err_o != nil {
				fmt.Println(options.Warnbox + "ERROR - Could not open file '" + originalFileName + "' to split.")
				log.Fatal(err_o)
			}

			parts := strings.Split(file.Name(), "-")
			if len(parts) < 4 {
				fmt.Println(options.Warnbox + "ERROR - File '" + originalFileName + "' does not match standard naming scheme, and could not be split.")
			}
			hostname := strings.Join(parts[0:len(parts)-3], "-")
			agentid := parts[len(parts)-3]
			payload := parts[len(parts)-2]
			splitFileNameStart := filepath.Join(options.EventBufferSplitDir, hostname+"-"+agentid+"-"+payload+"-")

			//https://stackoverflow.com/questions/21124327/how-to-read-a-text-file-line-by-line-in-go-when-some-lines-are-long-enough-to-ca
			scanner := bufio.NewScanner(originalFile)
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

			splitEventFiles := map[string][]string{}

			header := ""
			record := ""
			eventType := ""
			fieldType := ""

			attr_uid := ""
			attr_sequence_num := ""
			attr_hits := ""

			//For every line in file
			for scanner.Scan() {
				rowCount++
				line := scanner.Text()
				// <?xml version="1.0" encoding="UTF-8"?>
				if state == STATE_HEADER && rowCount == 1 {
					line = strings.TrimSpace(line)
					if !strings.HasPrefix(line, "<?xml ") {
						fmt.Println(options.Warnbox + "ERROR - Unexpected 1st Line: '" + line + "'.")
						return
					}
					header = line + "\n"
					continue
				}
				// <itemList generator="eventbuffer" generatorVersion="29.7.8" itemSchemaLocation="http://schemas.mandiant.com/2013/11/stateagentinspectoritem.xsd" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="http://schemas.mandiant.com/2013/11/stateagentinspectoritem.xsd">
				if state == STATE_HEADER && rowCount == 2 {
					line = strings.TrimSpace(line)
					if !strings.HasPrefix(line, "<itemList ") {
						fmt.Println(options.Warnbox + "ERROR - Unexpected 2nd Line: '" + line + "'.")
						return
					}
					header += `<itemList generator="eventbufferGAP" generatorVersion="29.7.8">` + "\n"
					state = STATE_EXPECTING_EVENTOPEN_OR_END
					continue
				}

				if state == STATE_EXPECTING_EVENTOPEN_OR_END {

					//END
					if line == "</itemList>" {
						//Finish up...
						state = STATE_FINISHED
						break
					}
					//Check if <eventItem.*>
					m := regEventOpen.FindStringSubmatch(line)
					if len(m) < 1 {
						fmt.Println(options.Warnbox + `ERROR - Expected '^[ \t]*<eventItem.*>' or '</itemList>' on line ` + strconv.Itoa(rowCount) + `: ` + line)
						return
					}

					//Reset and get attributes
					attr_uid = ""
					attr_sequence_num = ""
					attr_hits = ""
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
						attr_hits = mHITS[1]
					}
					state = STATE_EXPECTING_TYPEOPEN
					continue
				}

				if state == STATE_EXPECTING_TYPEOPEN {
					m := regTypeOpen.FindStringSubmatch(line)
					if len(m) < 2 {
						fmt.Println(options.Warnbox + `ERROR - Expected Event Type '^[ \t]*<([A-Za-z0-9]+)>' on line ` + strconv.Itoa(rowCount) + `: ` + line)
						return
					}
					eventType = UpperCamelCase(m[1])
					record = " <" + eventType + "Item"
					if len(attr_hits) != 0 {
						record += ` hits="` + attr_hits + `"`
					}
					record += ` uid="` + NewGUID() + `"`
					record += ` created="` + time.Now().UTC().Format("2006-01-02T15:04:05Z") + `"`
					if len(attr_sequence_num) != 0 {
						record += ` sequence_num="` + attr_sequence_num + `"`
					}
					if len(attr_uid) != 0 {
						record += ` old_uid="` + attr_uid + `"`
					}
					record += ">\n"
					state = STATE_EXPECTING_FIELDOPEN_OR_TYPECLOSE
					continue
				}

				if state == STATE_EXPECTING_FIELDOPEN_OR_TYPECLOSE {
					//regTypeClose   := regexp.MustCompile(`[ \t]*</([A-Za-z0-9]+)>$`)                   // </urlMonitorEvent>
					m1 := regTypeClose.FindStringSubmatch(line)
					if len(m1) > 1 {
						eventCloseType := UpperCamelCase(m1[1])
						if eventType != eventCloseType {
							fmt.Println(options.Warnbox + `ERROR - Event Type Close did not match '` + eventType + `' on line ` + strconv.Itoa(rowCount) + `: ` + line)
							return
						}
						record += " </" + eventType + "Item>\n"
						if _, exists := splitEventFiles[eventType]; !exists {
							splitEventFiles[eventType] = []string{}
						}
						splitEventFiles[eventType] = append(splitEventFiles[eventType], record)
						record = ""
						eventType = ""
						attr_uid = ""
						attr_sequence_num = ""
						attr_hits = ""
						state = STATE_EXPECTING_EVENTCLOSE
						continue
					}
					//regFieldSL       := regexp.MustCompile(`[ \t]*<([A-Za-z0-9]+)>(.*)</[A-Za-z0-9]+>$`)     //  <remoteIpAddress>10.34.155.235</remoteIpAddress>
					m2 := regFieldSL.FindStringSubmatch(line)
					if len(m2) > 1 {
						field := UpperCamelCase(m2[1])
						value := m2[2]
						if field == "Timestamp" {
							field = "GeneratedTime"
							value = value[0:19] + "Z"
						}
						if field == "StartTime" {
							value = value[0:19] + "Z"
						}
						if field == "EndTime" {
							value = value[0:19] + "Z"
						}
						if field == "Md5" {
							field = "Md5sum"
						}
						record += "  <" + field + ">" + value + "</" + field + ">\n"
						state = STATE_EXPECTING_FIELDOPEN_OR_TYPECLOSE
						continue
					}

					//regFieldMLOpen   := regexp.MustCompile(`[ \t]*<([A-Za-z0-9]+)>(.*)`)                 //  <httpHeader>POST /wsman HTTP/1.1
					m3 := regFieldMLOpen.FindStringSubmatch(line)
					if len(m3) > 1 {
						field := UpperCamelCase(m3[1])
						value := m3[2]
						if field == "Timestamp" {
							field = "GeneratedTime"
							value = value[0:19] + "Z"
						}
						if field == "StartTime" {
							value = value[0:19] + "Z"
						}
						if field == "EndTime" {
							value = value[0:19] + "Z"
						}
						if field == "Md5" {
							field = "Md5sum"
						}
						record += "  <" + field + ">" + value + "\n"
						fieldType = field
						state = STATE_EXPECTING_FIELDCLOSED
						continue
					}

					//regFieldSLClosed := regexp.MustCompile(`^[ \t]*<([A-Za-z0-9]+) ?/>$`)     //  <remoteIpAddress />
					m4 := regFieldSLClosed.FindStringSubmatch(line)
					if len(m4) > 1 {
						field := UpperCamelCase(m4[1])
						if field == "Timestamp" {
							field = "GeneratedTime"
						}
						if field == "Md5" {
							field = "Md5sum"
						}
						record += "  <" + field + " />\n"
						state = STATE_EXPECTING_FIELDOPEN_OR_TYPECLOSE
						continue
					}

					fmt.Println(options.Warnbox + `ERROR - Expected Record Close '^[ \t]*<(/[A-Za-z0-9]+)>$', SingleLine Field '^[ \t]*<([A-Za-z0-9]+)>(.*)</[A-Za-z0-9]+>$', Closed SingleLine Field '', or MultiLine Field Open '^[ \t]*<([A-Za-z0-9]+)>(.*)' on line ` + strconv.Itoa(rowCount) + `: ` + line)
					return
				}

				if state == STATE_EXPECTING_FIELDCLOSED {
					//regFieldMLClose  := regexp.MustCompile(`(.*)</([A-Za-z0-9]+)>$`)                //</httpHeader>
					m := regFieldMLClose.FindStringSubmatch(line)
					if len(m) > 1 {
						value := m[1]
						field := UpperCamelCase(m[2])
						if field == "Timestamp" {
							field = "GeneratedTime"
							value = value[0:19] + "Z"
						}
						if field == "StartTime" {
							value = value[0:19] + "Z"
						}
						if field == "EndTime" {
							value = value[0:19] + "Z"
						}
						if field == "Md5" {
							field = "Md5sum"
						}
						if fieldType != field {
							fmt.Println(options.Warnbox + `ERROR - MultiLine Field Type Close '(.*)</([A-Za-z0-9]+)>$' did not match '` + fieldType + `' on line ` + strconv.Itoa(rowCount) + `: ` + line)
							return
						}
						record += value + "</" + field + ">\n"
						state = STATE_EXPECTING_FIELDOPEN_OR_TYPECLOSE
					} else {
						record += line + "\n"
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
					fmt.Println(options.Warnbox + `ERROR - Expected Event Close '^[ \t]*</eventItem>$' on line ` + strconv.Itoa(rowCount) + `: ` + line)
					return
				}

				fmt.Println(options.Warnbox+`INTERNAL ERROR - Unexpected state`, state, `on line `+strconv.Itoa(rowCount)+`: `+line)
				return

			}

			//Create the split files
			for auditType, records := range splitEventFiles {
				outputFilePath := splitFileNameStart + auditType + "Item.xml"
				outputFile, err_c := os.Create(outputFilePath)
				if err_c != nil {
					fmt.Println(options.Warnbox + "ERROR - Could not create split file '" + outputFilePath + "'.")
					log.Fatal(err_c)
				}

				outputFile.WriteString(header)
				for _, record := range records {
					outputFile.WriteString(record)
				}
				outputFile.WriteString("</itemList>")
				outputFile.Sync()
				outputFile.Close()
			}

		} else if strings.Contains(file.Name(), "-stateagentinspector") {
			fmt.Println(options.Box + "Splitting '" + file.Name() + "'...")
			originalFileName := filepath.Join(options.InputPath, file.Name())
			originalFile, err_o := os.Open(originalFileName)
			if err_o != nil {
				fmt.Println(options.Warnbox + "ERROR - Could not open file '" + originalFileName + "' to split.")
				log.Fatal(err_o)
			}

			parts := strings.Split(file.Name(), "-")
			if len(parts) < 4 {
				fmt.Println(options.Warnbox + "ERROR - File '" + originalFileName + "' does not match standard naming scheme, and could not be split.")
			}
			hostname := strings.Join(parts[0:len(parts)-3], "-")
			agentid := parts[len(parts)-3]
			payload := parts[len(parts)-2]
			splitFileNameStart := filepath.Join(options.EventBufferSplitDir, hostname+"-"+agentid+"-"+payload+"-")

			//https://stackoverflow.com/questions/21124327/how-to-read-a-text-file-line-by-line-in-go-when-some-lines-are-long-enough-to-ca
			scanner := bufio.NewScanner(originalFile)
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

			splitEventFiles := map[string][]string{}

			header := ""
			record := ""
			eventType := ""

			attr_uid := ""
			attr_sequence_num := ""
			attr_hits := ""
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
						fmt.Println(options.Warnbox + "ERROR - Unexpected 1st Line: '" + line + "'.")
						return
					}
					header = line + "\n"
					continue
				}
				// <itemList generator="eventbuffer" generatorVersion="29.7.8" itemSchemaLocation="http://schemas.mandiant.com/2013/11/stateagentinspectoritem.xsd" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="http://schemas.mandiant.com/2013/11/stateagentinspectoritem.xsd">
				if state == STATE_HEADER && rowCount == 2 {
					line = strings.TrimSpace(line)
					if !strings.HasPrefix(line, "<itemList ") {
						fmt.Println(options.Warnbox + "ERROR - Unexpected 2nd Line: '" + line + "'.")
						return
					}
					header += `<itemList generator="eventbufferGAP" generatorVersion="29.7.8">` + "\n"
					state = STATE_EXPECTING_EVENTOPEN_OR_END
					continue
				}

				if state == STATE_EXPECTING_EVENTOPEN_OR_END {

					//END
					if line == "</itemList>" {
						//Finish up...
						state = STATE_FINISHED
						break
					}
					//regEventOpen     := regexp.MustCompile(`^[ \t]*<eventItem.*>$`)                         // <eventItem sequence_num="1670535298" uid="6209762">
					m := regEventOpen.FindStringSubmatch(line)
					if len(m) < 1 {
						fmt.Println(options.Warnbox + `ERROR - Expected '^[ \t]*<eventItem.*>' or '</itemList>' on line ` + strconv.Itoa(rowCount) + `: ` + line)
						return
					}

					//Reset and get attributes
					attr_uid = ""
					attr_sequence_num = ""
					attr_hits = ""
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
						attr_hits = mHITS[1]
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
							fmt.Println(options.Warnbox + `ERROR - Expected Timestamp '^[ \t]*<timestamp>(.*)</timestamp>$' or '^[ \t]*<timestamp />$' on line ` + strconv.Itoa(rowCount) + `: ` + line)
							return
						}
						field_timestamp = ""
					} else {
						field_timestamp = m[1][0:19] + "Z"
					}
					state = STATE_EXPECTING_EVENTTYPE
					continue
				}

				if state == STATE_EXPECTING_EVENTTYPE {
					//regType          := regexp.MustCompile(`^[ \t]*<eventType>(.*)</eventType>$`)           //  <eventType>dnsLookupEvent</eventType>
					m := regType.FindStringSubmatch(line)
					if len(m) < 2 {
						fmt.Println(options.Warnbox + `ERROR - Expected Event Type '^[ \t]*<eventType>(.*)</eventType>$' on line ` + strconv.Itoa(rowCount) + `: ` + line)
						return
					}
					eventType = UpperCamelCase(m[1])
					record = " <" + eventType + "Item"
					if len(attr_hits) != 0 {
						record += ` hits="` + attr_hits + `"`
					}
					record += ` uid="` + NewGUID() + `"`
					record += ` created="` + time.Now().UTC().Format("2006-01-02T15:04:05Z") + `"`
					if len(attr_sequence_num) != 0 {
						record += ` sequence_num="` + attr_sequence_num + `"`
					}
					if len(attr_uid) != 0 {
						record += ` old_uid="` + attr_uid + `"`
					}
					record += ">\n"
					record += "  <GeneratedTime>" + field_timestamp + "</GeneratedTime>\n"
					state = STATE_EXPECTING_DETAILSOPEN
					continue
				}

				if state == STATE_EXPECTING_DETAILSOPEN {
					//regDetailsOpen   := regexp.MustCompile(`^[ \t]*<details>$`)                             //  <details>
					m := regDetailsOpen.FindStringSubmatch(line)
					if len(m) == 0 {
						fmt.Println(options.Warnbox + `ERROR - Expected Details Open Tag '^[ \t]*<details>$' on line ` + strconv.Itoa(rowCount) + `: ` + line)
						return
					}
					state = STATE_EXPECTING_DETAILOPEN_OR_DETAILSCLOSE
					continue
				}

				if state == STATE_EXPECTING_DETAILOPEN_OR_DETAILSCLOSE {
					//regDetailsClose  := regexp.MustCompile(`^[ \t]*</details>$`)                            //  </details>
					m := regDetailsClose.FindStringSubmatch(line)
					if len(m) != 0 {
						record += " </" + eventType + "Item>\n"
						if _, exists := splitEventFiles[eventType]; !exists {
							splitEventFiles[eventType] = []string{}
						}
						splitEventFiles[eventType] = append(splitEventFiles[eventType], record)
						record = ""
						eventType = ""
						attr_uid = ""
						attr_sequence_num = ""
						attr_hits = ""
						field_timestamp = ""
						state = STATE_EXPECTING_EVENTCLOSE
						continue
					}

					//regDetailOpen    := regexp.MustCompile(`^[ \t]*<detail>$`)                              //   <detail>
					m2 := regDetailOpen.FindStringSubmatch(line)
					if len(m2) == 0 {
						fmt.Println(options.Warnbox + `ERROR - Expected Details Open Tag '^[ \t]*<details>$' or Details Close Tag '^[ \t]*</details>$' on line ` + strconv.Itoa(rowCount) + `: ` + line)
						return
					}
					state = STATE_EXPECTING_DETAILNAME
					continue
				}

				if state == STATE_EXPECTING_DETAILNAME {
					//regName          := regexp.MustCompile(`^[ \t]*<name>(.*)</name>$`)                     //    <name>pid</name>
					m := regName.FindStringSubmatch(line)

					if len(m) < 2 {
						fmt.Println(options.Warnbox + `ERROR - Expected Detail Name '^[ \t]*<name>(.*)</name>$ on line ` + strconv.Itoa(rowCount) + `: ` + line)
						return
					}
					field_name = UpperCamelCase(m[1])
					if field_name == "Md5" {
						field_name = "Md5sum"
					}
					state = STATE_EXPECTING_DETAILVALUE
					continue
				}

				if state == STATE_EXPECTING_DETAILVALUE {
					//regValueSL       := regexp.MustCompile(`^[ \t]*<value>(.*)</value>$`)                   //    <value>19052</value>
					m := regValueSL.FindStringSubmatch(line)
					if len(m) == 2 {
						value := m[1]
						if field_name == "StartTime" {
							value = value[0:19] + "Z"
						}
						if field_name == "EndTime" {
							value = value[0:19] + "Z"
						}
						record += "  <" + field_name + ">" + value + "</" + field_name + ">\n"
						field_name = ""
						state = STATE_EXPECTING_DETAILCLOSE
						continue
					}

					//regValueSLClosed := regexp.MustCompile(`^[ \t]*<value ?/>$`)                             //    <value />
					m3 := regValueSLClosed.FindStringSubmatch(line)
					if len(m3) == 1 {
						record += "  <" + field_name + " />\n"
						field_name = ""
						state = STATE_EXPECTING_DETAILCLOSE
						continue
					}

					//regValueMLOpen   := regexp.MustCompile(`^[ \t]*<value>(.*)$`)                           //    <value>POST /wsman HTTP/1.1
					m2 := regValueMLOpen.FindStringSubmatch(line)
					if len(m2) < 2 {
						fmt.Println(options.Warnbox + `ERROR - Expected Detail Value SingleLine '^[ \t]*<value>(.*)</value>$' or MultiLine Open '^[ \t]*<value>(.*)$' on line ` + strconv.Itoa(rowCount) + `: ` + line)
						return
					}
					record += "  <" + field_name + ">" + m2[1] + "\n"
					state = STATE_EXPECTING_DETAILVALUECLOSE
					continue
				}

				if state == STATE_EXPECTING_DETAILVALUECLOSE {
					//regValueMLClose  := regexp.MustCompile(`^(.*)</value>$`)                                //</value>
					m := regValueMLClose.FindStringSubmatch(line)
					if len(m) == 0 {
						record += line + "\n"
						state = STATE_EXPECTING_DETAILVALUECLOSE
						continue
					}
					record += m[1] + "</" + field_name + ">\n"
					state = STATE_EXPECTING_DETAILCLOSE
					continue
				}

				if state == STATE_EXPECTING_DETAILCLOSE {
					//regDetailClose   := regexp.MustCompile(`^[ \t]*</detail>$`)                             //   </detail>
					m := regDetailClose.FindStringSubmatch(line)
					if len(m) == 0 {
						fmt.Println(options.Warnbox + `ERROR - Expected Detail Close Tag '^[ \t]*</detail>$' on line ` + strconv.Itoa(rowCount) + `: ` + line)
						return
					}
					state = STATE_EXPECTING_DETAILOPEN_OR_DETAILSCLOSE
					continue

				}

				if state == STATE_EXPECTING_EVENTCLOSE {
					//regEventClose    := regexp.MustCompile(`^[ \t]*</eventItem>$`)                          // </eventItem>
					m := regEventClose.FindStringSubmatch(line)
					if len(m) == 0 {
						fmt.Println(options.Warnbox + `ERROR - Expected Event Close Tag '^[ \t]*</eventItem>$' on line ` + strconv.Itoa(rowCount) + `: ` + line)
						return
					}

					state = STATE_EXPECTING_EVENTOPEN_OR_END
					continue
				}

				fmt.Println(options.Warnbox+`INTERNAL ERROR - Unexpected state`, state, `on line `+strconv.Itoa(rowCount)+`: `+line)
				return
			}

			//Create the split files
			for auditType, records := range splitEventFiles {
				outputFilePath := splitFileNameStart + auditType + "Item.xml"
				outputFile, err_c := os.Create(outputFilePath)
				if err_c != nil {
					fmt.Println(options.Warnbox + "ERROR - Could not create split file '" + outputFilePath + "'.")
					log.Fatal(err_c)
				}

				outputFile.WriteString(header)
				for _, record := range records {
					outputFile.WriteString(record)
				}
				outputFile.WriteString("</itemList>")
				outputFile.Sync()
				outputFile.Close()
			}
		}
	}
}

func UpperCamelCase(s string) string {
	if len(s) == 0 {
		return ""
	}
	return strings.ToUpper(s[0:1]) + s[1:len(s)]
}

//https://play.golang.org/p/4FkNSiUDMg
func NewGUID() string {
	charmap := "0123456789abcdef"
	guid := ""

	for i := 0; i < 32; i++ {
		if i == 8 || i == 12 || i == 16 || i == 20 {
			guid += "-"
		}
		guid += string(charmap[rand.Intn(len(charmap))])
	}

	return guid
}
