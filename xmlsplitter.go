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
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

func GoAuditXMLSplitter_Start(options Options) []os.FileInfo {

	// Make output directory if it doesn't exist
	if _, err := os.Stat(options.XMLSplitOutputDir); os.IsNotExist(err) {
		if err = os.MkdirAll(options.XMLSplitOutputDir, os.ModePerm); err != nil {
			fmt.Println(options.Warnbox + "ERROR - Could not create XML split output directory '" + options.XMLSplitOutputDir + "'.")
			log.Fatal(err)
		}
	} else if options.WipeOutput {
		outputfiles, _ := ioutil.ReadDir(options.XMLSplitOutputDir)
		if len(outputfiles) > 0 {
			fmt.Println(options.Box + "Deleting all pre-existing XML files in the XML split output directory '" + options.XMLSplitOutputDir + "' as specified with the '-wo' flag.")
			for _, file := range outputfiles {
				var filename = file.Name()
				if strings.HasSuffix(filename, ".xml") {
					if options.Verbose > 0 {
						fmt.Println(options.Box + "Removing pre-existing XML file '" + filename + "'...")
					}
					os.Remove(filepath.Join(options.XMLSplitOutputDir, filename))
				}
			}
		}
	}

	var files []os.FileInfo

	//If this task is called from main parsing process, options.SubTaskFiles will be filled with files to split
	if len(options.SubTaskFiles) > 0 {
		files = options.SubTaskFiles
	} else {
		// Get input files
		input_st, err_st := os.Stat(options.InputPath)
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
				return []os.FileInfo{}
			}

			// Ingest split files too
			splitfiles, err_r2 := ioutil.ReadDir(filepath.Join(options.InputPath, "xmlsplit"))
			if err_r2 == nil {
				files = append(files, splitfiles...)
			}

			files = dirfiles
		}
	}

	c_tqdm := make(chan bool)

	if options.Verbose == 0 {
		go TQDM(len(files), options, options.Box+"Splitting large XML audits into '"+options.XMLSplitOutputDir+"'", c_tqdm)
	} else {
		fmt.Println(options.Box + "Extracting archives...")
	}

	//Split any files that are too large.
	filesSplit := []os.FileInfo{}
	splitSize := int64(options.XMLSplitByteSize)
	messages := []string{}
	for _, file := range files {
		xmlfilename := filepath.Base(file.Name())
		if filepath.Ext(xmlfilename) == ".issues" || strings.HasSuffix(strings.TrimSuffix(filepath.Base(xmlfilename), filepath.Ext(xmlfilename)), "issues") {
			if options.Verbose > 0 {
				messages = append(messages, options.Warnbox+"NOTICE - Not splitting or including 'issues' file to be split '"+xmlfilename+"'.")
			}
			if options.Verbose == 0 {
				c_tqdm <- true
			}
			continue
		}

		if file.Size() > splitSize {
			if options.Verbose > 0 {
				messages = append(messages, options.Warnbox+"NOTICE - File '"+xmlfilename+"' is greater than "+strconv.Itoa(int(splitSize))+" bytes and will be split.")
			}
			splitCount := 1
			originalFileName := filepath.Join(options.InputPath, file.Name())
			originalFile, err_o := os.Open(originalFileName)
			if err_o != nil {
				messages = append(messages, options.Warnbox+"ERROR - Could not open file '"+originalFileName+"' to split.")
				if options.Verbose == 0 {
					c_tqdm <- true
				}
				continue
			}

			basefilename := file.Name()

			var hostname string
			var agentid string
			var payload string
			var oldaudit string
			if strings.Contains(basefilename, ".urn_uuid_") {
				hostname = "HOSTNAMEPLACEHOLDER"
				agentid = "AGENTIDPLACEHOLDER0000"
				payload = strings.TrimSuffix(strings.ReplaceAll(basefilename, "-", "_"), ".xml")
				oldaudit = "UNCONFIRMED.xml"
			} else {
				parts := strings.Split(basefilename, "-")
				if len(parts) < 4 {
					messages = append(messages, options.Warnbox+"WARNING - File '"+xmlfilename+"' does not match standardized naming scheme and could not be split.")
					c_tqdm <- true
					continue
				}
				hostname = strings.Join(parts[0:len(parts)-3], "-")
				agentid = parts[len(parts)-3]
				payload = parts[len(parts)-2]
				oldaudit = parts[len(parts)-1]
			}
			splitFileName := filepath.Join(options.XMLSplitOutputDir, hostname+"-"+agentid+"-"+payload+"_spxml"+strconv.Itoa(splitCount)+"-"+oldaudit)

			splitFile, err_c := os.Create(splitFileName)
			if err_c != nil {
				messages = append(messages, options.Warnbox+"ERROR - Could not create split file '"+splitFileName+"'. "+err_c.Error())
				if options.Verbose == 0 {
					c_tqdm <- true
				}
				originalFile.Close()
				continue
			}

			scanner := bufio.NewScanner(originalFile)
			//https://stackoverflow.com/questions/21124327/how-to-read-a-text-file-line-by-line-in-go-when-some-lines-are-long-enough-to-ca
			buf := make([]byte, 0, 64*1024)
			scanner.Buffer(buf, 1024*1024*1024)

			writer := bufio.NewWriter(splitFile)
			rowCount := 0
			bytesWritten := int64(0)
			header := ""
			auditType := ""
			regAuditType := regexp.MustCompile(`<([^ ^>]+)[ >]`)
			issue := false
			for scanner.Scan() {
				if options.Verbose > 3 && rowCount%1000000 == 0 {
					messages = append(messages, options.Box+"SplitFile "+strconv.Itoa(splitCount)+" - Line "+strconv.Itoa(splitCount)+" - BytesWritten "+strconv.Itoa(splitCount))
				}
				rowCount++
				line := scanner.Text()
				if rowCount == 1 {
					if !strings.HasPrefix(line, "<?xml ") {
						messages = append(messages, options.Warnbox+"ERROR - Unexpected 1st Line '"+line+"'.")
						issue = true
						break
					} else {
						header = line + "\n"
						continue
					}
				}
				if rowCount == 2 {
					if !strings.HasPrefix(line, "<itemList") {
						fmt.Println(options.Warnbox + "ERROR - Unexpected 2nd Line '" + line + "'.")
						issue = true
						break
					} else {
						header += line + "\n"
						continue
					}
				}
				if rowCount == 3 {
					//Get AuditType
					if len(regAuditType.FindStringSubmatch(line)) <= 1 {
						messages = append(messages, options.Warnbox+"ERROR - Could not identify AuditType from '"+line+"'.")
						issue = true
						break
					}
					auditType = regAuditType.FindStringSubmatch(line)[1]
					bw, err_w := writer.WriteString(header + line + "\n")
					if err_w != nil {
						messages = append(messages, options.Warnbox+"ERROR - Could not write string to '"+splitFileName+"'. "+err_w.Error())
						issue = true
						break
					}
					bytesWritten += int64(bw)
					continue
				}
				bw, err_w := writer.WriteString(line + "\n")
				if err_w != nil {
					messages = append(messages, options.Warnbox+"ERROR - Could not write string to '"+splitFileName+"'. "+err_w.Error())
					issue = true
					break
				}
				bytesWritten += int64(bw)

				//If we are over the byte limit, write the rest of the "row" item to file
				if bytesWritten > splitSize-3000 {
					for scanner.Scan() {
						line = scanner.Text()
						bw, err_w := writer.WriteString(line + "\n")
						if err_w != nil {
							messages = append(messages, options.Warnbox+"ERROR - Could not write string to '"+splitFileName+"'. "+err_w.Error())
							issue = true
							break
						}
						bytesWritten += int64(bw)
						//If we are at the end of the "row" item, write it out, and start up a new split file
						if strings.TrimSpace(line) == "</"+auditType+">" {
							//End current split file
							_, err_w := writer.WriteString("</itemList>\n")
							if err_w != nil {
								messages = append(messages, options.Warnbox+"ERROR - Could not write string to '"+splitFileName+"'. "+err_w.Error())
								issue = true
								break
							}
							bytesWritten = 0
							writer.Flush()
							splitFile.Close()
							if fileinfo, err_s := os.Stat(splitFileName); !os.IsNotExist(err_s) {
								filesSplit = append(filesSplit, fileinfo)
							}
							//Start new split file
							splitCount++
							splitFileName = filepath.Join(options.XMLSplitOutputDir, hostname+"-"+agentid+"-"+payload+"_spxml"+strconv.Itoa(splitCount)+"-"+oldaudit)
							splitFile, err_c = os.Create(splitFileName)
							if err_c != nil {
								messages = append(messages, options.Warnbox+"ERROR - Could not create split file '"+splitFileName+"'. "+err_c.Error())
								issue = true
								break
							}
							writer = bufio.NewWriter(splitFile)
							scanner.Scan()
							line = scanner.Text()
							bw, err_w := writer.WriteString(header + line + "\n")
							if err_w != nil {
								messages = append(messages, options.Warnbox+"ERROR - Could not write string to '"+splitFileName+"'. "+err_w.Error())
								issue = true
								break
							}
							bytesWritten += int64(bw)
							break
						}
					}
				}
				if issue {
					break
				}
			}
			if issue {
				originalFile.Close()
				splitFile.Close()
				if options.Verbose == 0 {
					c_tqdm <- true
				}
				continue
			}
			err_se := scanner.Err()
			if err_se != nil {
				messages = append(messages, options.Warnbox+"ERROR - Could not completely read file '"+splitFileName+"'.")
				originalFile.Close()
				splitFile.Close()
				if options.Verbose == 0 {
					c_tqdm <- true
				}
				continue
			}
			originalFile.Close()
			writer.Flush()
			splitFile.Close()
			if fileinfo, err_s := os.Stat(splitFileName); !os.IsNotExist(err_s) {
				filesSplit = append(filesSplit, fileinfo)
			}
			c_tqdm <- true
		} else {
			//Just copy the file
			//https://opensource.com/article/18/6/copying-files-go (Example #3)
			if options.Verbose > 0 {
				messages = append(messages, options.Warnbox+"NOTICE - File '"+xmlfilename+"' is less than "+strconv.Itoa(int(splitSize))+" bytes and will not be split.")
			}

			originalFilePath := filepath.Join(options.InputPath, file.Name())
			sourcefile, err_o := os.Open(originalFilePath)
			if err_o != nil {
				messages = append(messages, options.Warnbox+"ERROR - Could not open file '"+xmlfilename+"'. "+err_o.Error())
				if options.Verbose == 0 {
					c_tqdm <- true
				}
				continue
			}
			defer sourcefile.Close()

			destfilename := filepath.Join(options.XMLSplitOutputDir, xmlfilename)

			destfile, err_w := os.Create(destfilename)
			if err_w != nil {
				messages = append(messages, options.Warnbox+"ERROR - Could not create output file '"+xmlfilename+"'. "+err_w.Error())
				sourcefile.Close()
				if options.Verbose == 0 {
					c_tqdm <- true
				}
				continue
			}
			defer destfile.Close()

			_, err_c := io.Copy(destfile, sourcefile)
			if err_c != nil {
				messages = append(messages, options.Warnbox+"ERROR - Could not copy contents of file '"+xmlfilename+"'. "+err_c.Error())
				sourcefile.Close()
				destfile.Close()
				if options.Verbose == 0 {
					c_tqdm <- true
				}
				continue
			}

			sourcefile.Close()
			destfile.Close()
			c_tqdm <- true
		}
	}
	for _, msg := range messages {
		fmt.Println(msg)
	}
	return filesSplit

}
