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
	//"archive/zip"
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/yeka/zip"
)

type ThreadReturnExtract struct {
	threadnum int
	zipfile   string
	message   string
	xmlfiles  []os.FileInfo
}

func GoAuditExtract_Start(options Options, files []os.FileInfo, config Parse_Config_JSON, configOutDirIndex int) []os.FileInfo {

	c_Success := 0
	c_Cached := 0
	c_Partial := 0
	c_Failed := 0

	extractionOnly := len(options.ExtractionOutputDir) > 0
	if !extractionOnly && !options.ForceReparse {
		for i := 0; i < len(files); i++ {
			var status string
			config, status = ParseConfigGetArchiveFileStatus(files[i], configOutDirIndex, config)
			if status == "extracted" {
				files = append(files[:i], files[i+1:]...)
				i--
				c_Cached++
			} else if status == "partial" {
				files = append(files[:i], files[i+1:]...)
				i--
				c_Partial++
			}
		}
	}

	if len(files) == 0 {
		fmt.Println(options.Box + "All identified archive file(s) already extracted.")
		return []os.FileInfo{}
	}

	// Make output directory if it does not exist
	if len(options.ExtractionOutputDir) > 0 {
		if _, err := os.Stat(options.ExtractionOutputDir); os.IsNotExist(err) {
			if err = os.MkdirAll(options.ExtractionOutputDir, os.ModePerm); err != nil {
				fmt.Println(options.Warnbox + "ERROR - Could not create output directory '" + options.ExtractionOutputDir + "'.")
				return nil
			}
		}
	}

	threads := options.Threads
	if threads < 1 {
		threads = 1
	}
	if len(files) < threads {
		threads = len(files)
	}

	c := make(chan ThreadReturnExtract)
	c_tqdm := make(chan bool)
	c_debug := make(chan map[int]string)
	if options.Threads < 1 {
		options.Threads = 1
	}
	if len(files) < options.Threads {
		options.Threads = len(files)
	}

	if options.Verbose == 0 {
		go TQDM(len(files), options, options.Box+"Extracting archives", c_tqdm)
	} else {
		fmt.Println(options.Box + "Extracting archives...")
		go Debug(options, c_debug)
	}

	threadMessages := []string{}
	xmlFiles := []os.FileInfo{}

	threadindex := 0
	threadtotal := len(files)
	threadpadding := len(strconv.Itoa(threadtotal))
	threadbuffer := map[int]string{}

	//Start time of timer
	start := time.Now()

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
			debug.FreeOSMemory()
			threadMessages = append(threadMessages, done.message)
			xmlFiles = append(xmlFiles, done.xmlfiles...)
			if !extractionOnly {
				config = ParseConfigUpdateArchive(configOutDirIndex, files[done.threadnum], done.message, config)
				err_s := ParseConfigSave(config, options)
				if err_s != nil {
					fmt.Println(options.Warnbox + "WARNING - Could not update '_GAPInputConfig.json'. " + err_s.Error())
				}
			}
		}
		threadbuffer[i] = files[i].Name() + "||" + time.Now().Format("2006-01-02 15:04:05")
		threadindex++
		if options.Verbose > 0 {
			c_debug <- threadbuffer
			fmt.Printf(options.Box+"Extracting %"+strconv.Itoa(threadpadding)+"d/%"+strconv.Itoa(threadpadding)+"d %6.2f%% "+filepath.Base(files[i].Name())+"...\n", threadindex, threadtotal, (float32(threadindex)/float32(threadtotal))*100.0)
		}
		go GoAuditExtract_Thread(files[i], options, i, c)
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
		debug.FreeOSMemory()
		threadMessages = append(threadMessages, done.message)
		xmlFiles = append(xmlFiles, done.xmlfiles...)
		if !extractionOnly {
			config = ParseConfigUpdateArchive(configOutDirIndex, files[done.threadnum], done.message, config)
			err_s := ParseConfigSave(config, options)
			if err_s != nil {
				fmt.Println(options.Warnbox + "WARNING - Could not update '_GAPInputConfig.json'. " + err_s.Error())
			}
		}
	}

	for _, msg := range threadMessages {
		if strings.Contains(msg, "unarchived with issues") {
			c_Partial++
			fmt.Println(msg)
		} else if strings.Contains(msg, "unarchived successfully") {
			c_Success++
			if options.Verbose > 0 {
				fmt.Println(msg)
			}
		} else if strings.Contains(msg, "Failed to unarchive") {
			c_Failed++
			fmt.Println(msg)
		} else {
			if options.Verbose > 0 {
				fmt.Println(msg)
			}
		}
	}

	elapsed := time.Since(start)
	time.Sleep(10 * time.Millisecond)

	fmt.Println(options.Box + "Archive Extraction Statistics:")
	fmt.Println(options.Box+" - Success: ", c_Success)
	fmt.Println(options.Box+" - Partial: ", c_Partial)
	fmt.Println(options.Box+" - Failed:  ", c_Failed)
	fmt.Println(options.Box+" - Cached:  ", c_Cached)

	fmt.Printf(options.Box+"Extracted %d file(s) in %s.", len(xmlFiles), elapsed.Truncate(time.Millisecond).String())
	if !options.MinimizedOutput {
		fmt.Printf("\n")
	}

	return xmlFiles
}

func GoAuditExtract_Thread(file os.FileInfo, options Options, threadNum int, c chan ThreadReturnExtract) {

	xmlfiles := []os.FileInfo{}
	fileName := filepath.Base(file.Name())
	filePath := filepath.Join(options.InputPath, fileName)
	reg_OtherFormat := regexp.MustCompile("-[A-Za-z0-9]{22}[.]zip")

	//=== OPEN ZIP FILE CONTENTS IN MEMORY ===//

	type ZipFileContent struct {
		IsExtracted bool
		File        io.ReadCloser
	}
	zipFileContents := map[string]ZipFileContent{}
	var zipFile *zip.ReadCloser

	var err_z error
	zipFile, err_z = zip.OpenReader(filePath)
	if err_z != nil {
		c <- ThreadReturnExtract{threadNum, fileName, options.Warnbox + `WARNING - Failed to unarchive '` + fileName + `'. Could not open as a ZIP file: ` + err_z.Error(), xmlfiles}
		return
	}

	warningMessages := []string{}
	for _, innerFile := range zipFile.File {
		if innerFile.IsEncrypted() {
			innerFile.SetPassword(options.ExtractionPassword)
		}
		rc, err_o := innerFile.Open()
		if err_o != nil {
			warningMessages = append(warningMessages, "Could not read archive file '"+innerFile.Name+"': "+err_o.Error())
			rc.Close()
			continue
		}
		zipFileContents[innerFile.Name] = ZipFileContent{false, rc}
	}

	//=== GET HOSTNAME + AGENT ID  ===//
	//Get Hostname and Agent ID from metadata.json for triage packages
	hostname := "0"
	agentid := "0000000000000000000000"
	baseFileName := strings.TrimSuffix(filepath.Base(fileName), filepath.Ext(fileName))

	//Try getting Hostname + Agent ID from metadata.json
	if _, exists := zipFileContents["metadata.json"]; exists {
		metaFile := zipFileContents["metadata.json"]
		metaFile.IsExtracted = true
		zipFileContents["metadata.json"] = metaFile
		//scanner := bufio.NewScanner(zipFileContents["metadata.json"].File)
		bytes, err_r := ioutil.ReadAll(metaFile.File)
		if err_r != nil {
			c <- ThreadReturnExtract{threadNum, fileName, options.Warnbox + `WARNING - Failed to unarchive '` + fileName + `'. File is likely encrypted (try '-ep <password>'). Could not read contents of 'metadata.json': ` + err_r.Error(), xmlfiles}
			return
		}
		contents := string(bytes)
		for _, line := range strings.Split(contents, "\n") {
			if strings.Contains(line, `"hostname": "`) {
				line = strings.TrimSpace(line)
				hostname = line[13 : len(line)-2]
				break
			} else if strings.Contains(line, `"_id": "`) {
				line = strings.TrimSpace(line)
				agentid = line[8 : len(line)-2]
			}
		}
		metaFile.File.Close()

		//Get Hostname + Agent ID based on other naming scheme (Ex. "<HOSTNAME>-<AGENTID>.zip")
	} else if reg_OtherFormat.MatchString(fileName) {
		parts := strings.Split(baseFileName, "-")
		hostname = strings.Join(parts[0:len(parts)-1], "-")
		agentid = strings.Join(parts[len(parts)-1:], "-")[0:22]

		//Get Hostname + Agent ID based on usual naming scheme (Ex. "<HOSTNAME>-<AGENTID>-<OTHER>-<AUDITTYPE>.zip")
	} else if len(strings.Split(baseFileName, "-")) >= 4 {
		parts := strings.Split(baseFileName, "-")
		if len(strings.Join(parts[len(parts)-3:len(parts)-2], "-")) == 22 {
			hostname = strings.Join(parts[0:len(parts)-3], "-")
			agentid = strings.Join(parts[len(parts)-3:len(parts)-2], "-")[0:22]
		}
	}

	// === RENAME THE FILES TO PROPER NAMES === //

	//Open manifest.json
	manifestFile, exists := zipFileContents["manifest.json"]
	if !exists {
		c <- ThreadReturnExtract{threadNum, fileName, options.Warnbox + `WARNING - Failed to unarchive '` + fileName + `'. Could not find of 'manifest.json'.`, xmlfiles}
		return
	}
	manifestFile.IsExtracted = true
	zipFileContents["manifest.json"] = manifestFile
	scanner := bufio.NewScanner(manifestFile.File)
	var generator = ""
	var payload = ""
	var ptype = ""
	var filename = ""

	var outputDir = options.InputPath
	if len(options.ExtractionOutputDir) > 0 {
		outputDir = options.ExtractionOutputDir
	}

	//Iterate manifest.json line by line
	for scanner.Scan() {
		var line = scanner.Text()
		//Files from audits
		if strings.Contains(line, "\"generator\"") {
			line = strings.TrimSpace(line)
			generator = line[14 : len(line)-2]
		} else if strings.Contains(line, "\"payload\"") {
			line = strings.TrimSpace(line)
			payload = line[12 : len(line)-2]
		} else if strings.Contains(line, "\"type\": \"application/") {

			ptype = ""
			if strings.Contains(line, "issue") {
				ptype = ".issues"
			} else if strings.Contains(generator, "multifile") || strings.Contains(line, "octet-stream") {
				continue //Gets parsed down below as an acquisition
			} else if strings.Contains(line, "xml") {
				ptype = ".xml"
			} else if strings.Contains(line, "json") {
				ptype = ".json"
			} else {
				warningMessages = append(warningMessages, "Could not identify ptype '"+strings.TrimSpace(line)+"' of payload '"+payload+"' in manifest.")
				continue
			}

			var old_name = payload
			var new_name = ""
			generator = strings.Replace(generator, "-", "_", -1)
			if options.ExtractXMLFormat == 2 {
				payload = "0"
			}
			new_name = hostname + "-" + agentid + "-" + payload + "-" + generator + ptype

			oldFile, exists := zipFileContents[old_name]
			if ptype == ".issues" {
				oldFile.File.Close()
				oldFile.IsExtracted = true
				zipFileContents[old_name] = oldFile
				continue
			}
			if !exists {
				warningMessages = append(warningMessages, "Could not find file '"+old_name+"' to rename into '"+new_name+"'.")
				continue
			}
			oldFile.IsExtracted = true
			zipFileContents[old_name] = oldFile

			if options.ExtractFilesOnly {
				continue
			}

			outFilePath := filepath.Join(outputDir, new_name)
			outFile, err_o := os.Create(outFilePath)
			if err_o != nil {
				warningMessages = append(warningMessages, "Could not create destination file '"+new_name+"'. "+err_o.Error())
				continue
			}
			_, err_c := io.Copy(outFile, oldFile.File)
			if err_c != nil {
				warningMessages = append(warningMessages, "Could not copy contents to destination file '"+new_name+"'. "+err_c.Error())
				continue
			}

			oldFile.File.Close()
			outFile.Close()

			if ptype == ".xml" {
				xmlfile, _ := os.Stat(outFilePath)
				xmlfiles = append(xmlfiles, xmlfile)
			}

			//Files from acquisition
		} else if strings.Contains(line, "\"name\": \"mandiant/mir/agent/FileName\"") {
			scanner.Scan()
			line = scanner.Text()
			line = strings.TrimSpace(line)
			filename = line[10 : len(line)-1]
		} else if strings.Contains(line, "\"name\": \"mandiant/mir/agent/FilePath\"") {
			scanner.Scan()
			line = scanner.Text()
			line = strings.TrimSpace(line)
			path := line[10 : len(line)-1]
			path = strings.Replace(path, "\\\\", "_", -1)
			path = strings.Replace(path, "\\", "_", -1)
			path = strings.Replace(path, "/", "_", -1)
			path = strings.Replace(path, ":", "", -1)
			path = strings.Replace(path, "_", "__", -1)
			generator = strings.Replace(generator, "-", "_", -1)

			var old_name = payload
			var new_name = filename
			oldFile, exists := zipFileContents[old_name]
			if !exists {
				warningMessages = append(warningMessages, "Could not find file '"+old_name+"' to rename into '"+new_name+"'.")
				continue
			}
			oldFile.IsExtracted = true
			zipFileContents[old_name] = oldFile

			if options.ExtractFileFormat >= 1 && options.ExtractFileFormat <= 4 {
				new_name = path + new_name
			}
			if options.ExtractFileFormat >= 1 && options.ExtractFileFormat <= 2 {
				new_name = hostname + "-" + agentid + "-" + generator + "-" + new_name
			}
			if options.ExtractFileFormat%2 == 1 {
				new_name = new_name + "_"
			}

			outFilePath := filepath.Join(outputDir, new_name)
			outFile, err_o := os.Create(outFilePath)
			if err_o != nil {
				warningMessages = append(warningMessages, "Could not create destination file '"+new_name+"'. "+err_o.Error())
				continue
			}
			_, err_c := io.Copy(outFile, oldFile.File)
			if err_c != nil {
				warningMessages = append(warningMessages, "Could not copy contents to destination file '"+new_name+"'. "+err_c.Error())
				continue
			}

			oldFile.File.Close()
			outFile.Close()
		}
	}
	manifestFile.File.Close()
	if err_s := scanner.Err(); err_s != nil {
		c <- ThreadReturnExtract{threadNum, fileName, options.Warnbox + `WARNING - Failed to unarchive '` + fileName + `'. An error occurred while reading 'manifest.json.'. ` + err_s.Error(), xmlfiles}
		return
	}

	//Extract any remaining files that have not yet been extracted
	for filename, file := range zipFileContents {
		if !file.IsExtracted {
			if filename == "script.xml" {
				continue
			}
			outFile, err_o := os.Create(filepath.Join(outputDir, filename))
			if err_o != nil {
				warningMessages = append(warningMessages, "Could not create destination file '"+filename+"'. "+err_o.Error())
				continue
			}
			_, err_c := io.Copy(outFile, file.File)
			if err_c != nil {
				warningMessages = append(warningMessages, "Could not copy contents to destination file '"+filename+"'.")
				continue
			}
			file.File.Close()
			outFile.Close()
		}
	}

	zipFile.Close()

	if len(warningMessages) > 0 {
		c <- ThreadReturnExtract{threadNum, fileName, options.Warnbox + `WARNING - File '` + fileName + `' unarchived with issues.` + "\n" + strings.Join(warningMessages, "\n"+options.Warnbox+"- "), xmlfiles}
	} else {
		c <- ThreadReturnExtract{threadNum, fileName, options.Box + `NOTICE - File '` + fileName + `' unarchived successfully.`, xmlfiles}
	}
}

// https://golangcode.com/unzip-files-in-go/
func Unzip(src string, dest string) ([]string, error) {
	var filenames []string
	r, err := zip.OpenReader(src)
	if err != nil {
		return filenames, err
	}
	defer r.Close()
	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			return filenames, err
		}
		defer rc.Close()
		// Store filename/path for returning and using later on
		fpath := filepath.Join(dest, f.Name)
		filenames = append(filenames, fpath)
		if f.FileInfo().IsDir() {
			// Make Folder
			os.MkdirAll(fpath, os.ModePerm)
		} else {
			// Make File
			if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
				return filenames, err
			}
			outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				return filenames, err
			}
			_, err = io.Copy(outFile, rc)
			// Close the file without defer to close before next iteration of loop
			outFile.Close()
			if err != nil {
				return filenames, err
			}
		}
	}
	return filenames, nil
}
