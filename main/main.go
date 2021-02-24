// ==============================================================
// Copyright 2020 FireEye, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
// ==============================================================

package main

import (
    "crypto/md5"
    "fmt"
    "io"
    "io/ioutil"
    "log"
    "os"
    "path/filepath"
    "strconv"
    "strings"
    "sort"

    "github.com/fireeye/goauditparser"
)

func main() {

    //Parse input flags, read config file, determine what to do
    options := goauditparser.Setup()
    if options.ErrorDuringSetup {
        return
    }

    if options.TimelineOnly {
        //If the user provided -i instead of -o, copy it over
        if options.OutputPath == "" && options.InputPath != "" {
            options.OutputPath = options.InputPath
        }
        goauditparser.GoAuditTimeliner_Start(options)
        return
    }

    //Check required arguments
    if options.InputPath == "" {
        fmt.Println(goauditparser.GetHelpExamples())
        return
    }

    if options.EventBufferSplitDir != "" {
        goauditparser.GoAuditEventSplitter_Start(options)
        return
    }

    if options.XMLSplitOutputDir != "" {
        goauditparser.GoAuditXMLSplitter_Start(options)
        return
    }

    if options.ExtractionOutputDir != "" {
        //Read input directory
        files, err_r := ioutil.ReadDir(options.InputPath)
        if err_r != nil {
            fmt.Println(options.Warnbox + "ERROR - Could not read input directory '" + options.InputPath + "'.")
            log.Fatal(err_r)
        }
        if len(files) == 0 {
            fmt.Println(options.Warnbox + "ERROR - Could not identify any files in input directory '" + options.InputPath + "'.")
            return
        }

        //Iterate through each file
        archives := []os.FileInfo{}
        for i := 0; i < len(files); i++ {
            filename := filepath.Base(files[i].Name())

            if strings.ToLower(filepath.Ext(filename)) == ".zip" || strings.ToLower(filepath.Ext(filename)) == ".mans" {
                archives = append(archives, files[i])
                files = append(files[:i], files[i+1:]...)
                i--
                continue
            } else if filename == "_GAPParseConfig.json" {
                files = append(files[:i], files[i+1:]...)
                i--
                continue
            }
        }
        //Unarchive any files
        if len(archives) > 0 {
            goauditparser.GoAuditExtract_Start(options, archives, goauditparser.Parse_Config_JSON{}, -1)
        } else {
            fmt.Println(options.Warnbox + "ERROR - Could not identify any archive files in input directory '" + options.InputPath + "'.")
        }
        return
    }

    //Get number of input directories
    inputArray := strings.Split(options.InputPath, ",")
    if len(inputArray) > 1 {
        fmt.Println(options.Box+"Provided", len(inputArray), "input directories:")
        for i, inputPath := range inputArray {
            fmt.Println(options.Box + strconv.Itoa(i+1) + ". " + inputPath)
        }
    }

    if (options.Recursive) {
        inputMap := map[string]bool{}
        fmt.Println(options.Box+"Recursively identifying directories:")
        for _, inputPath := range inputArray {
            inputMap[inputPath] = true
            err := filepath.Walk(inputPath, func(path string, info os.FileInfo, err error) error {
                if err != nil {
                    return err
                }
                if (info.IsDir() && info.Name() != "xmlsplit")  {inputMap[path] = true}
                return nil
            })
            if err != nil {
                fmt.Println(options.Warnbox + "ERROR - Could not recursively explore the directory '" + inputPath + "'.")
                break;
            }
        }

        inputArray = []string{}
        for k, _ := range inputMap {
            inputArray = append(inputArray,k);
        }
        sort.Strings(inputArray)
        for i, inputPath := range inputArray {
            fmt.Println(options.Box + strconv.Itoa(i+1) + ". " + inputPath)
        }
        
    }
    
    // Make output directory if it does not exist
    if _, err := os.Stat(options.OutputPath); os.IsNotExist(err) {
        if err = os.MkdirAll(options.OutputPath, os.ModePerm); err != nil {
            fmt.Println(options.Warnbox + "ERROR - Could not create output directory '" + options.OutputPath + "'.")
            log.Fatal(err)
        }
    } else {
        // Remove all
        if options.WipeOutput {
            outputfiles, _ := ioutil.ReadDir(options.OutputPath)
            if len(outputfiles) > 0 {
                fmt.Println(options.Box + "Deleting all pre-existing CSV files in the output directory '" + options.OutputPath + "' as specified with the '-wo' flag.")
                for _, file := range outputfiles {
                    var filename = file.Name()
                    if strings.HasSuffix(filename, ".csv") {
                        if options.Verbose > 0 {
                            fmt.Println(options.Box + "Removing pre-existing CSV file '" + filename + "'...")
                        }
                        os.Remove(filepath.Join(options.OutputPath, filename))
                    }
                }
            }
        }
    }

    //Iterate through each input directory
    for _, inputPath := range inputArray {

        if len(inputArray) != 1 {
            fmt.Println(options.Box + "Starting process for input '" + inputPath + "' into output '" + options.OutputPath + "'...")
        }

        // SET ORIGINALS
        originalInputPath := options.InputPath
        originalWipeOutput := options.WipeOutput
        options.InputPath = inputPath

        // RUN PARSER
        goauditparser.GoAuditParser_Start(options)

        // DISABLE WIPE DIRECTORY
        options.WipeOutput = false

        // RESET ORIGINALS
        options.InputPath = originalInputPath
        options.WipeOutput = originalWipeOutput
    }

    // RUN TIMELINER
    if options.Timeline {
        goauditparser.GoAuditTimeliner_Start(options)
    }
}

func MD5Hash(filepath string) string {
    f, err := os.Open(filepath)
    if err != nil {
        log.Fatal(err)
    }
    h := md5.New()
    if _, err := io.Copy(h, f); err != nil {
        log.Fatal(err)
    }
    hash := string(h.Sum(nil))
    f.Close()
    return hash
}

func RemoveFilesByExt(dirpath string, ext string) {
    files, _ := ioutil.ReadDir(dirpath)
    for _, f := range files {
        if strings.HasSuffix(f.Name(), ext) {
            os.Remove(filepath.Join(dirpath, f.Name()))
        }
    }
}
