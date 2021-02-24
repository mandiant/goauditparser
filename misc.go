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
    "encoding/json"
    "flag"
    "fmt"
    "io/ioutil"
    "log"
    "os"
    "os/user"
    "path/filepath"
    "regexp"
    "runtime"
    "strconv"
    "strings"
    "time"
)

func GetASCIIArt() string {
    return `
              ______      ___             ___ __  ____                           
   --111<xml>10____/___  /   | __  ______/ (_) /_/ __ \____ ______________  _____
  --10011<audit>1_/ __ \/ /| |/ / / / __  / / __/ /_/ / __ '/ ___/ ___/ _ \/ ___/
 --110</audit>0/ / /_/ / ___ / /_/ / /_/ / / /_/ ____/ /_/ / /  \__  /  __/ /    
--01101</xml>1011\____/_/  |_\____/\____/_/\__/_/    \__._/_/  \____/\___/_/     

+------------------------------------------------------------------------------+
| A utility designed for FireEye Endpoint Security analysts to extract, parse, |
|      and timeline XML audit data to CSV format quickly and efficiently.      |
+------------------------------------------------------------------------------+

                                 - Version ` + version + ` -
                          Copyright (C) 2020, FireEye, Inc.

`
}

func GetHelpExamples() string {
    return `+=================================================================================+
| Example GoAuditParser Syntax                                                    |
+===================+=============================================================+
| Basic Parse       | goauditparser -i <in_dir> -o <csv_dir>                      |
| Parse & Timeline  | goauditparser -i <in_dir> -o <csv_dir> -tl                  |
| Extract Audits    | goauditparser -i <in_dir> -eo <out_dir>                     |
| Extract File Acqs | goauditparser -i <in_dir> -efo <out_dir> -ep <password>     |
| Raw Parse         | goauditparser -i <in_dir> -o <csv_dir> -raw                 |
+-------------------+-------------------------------------------------------------+
`
}

func GetHelpMenu() string {
    return `

===== [BASICS] =======================================================================================================
# GoAuditParser can perform multiple tasks, sometimes independent of other steps, but it usually follows this order:

    #  Name       Description                                               Automatic?
    -- ---------  --------------------------------------------------------  ---------------
    1) EXTRACT    Extract XML audits and other files from FireEye archives  YES
    2) SPLIT      Split XML files that are too big into smaller files       YES
    3) PARSE      Parse XML data to CSV                                     YES
    4) TIMELINE   Timeline CSV data into an output file                     NO, needs '-tl'


===== [REQUIRED] =================================  ===== [NOTES] ====================================================
  -i <str>     Directory Input                      ! REQUIRED - (except when '-tlo' used)
                                                        Can provide multiple comma delimited paths:
                                                            Ex: -i "dir/xmldir1,xmldir2"
                                                        Works with .xml, .zip, or .mans files in the directory.

===== [EXTRACTING] ===============================  ==================================================================
# Extract and rename files from triages packages (.mans), bulk data collections (.zip), and file acquisitions (.zip).
# The standardized naming scheme for XML files is as follows:
#   <hostname>-<agentid>-<EXTRADATA>-<audittype>.xml

  -o <str>     CSV Directory Output                 ! ONE REQUIRED (1/2) - Parse XML to CSV. Defaults to "./parsed".
  -eo <str>    Extract Output Directory (Only)      ! ONE REQUIRED (2/2) - Only extract and do not parse audits.
                                                        Archive files are automatically extracted to input directory
                                                            if this flag is not used.
  -ep <str>    Archive Password                     Provide a password for encrypted archives.
                                                        Required to extract from file acquisition archives.
  -efo         Extract File Acquisitions Only       Extract acquired files from archives only, no XML audits.
                                                        Defaults '-eo' flag to "files" if not specified.
                                                        Does not parse audits if used.
  -eff <int>   Extract File Acquisition Format      Change how filenames for acquired files are formatted.
                                                        1: <hostname>-<agentid>-<payloadid>-<fullfilepath>_  (default)
                                                        2: <hostname>-<agentid>-<payloadid>-<fullfilepath>
                                                        3: <fullfilepath>_
                                                        4: <fullfilepath>
                                                        5: <basefilename>_
                                                        6: <basefilename>

  -exf <int>   Extract XML Format                   Change how filenames for acquired files are formatted.
                                                        1: <hostname>-<agentid>-<payloadid>-<audittype>.xml  (default)
                                                        2: <hostname>-<agentid>-0-<audittype>.xml

===== [SPLITTING] ================================  ==================================================================
# Split XML files. This step is automatically included if parsing.

  -xso <str>   XML Split Output Directory Only      Split XML audits into chunks. Use with '-xsb <int>' if desired.
                                                        XML files are automatically split to "<inputdir>/xmlsplit/".
                                                        Does not parse audits if a different path is specified.
                                                        Appends "_spxml#" to payload of filename.
  -xsb <int>   XML Split Byte Size                  Default value is "300000000" (300 MB). Not required for '-xso'.
  -ebs <str>   Event Buffer Split Output Directory  Split "eventbuffer" and "stateagentinspector" XML by event types.
                                                        Provide an output directory.
                                                        Does not parse audits if used.

===== [PARSING] ==================================  ==================================================================
# Parse XML audit data to CSV format.

  -o <str>     CSV Directory Output                 -REQUIRED- Parse XML to CSV. Defaults to "./parsed".
  -r           Recursive Input                      Recursively dive into directories for parsing files.
  -f           Force                                Force any previously extracted, parsed, or timelined
                                                        files to be reprocessed.
  -rn          Replace New-Line Chars with '|'      Useful when grepping through audits like event log messages.
  -wo          Wipe Output Directory                Delete all files in output directory before parsing.
                                                        Also enables "-f" flag for parsing/timelining only.
  -c <str>     Configuration File                   Contains a static order of headers for parsed CSV files.
                                                        Defaults to "~/.MandiantTools/GoAuditParser/config.json".
  -pcf <int>   Parsed CSV Format                    Change how filenames for acquired files are formatted.
                                                        1: <hostname>-<agentid>-<EXTRADATA>-<audittype>.csv  (default)
                                                        2: <hostname>-<agentid>-0-<audittype>.csv
  -pah <str>   Alternate Hostname                   Overwrite Hostname to provided string.
  -paa <str>   Alternate AgentID                    Overwrite AgentID to provided string.

===== [TIMELINING] ===============================  ==================================================================
# Convert parsed CSV audit data in the output directory into a timeline.
# A static timeline configuration file ('-tlcf <str>') is required to tell GoAuditParser how to format the timeline.

  -o <str>     CSV Directory Output                 -REQUIRED- Parse XML to CSV. Defaults to "./parsed"
  -tl          Timeline                             -REQUIRED- Timeline files after parsed from XML to CSV.
  -tlo         Timeline Only (don't parse)          Only perform timelining with specified CSV directory.
                                                        Needs output CSV directory specified with "-o <csv_dir>".
                                                        Does NOT need an input XML directory specified.
  -tld         Timeline Deduplicate                 Deduplicate timeline lines by entire row.
  -tlout <str> Timeline Output Filepath             Defaults to "<csv_dir>/_Timeline_<DATE>_<TIME>.csv".
  -tlf <str>   Timeline Filter                      Include only events which match the provided filter(s).
                                                        Time Filter formats:
                                                            "YYYY-MM-DD HH:MM:SS - YYYY-MM-DD HH:MM:SS"
                                                            "YYYY-MM-DD HH:MM:SS +-5m"
                                                            "YYYY-MM-DD - YYYY-MM-DD"
                                                            "YYYY-MM-DD +-5m"
                                                        Can provide multiple comma delimited filters:
                                                            Ex: -tlf "2019-01-01 - 2020-01-01,2015-01-01 +-3d"
  -tlsod       Output IIMS/SOD format               Overwrites default timeline config to match IIMS/SOD format.
  -tlcf <str>  Timeline Config Filepath             Defaults to "~/.MandiantTools/GoAuditParser/timeline.json".

===== [OTHER] ====================================  =================================================================
  -c <str>     Configuration File                   Defaults to "~/.MandiantTools/GoAuditParser/config.json".
  -raw         Disable Excel-Friendly Features      Using this flag will disable the following Excel-Friendly features:
                                                        1. Truncating cells to 32k chars
                                                        2. Split CSV files by 1mil rows
                                                            Appends "_spcsv#" to payload of filename.
  -t <int>     Thread Count                         Defaults to number of existing CPUs.
  -v[vvv]      Verbose
  -min         Minimized Output Mode
  --help       Show this Help Menu

`
}

type Options struct {
    InputPath           string
    ConfigPath          string
    Config              Main_Config_JSON
    OutputPath          string
    ReplaceNewLineFeeds bool
    ForceReparse        bool
    ParseAltHostname    string
    ParseAltAgentID     string
    ExcelFriendly       bool
    MinimizedOutput     bool
    Threads             int
    Timeline            bool
    TimelineOutputFile  string
    TimelineOnly        bool
    TimelineSOD         bool
    TimelineFilter      string
    TimelineFilters     [][]time.Time
    TimelineFilterEmpty bool
    TimelineConfigFile  string
    TimelineDeduplicate bool
    EventBufferSplitDir string
    WipeOutput          bool
    Help                bool
    AlternateParse      bool
    XMLSplitOutputDir   string
    XMLSplitByteSize    int
    RemoveNewlines      string
    ExtractionPassword  string
    ExtractionOutputDir string
    ExtractFilesOnly    bool
    ExtractFileFormat   int
    ExtractXMLFormat    int
    ParseCSVFormat      int
    SubTaskFiles        []os.FileInfo
    Recursive           bool

    Verbose int

    Box     string
    Warnbox string

    ErrorDuringSetup bool
}

func Setup() Options {

    flag.Usage = func() {
        fmt.Println(GetASCIIArt())
        fmt.Println(GetHelpExamples())
        fmt.Println(GetHelpMenu())
    }

    var v1 bool
    var v2 bool
    var v3 bool
    var v4 bool
    var raw bool

    options := Options{}

    flag.StringVar(&options.InputPath, "i", "", "")
    flag.StringVar(&options.ConfigPath, "c", "", "")
    flag.StringVar(&options.OutputPath, "o", "parsed", "")
    flag.BoolVar(&options.ReplaceNewLineFeeds, "rn", false, "")
    flag.BoolVar(&options.ForceReparse, "f", false, "")
    flag.BoolVar(&raw, "raw", false, "")
    flag.BoolVar(&options.MinimizedOutput, "min", false, "")
    flag.IntVar(&options.Threads, "t", -1, "")
    flag.BoolVar(&options.Timeline, "tl", false, "")
    flag.BoolVar(&options.TimelineDeduplicate, "tld", false, "")
    flag.BoolVar(&options.TimelineSOD, "tlsod", false, "")
    flag.BoolVar(&options.TimelineOnly, "tlo", false, "")
    flag.StringVar(&options.TimelineOutputFile, "tlout", "", "")
    flag.StringVar(&options.TimelineFilter, "tlf", "", "")
    flag.StringVar(&options.TimelineConfigFile, "tlcf", "", "")
    flag.StringVar(&options.EventBufferSplitDir, "ebs", "", "")
    flag.BoolVar(&options.WipeOutput, "wo", false, "")
    flag.StringVar(&options.XMLSplitOutputDir, "xso", "", "")
    flag.StringVar(&options.ExtractionOutputDir, "eo", "", "")
    flag.BoolVar(&options.ExtractFilesOnly, "efo", false, "")
    flag.StringVar(&options.ExtractionPassword, "ep", "", "")
    flag.IntVar(&options.ExtractFileFormat, "eff", 1, "")
    flag.IntVar(&options.ExtractXMLFormat, "exf", 1, "")
    flag.IntVar(&options.ParseCSVFormat, "pcf", 1, "")
    flag.IntVar(&options.XMLSplitByteSize, "xsb", 300000000, "")
    flag.StringVar(&options.ParseAltHostname, "pah", "", "")
    flag.StringVar(&options.ParseAltAgentID, "paa", "", "")
    flag.BoolVar(&options.Recursive, "r", false, "")

    flag.BoolVar(&v1, "v", false, "")
    flag.BoolVar(&v2, "vv", false, "")
    flag.BoolVar(&v3, "vvv", false, "")
    flag.BoolVar(&v4, "vvvv", false, "")

    flag.Parse()

    //Update some flags based on other flags
    options.Verbose = 0
    if v1 {
        options.Verbose = 1
    }
    if v2 {
        options.Verbose = 2
    }
    if v3 {
        options.Verbose = 3
    }
    if v4 {
        options.Verbose = 4
    }
    options.ExcelFriendly = !raw
    if options.ExtractFilesOnly && options.ExtractionOutputDir == "" {
        options.ExtractionOutputDir = "files"
    }
    if options.ExtractFileFormat <= 0 || options.ExtractFileFormat >= 7 {
        options.ExtractFileFormat = 1
    }
    if options.ExtractXMLFormat <= 0 || options.ExtractXMLFormat >= 3 {
        options.ExtractXMLFormat = 1
    }
    if options.ParseCSVFormat <= 0 || options.ParseCSVFormat >= 3 {
        options.ParseCSVFormat = 1
    }

    if options.TimelineSOD {
        options.Timeline = true
    }

    options.Box = "[+] "
    options.Warnbox = "[!] "
    if options.MinimizedOutput {
        options.Box = "[#] "
    }
    if !options.MinimizedOutput {
        fmt.Println(GetASCIIArt())
    } else {
        fmt.Println(options.Box + "- GoAuditParser v" + version + " -")
        fmt.Println(options.Box + "Copyright (C) 2020, FireEye, Inc.")
    }

    //Parse time filter
    options.TimelineFilterEmpty = false

    //options.TimelineFilters = [][]time.Time{}
    timeParse1 := regexp.MustCompile(`^ *(\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) *- *(\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) *$`)
    timeParse2 := regexp.MustCompile(`^ *(\d\d\d\d-\d\d-\d\d) *- *(\d\d\d\d-\d\d-\d\d) *$`)
    timeParse3 := regexp.MustCompile(`^ *(\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d) *(\+-|\+|\-) *(\d+) *([smhdy]) *$`)
    timeParse4 := regexp.MustCompile(`^ *(\d\d\d\d-\d\d-\d\d) *(\+-|\+|\-) *(\d+) *([smhdy]) *$`)
    if options.TimelineFilter == "" {
        options.TimelineFilterEmpty = true
    } else {
        timeStart := time.Time{}
        timeEnd := time.Time{}
        for _, timelineFilter := range strings.Split(options.TimelineFilter, ",") {
            // "DATE1 - DATE2"
            if timeParse1.MatchString(timelineFilter) || timeParse2.MatchString(timelineFilter) {
                if timeParse1.MatchString(timelineFilter) {
                    matches := timeParse1.FindStringSubmatch(timelineFilter)
                    t1, err_t1 := time.Parse("2006-01-02 15:04:05", matches[1])
                    if err_t1 != nil {
                        fmt.Println(options.Warnbox + "Could not parse '" + matches[1] + "' in format 'yyyy-mm-dd hh:mm:ss'.")
                        log.Fatal(err_t1)
                    }
                    t2, err_t2 := time.Parse("2006-01-02 15:04:05", matches[2])
                    if err_t2 != nil {
                        fmt.Println(options.Warnbox + "Could not parse '" + matches[2] + "' in format 'yyyy-mm-dd hh:mm:ss'.")
                        log.Fatal(err_t2)
                    }
                    timeStart = t1
                    timeEnd = t2
                } else {
                    matches := timeParse2.FindStringSubmatch(timelineFilter)
                    t1, err_t1 := time.Parse("2006-01-02", matches[1])
                    if err_t1 != nil {
                        fmt.Println(options.Warnbox + "Could not parse '" + matches[1] + "' in format 'yyyy-mm-dd'.")
                        log.Fatal(err_t1)
                    }
                    t2, err_t2 := time.Parse("2006-01-02", matches[2])
                    t2 = t2.Add(time.Hour*23 + time.Minute*59 + time.Minute*59)
                    if err_t2 != nil {
                        fmt.Println(options.Warnbox + "Could not parse '" + matches[2] + "' in format 'yyyy-mm-dd'.")
                        log.Fatal(err_t2)
                    }
                    timeStart = t1
                    timeEnd = t2
                }
                // "DATE +-5m"
            } else if timeParse3.MatchString(timelineFilter) || timeParse4.MatchString(timelineFilter) {
                var t time.Time
                var matches []string

                if timeParse3.MatchString(timelineFilter) {
                    matches = timeParse3.FindStringSubmatch(timelineFilter)
                    t1, err_t1 := time.Parse("2006-01-02 15:04:05", matches[1])
                    if err_t1 != nil {
                        fmt.Println(options.Warnbox + "Could not parse '" + matches[1] + "' in format 'yyyy-mm-dd hh:mm:ss'.")
                        log.Fatal(err_t1)
                    }
                    t = t1
                } else {
                    matches = timeParse4.FindStringSubmatch(timelineFilter)
                    t1, err_t1 := time.Parse("2006-01-02", matches[1])
                    if err_t1 != nil {
                        fmt.Println(options.Warnbox + "Could not parse '" + matches[1] + "' in format 'yyyy-mm-dd'.")
                        log.Fatal(err_t1)
                    }
                    t = t1
                }
                durNum, err_i := strconv.Atoi(matches[3])
                if err_i != nil {
                    fmt.Println(options.Warnbox + "Could not convert '" + matches[3] + "' to an integer.")
                    log.Fatal(err_i)
                }
                durName := matches[4]
                durVal := time.Second * 0
                if durName == "s" {
                    durVal = time.Duration(durNum) * time.Second
                } else if durName == "m" {
                    durVal = time.Duration(durNum) * time.Minute
                } else if durName == "h" {
                    durVal = time.Duration(durNum) * time.Hour
                } else if durName == "d" {
                    durVal = time.Duration(durNum*24) * time.Hour
                }

                operation := matches[2]
                if operation == "+-" {
                    timeStart = t.Add(-durVal)
                    timeEnd = t.Add(durVal)
                } else if operation == "+" {
                    timeStart = t
                    timeEnd = t.Add(durVal)
                } else if operation == "-" {
                    timeStart = t.Add(-durVal)
                    timeEnd = t
                }
            } else {
                fmt.Println(options.Warnbox + "ERROR - Could not parse provided timeline filter '" + timelineFilter + "'.")
                fmt.Println(options.Warnbox + "Formats: 'YYYY-MM-DD HH:MM:SS - YYYY-MM-DD HH:MM:SS' OR 'YYYY-MM-DD HH:MM:SS +-5m'")
                options.ErrorDuringSetup = true
                return options
            }
            options.TimelineFilters = append(options.TimelineFilters, []time.Time{timeStart, timeEnd})
        }
    }

    //Create config directory
    dataDir := GetDataDir(options)
    if options.TimelineConfigFile == "" {
        options.TimelineConfigFile = filepath.Join(dataDir, "timeline.json")
    }

    //Check for JSON Config File
    if options.ConfigPath == "" {
        options.ConfigPath = filepath.Join(dataDir, "config.json")
    }
    if options.Verbose > 0 {
        fmt.Println(options.Box + "Reading main config file '" + options.ConfigPath + "'...")
    }
    _, err_s := os.Stat(options.ConfigPath)
    //If config file exists, create the file
    if os.IsNotExist(err_s) {
        //Create config file
        fmt.Println(options.Warnbox + "NOTICE - Main config file '" + options.ConfigPath + "' does not exist. Creating...")
        file, err_c := os.Create(options.ConfigPath)
        if err_c != nil {
            fmt.Println(options.Box + "ERROR - Could not create main config file '" + options.ConfigPath + "'.")
            log.Fatal(err_c)
        }
        var newconfig Main_Config_JSON
        err_j := json.Unmarshal([]byte(GetMainConfigTemplate(options)), &newconfig)
        if err_j != nil {
            if options.Verbose > 2 {
                fmt.Println(GetMainConfigTemplate(options))
            }
            fmt.Println(options.Warnbox + "ERROR - Could not parse pre-made JSON for main config file. Please contact the developer.")
            log.Fatal(err_j)
        }
        file.WriteString(GetMainConfigTemplate(options))
        file.Close()
    }

    //Read JSON from config file
    file, err_o := os.Open(options.ConfigPath)
    if err_o != nil {
        fmt.Println(options.Warnbox + "ERROR - Could not open main config file '" + options.ConfigPath + "'.")
        log.Fatal(err_o)
    }
    b, err_i := ioutil.ReadAll(file)
    if err_i != nil {
        fmt.Println(options.Warnbox + "ERROR - Could not read contents from main config '" + options.ConfigPath + "'.")
        log.Fatal(err_i)
    }
    var config Main_Config_JSON
    err_j := json.Unmarshal(b, &config)
    file.Close()
    if err_j != nil {
        fmt.Println(options.Warnbox + "ERROR - Could not parse JSON from main config file '" + options.ConfigPath + "': " + err_j.Error())
        reader := bufio.NewReader(os.Stdin)
        fmt.Println(options.Box + "Would you like to overwrite the previous main config file with a new one? [Y/N]")
        fmt.Print("> ")
        text, _ := reader.ReadString('\n')
        if strings.HasPrefix(strings.TrimSpace(strings.ToLower(text)), "y") {
            file, err_c := os.Create(options.ConfigPath)
            if err_c != nil {
                fmt.Println(options.Box + "ERROR - Could not create main config file '" + options.ConfigPath + "'.")
                log.Fatal(err_c)
            }
            var newconfig Main_Config_JSON
            err_j := json.Unmarshal([]byte(GetMainConfigTemplate(options)), &newconfig)
            if err_j != nil {
                if options.Verbose > 2 {
                    fmt.Println(GetMainConfigTemplate(options))
                }
                fmt.Println(options.Warnbox + "ERROR - Could not parse pre-made JSON for main config file. Please contact the developer.")
                log.Fatal(err_j)
            }
            file.WriteString(GetMainConfigTemplate(options))
            file.Close()
        } else {
            fmt.Println(options.Warnbox + "Please fix the main config file manually.")
            options.ErrorDuringSetup = true
            return options
        }
    }

    //Check for new version
    updateConig := false
    if config.Version != version {
        if !config.DontOverwrite {
            fmt.Println(options.Box + "Updating old config v" + config.Version + " to v" + version + "...")
            //Update config
            updateConig = true
            var newconfig Main_Config_JSON
            err_j := json.Unmarshal([]byte(GetMainConfigTemplate(options)), &newconfig)
            if err_j != nil {
                fmt.Println(options.Warnbox + "ERROR - Could not parse pre-made JSON for main config file. Please contact the developer.")
                log.Fatal(err_j)
            }
            //Keep some old settings
            newconfig.OmitUnlisted = config.OmitUnlisted
            if !strings.HasPrefix(config.Version, "0.") {
                newconfig.AutoSplitFiles = config.AutoSplitFiles
                newconfig.AutoExtract = config.AutoExtract
            }
            config = newconfig
        } else {
            fmt.Println(options.Warnbox + "NOTICE - New main config file version is available, but the JSON property 'Dont_Overwrite_With_New_Update' is set to 'true'.")
            time.Sleep(time.Second * 1)
        }
    }

    //Update the main config file
    if updateConig {
        fmt.Println(options.Box + "Updating config file...")
        //Write new JSON to timeline file
        newFile, err_c := os.Create(options.ConfigPath)
        config.Version = version
        if err_c != nil {
            fmt.Println(options.Warnbox + "ERROR - Could not create new version of main config file '" + options.ConfigPath + "'")
            log.Fatal(err_c)
        }
        b, _ := json.MarshalIndent(config, "", "    ")
        newFile.Write(b)
        newFile.Close()
    }
    options.Config = config

    //Set thread count
    if options.Threads <= 0 {
        options.Threads = runtime.NumCPU()
    }
    if options.Verbose > 2 {
        fmt.Println(options.Warnbox + "NOTICE - Verbosity set to DEBUG state. Multi-threading is disabled.")
        options.Threads = 1
    }

    return options
}

func GetDataDir(options Options) string {
    var dirName = filepath.Join(".MandiantTools", "GoAuditParser")
    var dataPath = ""

    usr, u_err := user.Current()
    if u_err != nil {
        log.Fatal(options.Box + "ERROR - Could not identify user.")
    }
    dataPath = filepath.Join(usr.HomeDir, dirName)
    //Create directory if necessary
    if _, s_err := os.Stat(dataPath); os.IsNotExist(s_err) {
        d_err := os.MkdirAll(dataPath, os.ModePerm)
        if d_err != nil {
            log.Fatal(options.Box + "ERROR - Could not create data directory '" + dataPath + "'.")
        }
    }

    return dataPath
}

type Main_Config_JSON struct {
    Version            string   `json:"Version"`
    DontOverwrite      bool     `json:"Dont_Overwrite_With_New_Update"`
    AutoSplitFiles     bool     `json:"Automatically_Split_Big_XML"`
    AutoExtract        bool     `json:"Automatically_Extract_Archives"`
    OmitUnlisted       bool     `json:"Omit_Nonordered_Headers"`
    HeadersMandatory   []string `json:"Mandatory_Headers"`
    HeadersOptional    []string `json:"Optional_Headers"`
    AuditHeaderConfigs []struct {
        Name           string   `json:"Name"`
        ItemName       string   `json:"Item_Name"`
        HeaderOrder    []string `json:"Header_Order"`
        HeadersOmitted []string `json:"Headers_Omitted"`
    } `json:"Audit_Header_Configs"`
}

func GetMainConfigTemplate(options Options) string {
    template_head := `{
    "Version": "` + version + `",
    "Dont_Overwrite_With_New_Update": false,
    "Automatically_Split_Big_XML": true,
    "Automatically_Extract_Archives": true,
    "Omit_Nonordered_Headers": false,
    "Mandatory_Headers": [
        "Tag",
        "Notes",
        "Hostname",
        "AgentID"
    ],
    "Optional_Headers": [
        "Audit UID",
        "UID",
        "Sequence Number",
        "FireEyeGeneratedTime",
        "EventBufferType"
    ],
    "Audit_Header_Configs": [
`
    template_audits := `        {
            "Name": "AgentInfo",
            "Item_Name": "AgentInfo",
            "Header_Order": [],
            "Headers_Omitted": []
        },{
            "Name": "ArpEntryItem",
            "Item_Name": "ArpEntryItem",
            "Header_Order": [
                "Interface",
                "InterfaceType",
                "PhysicalAddress",
                "IPv4Address",
                "IPv6Address",
                "IsRouter",
                "LastReachable",
                "LastUnreachable",
                "CacheType",
                "State"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "CookieHistoryItem",
            "Item_Name": "CookieHistoryItem",
            "Header_Order": [
                "FileName",
                "FilePath",
                "CookiePath",
                "CookieName",
                "CookieValue",
                "HostName",
                "ExpirationDate",
                "CreationDate",
                "LastAccessedDate",
                "LastModifiedDate",
                "Username",
                "Profile",
                "BrowserName",
                "BrowserVersion",
                "IsSecure",
                "IsHttpOnly"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "DiskItem",
            "Item_Name": "DiskItem",
            "Header_Order": [
                "DiskName",
                "DiskSize",
                "PartitionList.Partition.PartitionNumber",
                "PartitionList.Partition.PartitionOffset",
                "PartitionList.Partition.PartitionLength",
                "PartitionList.Partition.PartitionType"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "DnsEntryItem",
            "Item_Name": "DnsEntryItem",
            "Header_Order": [
                "Host",
                "RecordName",
                "RecordType",
                "TimeToLive",
                "Flags",
                "DataLength",
                "RecordData"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "DriverItem",
            "Item_Name": "DriverItem",
            "Header_Order": [
                "DriverName",
                "DriverInit",
                "DriverStartIo",
                "DriverUnload",
                "DeviceName",
                "DriverObjectAddress",
                "ImageBase",
                "ImageSize",
                "Md5sum",
                "SignatureExists",
                "SignatureVerified",
                "SignatureDescription",
                "CertificateIssuer"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "EventItem_DnsLookupEvent",
            "Item_Name": "EventItem_DnsLookupEvent",
            "Header_Order": [
                "EventBufferTime_DnsLookupEvent",
                "ProcessPath",
                "Process",
                "DNSHostname",
                "Pid"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "EventItem_FileWriteEvent",
            "Item_Name": "EventItem_FileWriteEvent",
            "Header_Order": [
                "EventBufferTime_FileWriteEvent",
                "ProcessPath",
                "Process",
                "FullPath",
                "DevicePath",
                "Md5",
                "Pid",
                "Closed",
                "Writes",
                "Size",
                "NumBytesSeenWritten",
                "LowestFileOffsetSeen",
                "TextAtLowestOffset"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "EventItem_ImageLoadEvent",
            "Item_Name": "EventItem_ImageLoadEvent",
            "Header_Order": [
                "EventBufferTime_ImageLoadEvent",
                "ProcessPath",
                "Process",
                "FullPath",
                "DevicePath",
                "Pid"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "EventItem_Ipv4NetworkEvent",
            "Item_Name": "EventItem_Ipv4NetworkEvent",
            "Header_Order": [
                "EventBufferTime_Ipv4NetworkEvent",
                "ProcessPath",
                "Process",
                "LocalIP",
                "LocalPort",
                "RemoteIP",
                "RemotePort",
                "Protocol",
                "Pid"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "EventItem_ProcessEvent",
            "Item_Name": "EventItem_ProcessEvent",
            "Header_Order": [
                "EventBufferTime_ProcessEvent",
                "ProcessPath",
                "Process",
                "ProcessCmdLine",
                "Md5",
                "ParentProcessPath",
                "ParentProcess",
                "EventType",
                "Pid",
                "ParentPid",
                "StartTime"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "EventItem_RegKeyEvent",
            "Item_Name": "EventItem_RegKeyEvent",
            "Header_Order": [
                "EventBufferTime_RegKeyEvent",
                "ProcessPath",
                "Process",
                "Path",
                "ValueName",
                "Text",
                "ValueType",
                "EventType",
                "Pid"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "EventItem_UrlMonitorEvent",
            "Item_Name": "EventItem_UrlMonitorEvent",
            "Header_Order": [
                "EventBufferTime_UrlMonitorEvent",
                "ProcessPath",
                "Process",
                "DNSHostname",
                "RequestUrl",
                "RemoteIpAddress",
                "Text",
                "LocalPort",
                "RemotePort",
                "UrlMethod",
                "UserAgent",
                "Pid"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "EventLogItem",
            "Item_Name": "EventLogItem",
            "Header_Order": [
                "genTime",
                "writeTime",
                "log",
                "source",
                "EID",
                "type",
                "message",
                "user",
                "index",
                "machine",
                "category",
                "CorrelationActivityId",
                "CorrelationRelatedActivityId",
                "ExecutionProcessId",
                "ExecutionThreadId"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "FileDownloadHistoryItem",
            "Item_Name": "FileDownloadHistoryItem",
            "Header_Order": [
                "Profile",
                "BrowserName",
                "BrowserVersion",
                "Username",
                "DownloadType",
                "SourceURL",
                "TargetDirectory",
                "StartDate",
                "EndDate",
                "LastCheckedDate",
                "LastAccessedDate",
                "LastModifiedDate",
                "BytesDownloaded",
                "MaxBytes"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "FileItem",
            "Item_Name": "FileItem",
            "Header_Order": [
                "FullPath",
                "Created",
                "Modified",
                "Accessed",
                "Changed",
                "FilenameCreated",
                "FilenameModified",
                "FilenameAccessed",
                "FilenameChanged",
                "SizeInBytes",
                "Md5sum",
                "Username",
                "FileAttributes",
                "INode",
                "SecurityID",
                "SecurityType",
                "DevicePath",
                "Drive",
                "FilePath",
                "FileName",
                "FileExtension"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "FormHistoryItem",
            "Item_Name": "FormHistoryItem",
            "Header_Order": [
                "Username",
                "Profile",
                "BrowserName",
                "BrowserVersion",
                "FormType",
                "FormFieldName",
                "FormFieldValue",
                "TimesUsed",
                "FirstUsedDate",
                "LastUsedDate",
                "Guid"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "GroupItem",
            "Item_Name": "GroupItem",
            "Header_Order": [
                "GroupName",
                "fullname",
                "groupguid",
                "userlist.username",
                "gid"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "HiveItem",
            "Item_Name": "HiveItem",
            "Header_Order": [
                "Name",
                "Path"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "HookItem",
            "Item_Name": "HookItem",
            "Header_Order": [
                "HookDescription",
                "HookedFunction",
                "HookedModule",
                "HookingModule",
                "HookingAddress",
                "DigitalSignatureHooking",
                "DigitalSignatureHooked"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "LoginHistoryItem",
            "Item_Name": "LoginHistoryItem",
            "Header_Order": [
                "Path",
                "StartTime",
                "EndTime",
                "SessionLength",
                "Hostname",
                "IsRemoteLogin",
                "IPv4Address",
                "IPv6Address",
                "Username",
                "RecordType",
                "PID",
                "Terminal",
                "IsFailedLogin"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "ModuleItem",
            "Item_Name": "ModuleItem",
            "Header_Order": [
                "ModuleAddress",
                "ModuleInit",
                "ModuleBase",
                "ModuleSize",
                "ModulePath",
                "ModuleName"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "PersistenceItem",
            "Item_Name": "PersistenceItem",
            "Header_Order": [
                "PersistenceType",
                "status",
                "serviceDLLCertificateIssuer",
                "md5sum",
                "TaskFileName",
                "SignatureVerified",
                "RegistryItem",
                "pathSignatureDescription",
                "mode",
                "CertificateIssuer",
                "serviceDLLCertificateSubject",
                "RegOwner",
                "MagicHeader",
                "detectedAnomaly",
                "Scheduled",
                "FileModified",
                "pathSignatureVerified",
                "serviceDLL",
                "FileCreated",
                "arguments",
                "ServiceItem",
                "SignatureExists",
                "FileOwner",
                "FileChanged",
                "startedAs",
                "FileItem",
                "SignatureDescription",
                "serviceDLLmd5sum",
                "Created",
                "RegText",
                "pathmd5sum",
                "TaskStatus",
                "RegModified",
                "ServiceName",
                "Command",
                "TaskFullPath",
                "ServicePath",
                "TaskName",
                "pathCertificateIssuer",
                "serviceDLLSignatureExists",
                "LastRun",
                "serviceDLLSignatureDescription",
                "serviceDLLMagicHeader",
                "pathMagicHeader",
                "FilePath",
                "pathCertificateSubject",
                "FileAccessed",
                "descriptiveName",
                "CertificateSubject",
                "serviceDLLSignatureVerified",
                "pathSignatureExists",
                "RegPath"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "PortItem",
            "Item_Name": "PortItem",
            "Header_Order": [
                "pid",
                "process",
                "path",
                "state",
                "localIP",
                "remoteIP",
                "localPort",
                "remotePort",
                "protocol"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "PrefetchItem",
            "Item_Name": "PrefetchItem",
            "Header_Order": [
                "ApplicationFileName",
                "ApplicationFullPath",
                "Created",
                "LastRun",
                "TimesExecuted",
                "ReportedSizeInBytes",
                "FullPath",
                "SizeInBytes",
                "PrefetchHash"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "ProcessItem",
            "Item_Name": "ProcessItem",
            "Header_Order": [
                "pid",
                "parentpid",
                "path",
                "name",
                "arguments",
                "Username",
                "SecurityID",
                "SecurityType",
                "startTime",
                "kernelTime",
                "userTime"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "QuarantineEventItem",
            "Item_Name": "QuarantineEventItem",
            "Header_Order": [
                "User",
                "EventIdentifier",
                "TimeStamp",
                "AgentBundleIdentifier",
                "AgentName",
                "DataURLString",
                "TypeNumber",
                "OriginURLString"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "QuarantineListItem",
            "Item_Name": "QuarantineListItem",
            "Header_Order": [
                "QuarId",
                "CorrelationId",
                "QuarantineTime",
                "Final",
                "ObjectType",
                "FilePath",
                "FileSize",
                "FileMD5",
                "FileSHA1",
                "FileState"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "RegistryItem",
            "Item_Name": "RegistryItem",
            "Header_Order": [
                "Path",
                "Text",
                "Modified",
                "Username",
                "SecurityID",
                "Hive",
                "KeyPath",
                "ValueName",
                "Type",
                "Value",
                "NumValues",
                "NumSubKeys",
                "ReportedLengthInBytes"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "RouteEntryItem",
            "Item_Name": "RouteEntryItem",
            "Header_Order": [
                "Interface",
                "Destination",
                "Netmask",
                "Gateway",
                "RouteType",
                "Protocol",
                "RouteAge",
                "Metric",
                "IsIPv6"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "ScanSummary",
            "Item_Name": "ScanSummary",
            "Header_Order": [
                "uuid",
                "scan-name",
                "scan-type",
                "scanned-object",
                "infected-object",
                "actioned-object",
                "timestamp",
                "start-time",
                "end-time",
                "scan-result",
                "scan-error",
                "product-version",
                "engine-version",
                "content-version",
                "reboot-required",
                "scan-correlation-id", 
                "scan-summary-version"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "ServiceItem",
            "Item_Name": "ServiceItem",
            "Header_Order": [
                "name",
                "descriptiveName",
                "description",
                "mode",
                "startedAs",
                "path",
                "arguments",
                "pathmd5sum",
                "pathSignatureExists",
                "pathSignatureVerified",
                "pathSignatureDescription",
                "pathCertificateSubject",
                "pathCertificateIssuer",
                "serviceDLL",
                "serviceDLLmd5sum",
                "serviceDLLSignatureExists",
                "serviceDLLSignatureVerified",
                "serviceDLLSignatureDescription",
                "serviceDLLCertificateSubject",
                "serviceDLLCertificateIssuer",
                "status",
                "pid",
                "type",
                "md5sum",
                "sha1sum",
                "sha256sum",
                "userName",
                "groupName",
                "reference"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "ShellHistoryItem",
            "Item_Name": "ShellHistoryItem",
            "Header_Order": [
                "FileOrder",
                "Command",
                "UserName",
                "Shell",
                "Timestamp"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "SudoLogItem",
            "Item_Name": "SudoLogItem",
            "Header_Order": [
            "timestamp",
            "ModifiedTimestamp",
            "suOrSudo",
            "username",
            "tty",
            "pwd",
            "userExecuteAs",
            "command",
            "success",
            "SourceLog"

            ],
            "Headers_Omitted": []
        },
        {
            "Name": "Syslog",
            "Item_Name": "Syslog",
            "Header_Order": [
                "ID",
                "Time",
                "Level",
                "PID",
                "UID",
                "GID",
                "Host",
                "Sender",
                "Facility",
                "Message"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "SystemInfoItem",
            "Item_Name": "SystemInfoItem",
            "Header_Order": [
                "machine",
                "totalphysical",
                "availphysical",
                "uptime",
                "OS",
                "OSbitness",
                "hostname",
                "date",
                "user",
                "domain",
                "processor",
                "patchLevel",
                "buildNumber",
                "procType",
                "productID",
                "productName",
                "regOrg",
                "regOwner",
                "installDate",
                "MAC",
                "timezoneDST",
                "timezoneStandard",
                "networkArray",
                "containmentState",
                "timezone",
                "gmtoffset",
                "clockSkew",
                "stateAgentStatus",
                "primaryIpv4Address",
                "primaryIpAddress",
                "loggedOnUser",
                "appVersion",
                "platform",
                "appCreated"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "SystemRestoreItem",
            "Item_Name": "SystemRestoreItem",
            "Header_Order": [],
            "Headers_Omitted": []
        },
        {
            "Name": "TaskItem",
            "Item_Name": "TaskItem",
            "Header_Order": [
                "Name",
                "VirtualPath",
                "ExitCode",
                "CreationDate",
                "Comment",
                "Creator",
                "MaxRunTime",
                "Flag",
                "AccountName",
                "AccountRunLevel",
                "AccountLogonType",
                "MostRecentRunTime",
                "NextRunTime",
                "Status"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "UrlHistoryItem",
            "Item_Name": "UrlHistoryItem",
            "Header_Order": [
                "Profile",
                "BrowserName",
                "BrowserVersion",
                "LastVisitDate",
                "Username",
                "URL",
                "PageTitle",
                "HostName",
                "Typed",
                "Hidden",
                "VisitFrom",
                "VisitType",
                "VisitCount"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "UserItem",
            "Item_Name": "UserItem",
            "Header_Order": [
                "Username",
                "SecurityID",
                "SecurityType",
                "fullname",
                "description",
                "homedirectory",
                "scriptpath",
                "grouplist",
                "LastLogin",
                "disabled",
                "lockedout",
                "passwordrequired",
                "userpasswordage",
                "shell",
                "userid",
                "userguid"
            ],
            "Headers_Omitted": []
        },
        {
            "Name": "VolumeItem",
            "Item_Name": "VolumeItem",
            "Header_Order": [
                "VolumeName",
                "DevicePath",
                "DriveLetter",
                "Type",
                "Name",
                "SerialNumber",
                "FileSystemFlags",
                "FileSystemName",
                "ActualAvailableAllocationUnits",
                "TotalAllocationUnits",
                "BytesPerSector",
                "SectorsPerAllocationUnit",
                "CreationTime",
                "IsMounted"
            ],
            "Headers_Omitted": []
        }`
    template_end := `
    ]
}`
    return template_head + template_audits + template_end
}

type Parse_Config_JSON struct {
    Version           string                         `json:"Version"`
    OutputDirectories []Parse_Config_OutputDirectory `json:"OutputDirectories"`
}

type Parse_Config_OutputDirectory struct {
    OutputDirectory string                     `json:"OutputDirectory"`
    XMLFiles        []Parse_Config_XMLFile     `json:"XMLFiles"`
    ArchiveFiles    []Parse_Config_ArchiveFile `json:"ArchiveFiles"`
}

type Parse_Config_XMLFile struct {
    InputFileName string `json:"Name"`
    InputFileSize int64  `json:"Size"`
    Status        string `json:"Status"`
}

type Parse_Config_ArchiveFile struct {
    InputFileName string `json:"Name"`
    InputFileSize int64  `json:"Size"`
    Status        string `json:"Status"`
}

func ParseConfigSave(config Parse_Config_JSON, options Options) error {
    inputConfigFile := filepath.Join(options.InputPath, "_GAPParseCache.json")
    file, err_c := os.Create(inputConfigFile)
    if err_c != nil {
        return err_c
    }
    b, err_m := json.Marshal(config)
    if err_m != nil {
        return err_m
    }
    file.Write(b)
    file.Close()
    return nil
}

func ParseConfigUpdateXMLParse(dirIndex int, xmlfile os.FileInfo, msg string, extra bool, config Parse_Config_JSON) Parse_Config_JSON {
    xmlFileIndex := -1
    found := false
    filename := filepath.Base(xmlfile.Name())
    filesize := xmlfile.Size()
    for i, xmlFile := range config.OutputDirectories[dirIndex].XMLFiles {
        if xmlFile.InputFileSize == filesize && xmlFile.InputFileName == filename {
            found = true
            xmlFileIndex = i
            break
        }
    }
    if !found {
        config.OutputDirectories[dirIndex].XMLFiles = append(config.OutputDirectories[dirIndex].XMLFiles, Parse_Config_XMLFile{InputFileName: filename, InputFileSize: filesize})
        xmlFileIndex = len(config.OutputDirectories[dirIndex].XMLFiles) - 1
    }
    status := msg
    if strings.Contains(msg, "already exists") {
        status = "parsed"
    }
    if strings.Contains(msg, "parsed successfully") {
        status = "parsed"
    }
    if strings.Contains(msg, "Issues file") {
        status = "ignored/issues"
    }
    if strings.Contains(msg, "is empty") {
        status = "ignored/empty"
    }
    if strings.Contains(msg, "not rename") {
        status = "failed/rename"
    }
    if strings.Contains(msg, "not parse file") {
        status = "failed/error"
    }
    if strings.Contains(msg, "does not exist") {
        status = "failed/notexist"
    }
    if strings.Contains(msg, "File was split") {
        status = "split"
    }
    config.OutputDirectories[dirIndex].XMLFiles[xmlFileIndex].Status = status
    return config
}

func InputConfig_GetOutDirIndex(path string, config Parse_Config_JSON) (Parse_Config_JSON, int) {
    for i, outdir := range config.OutputDirectories {
        if outdir.OutputDirectory == path {
            return config, i
        }
    }
    config.OutputDirectories = append(config.OutputDirectories, Parse_Config_OutputDirectory{OutputDirectory: path})
    return config, len(config.OutputDirectories) - 1
}

func InputConfig_GetXMLParseFileStatus(xmlfile os.FileInfo, dirIndex int, config Parse_Config_JSON) (Parse_Config_JSON, string) {
    xmlFileIndex := -1
    found := false
    filename := filepath.Base(xmlfile.Name())
    filesize := xmlfile.Size()
    for _, xmlFile := range config.OutputDirectories[dirIndex].XMLFiles {
        if xmlFile.InputFileSize == filesize && xmlFile.InputFileName == filename {
            return config, xmlFile.Status
        }
    }
    if !found {
        config.OutputDirectories[dirIndex].XMLFiles = append(config.OutputDirectories[dirIndex].XMLFiles, Parse_Config_XMLFile{InputFileName: filename, InputFileSize: filesize})
        xmlFileIndex = len(config.OutputDirectories[dirIndex].XMLFiles) - 1
    }
    config.OutputDirectories[dirIndex].XMLFiles[xmlFileIndex].Status = "failed/notattemptedyet"
    return config, "failed/notattemptedyet"
}

func InputConfig_GetXMLParseConfig(xmlfile os.FileInfo, dirIndex int, config Parse_Config_JSON) (Parse_Config_JSON, Parse_Config_XMLFile) {
    xmlFileIndex := -1
    found := false
    filename := filepath.Base(xmlfile.Name())
    filesize := xmlfile.Size()
    for _, xmlFile := range config.OutputDirectories[dirIndex].XMLFiles {
        if xmlFile.InputFileSize == filesize && xmlFile.InputFileName == filename {
            return config, xmlFile
        }
    }
    if !found {
        config.OutputDirectories[dirIndex].XMLFiles = append(config.OutputDirectories[dirIndex].XMLFiles, Parse_Config_XMLFile{InputFileName: filename, InputFileSize: filesize})
        xmlFileIndex = len(config.OutputDirectories[dirIndex].XMLFiles) - 1
    }
    config.OutputDirectories[dirIndex].XMLFiles[xmlFileIndex].Status = "failed/notattemptedyet"
    return config, config.OutputDirectories[dirIndex].XMLFiles[xmlFileIndex]
}

func ParseConfigGetArchiveFileStatus(archiveFile os.FileInfo, dirIndex int, config Parse_Config_JSON) (Parse_Config_JSON, string) {
    archiveFileIndex := -1
    found := false
    filename := filepath.Base(archiveFile.Name())
    filesize := archiveFile.Size()
    for _, archiveFile := range config.OutputDirectories[dirIndex].ArchiveFiles {
        if archiveFile.InputFileSize == filesize && archiveFile.InputFileName == filename {
            return config, archiveFile.Status
        }
    }
    if !found {
        config.OutputDirectories[dirIndex].ArchiveFiles = append(config.OutputDirectories[dirIndex].ArchiveFiles, Parse_Config_ArchiveFile{InputFileName: filename, InputFileSize: filesize})
        archiveFileIndex = len(config.OutputDirectories[dirIndex].ArchiveFiles) - 1
    }
    config.OutputDirectories[dirIndex].ArchiveFiles[archiveFileIndex].Status = "failed/notattemptedyet"
    return config, "failed/notattemptedyet"
}

func ParseConfigUpdateArchive(dirIndex int, archivefile os.FileInfo, msg string, config Parse_Config_JSON) Parse_Config_JSON {
    archiveFileIndex := -1
    found := false
    filename := filepath.Base(archivefile.Name())
    filesize := archivefile.Size()
    for i, archiveFile := range config.OutputDirectories[dirIndex].ArchiveFiles {
        if archiveFile.InputFileSize == filesize && archiveFile.InputFileName == filename {
            found = true
            archiveFileIndex = i
            break
        }
    }
    if !found {
        config.OutputDirectories[dirIndex].ArchiveFiles = append(config.OutputDirectories[dirIndex].ArchiveFiles, Parse_Config_ArchiveFile{InputFileName: filename, InputFileSize: filesize})
        archiveFileIndex = len(config.OutputDirectories[dirIndex].ArchiveFiles) - 1
    }
    status := msg
    if strings.Contains(msg, "unarchived successfully") {
        status = "extracted"
    }
    if strings.Contains(msg, "unarchived with issues") {
        status = "partial"
    }
    if strings.Contains(msg, "Failed to unarchive") {
        status = "failed"
    }
    config.OutputDirectories[dirIndex].ArchiveFiles[archiveFileIndex].Status = status
    return config
}

//ExtraEnabled for addons/extensions
func ExtraEnabled() bool {
    return true
}

//ExtraStruct1 for addons/extensions
type ExtraStruct1 struct {
    ExtraBool1 bool
}

//ExtraStruct2 for addons/extensions
type ExtraStruct2 struct {
}

//ExtraFunc1 for addons/extensions
func ExtraFunc1(options Options, files []os.FileInfo, config Parse_Config_JSON, configOutDirIndex int) (Parse_Config_JSON, ExtraStruct1, string) {
    es1 := ExtraStruct1{}
    extramsg := ""
    return config, es1, extramsg
}

//ExtraFunc2 for addons/extensions
func ExtraFunc2(options Options, fileconfig Parse_Config_XMLFile) ExtraStruct2 {
    es2 := ExtraStruct2{}
    return es2
}

//ExtraFunc3 for addons/extensions
func ExtraFunc3(options Options, fileconfig Parse_Config_XMLFile, es2 ExtraStruct2) ExtraStruct2 {
    return es2
}

//ExtraFunc4 for addons/extensions
func ExtraFunc4(options Options, es1 ExtraStruct1, es2 ExtraStruct2, line string, headerPathParts []string, headers map[string]int, row map[int]*strings.Builder, include_value bool) bool {
    return include_value
}

//ExtraFunc5 for addons/extensions
func ExtraFunc5(options Options, fileconfig Parse_Config_XMLFile) bool {
    value := false
    return value
}

//ExtraFunc6 for addons/extensions
func ExtraFunc6(options Options) bool {
    value := false
    return value
}


//ExtraFunc7 for addons/extensions
func ExtraFunc7(options Options, attr int) string {
    value := "Extra"
    return value
}

func GetTimelineConfigTemplate() string {
    template_head := `{
    "Version": "` + version + `",
    "Dont_Overwrite_With_New_Update": false,
    "Include_Summary_Headers": true,
    "Unique_Row_Per_Timestamp": false,
    "Include_Timestampless_Audits": true,
    "Extra_Fields_Order": ["Tag","Notes","Hostname","AgentID","MD5","Size","User","SignatureExists","SignatureVerified","SubAuditType","Extra1","Extra2","Extra3"],
    "Audit_Timeline_Configs":
    [`
    template_audits := `
        {   
            "Name": "CookieHistoryItem",
            "Filename_Suffix": "CookieHistoryItem",
            "Timestamp_Fields": [
                "CreationDate",
                "ExpirationDate",
                "LastAccessedDate",
                "LastModifiedDate"
            ],
            "Summary_Fields": [
                "FilePath",
                "CookiePath"
            ],
            "Extra_Fields": [
                "Hostname",
                "AgentID"
            ]
        },
        {   
            "Name": "CookieHistoryItem",
            "Filename_Suffix": "CookieHistoryItem",
            "Timestamp_Fields": [
                "CreationDate",
                "ExpirationDate",
                "LastAccessedDate",
                "LastModifiedDate"
            ],
            "Summary_Fields": [
                "FilePath",
                "CookiePath"
            ],
            "Extra_Fields": [
                "Hostname",
                "AgentID"
            ]
        },
        {
            "Name": "DiskItem",
            "Filename_Suffix": "DiskItem",
            "Timestamp_Fields": [],
            "Summary_Fields": [
                "DiskName",
                "DiskSize",
                "PartitionList.Partition.PartitionNumber",
                "PartitionList.Partition.PartitionOffset",
                "PartitionList.Partition.PartitionLength",
                "PartitionList.Partition.PartitionType"
            ],
            "Extra_Fields": [
                "PartitionList.Partition.PartitionLength>Size",
                "Hostname",
                "AgentID"
            ]
        },
        {
            "Name": "DnsEntryItem",
            "Filename_Suffix": "DnsEntryItem",
            "Timestamp_Fields": [],
            "Summary_Fields": [
                "Host",
                "RecordName",
                "RecordType",
                "RecordData.IPv4Address",
                "TimeToLive"
            ],
            "Extra_Fields": [
                "DataLength>Size",
                "Hostname",
                "AgentID"
            ]
        },
        {
            "Name": "DriverItem",
            "Filename_Suffix": "DriverItem",
            "Timestamp_Fields": [],
            "Summary_Fields": [
                "DeviceName",
                "DriverName"
            ],
            "Extra_Fields": [
                "Hostname",
                "AgentID"
            ]
        },
        {
            "Name": "EventItem_DnsLookupEvent",
            "Filename_Suffix": "EventItem_DnsLookupEvent",
            "Timestamp_Fields": [
                "EventBufferTime_DnsLookupEvent>DnsLookupEvent"
            ],
            "Summary_Fields": [
                "ProcessPath",
                "Process",
                "DNSHostname",
                "Pid"
            ],
            "Extra_Fields": [
                "Username>User",
                "EventBufferType>SubAuditType",
                "Process||Pid>Extra1",
                "DNSHostname>Extra2",
                "Hostname",
                "AgentID"
            ]
        },
        {
            "Name": "EventItem_FileWriteEvent",
            "Filename_Suffix": "EventItem_FileWriteEvent",
            "Timestamp_Fields": [
                "EventBufferTime_FileWriteEvent>FileWriteEvent"
            ],
            "Summary_Fields": [
                "ProcessPath",
                "Process",
                "FullPath",
                "DevicePath",
                "Pid",
                "Closed",
                "Writes",
                "Size",
                "NumBytesSeenWritten",
                "LowestFileOffsetSeen",
                "TextAtLowestOffset"
            ],
            "Extra_Fields": [
                "Username>User",
                "Md5>MD5",
                "Size",
                "EventBufferType>SubAuditType",
                "Process||Pid>Extra1",
                "FullPath>Extra2",
                "Hostname",
                "AgentID"
            ]
        },
        {
            "Name": "EventItem_ImageLoadEvent",
            "Filename_Suffix": "EventItem_ImageLoadEvent",
            "Timestamp_Fields": [
                "EventBufferTime_ImageLoadEvent>ImageLoadEvent"
            ],
            "Summary_Fields": [
                "ProcessPath",
                "Process",
                "FullPath",
                "DevicePath",
                "Pid"
            ],
            "Extra_Fields": [
                "Username>User",
                "EventBufferType>SubAuditType",
                "Process||Pid>Extra1",
                "FullPath>Extra2",
                "Hostname",
                "AgentID"
            ]
        },
        {
            "Name": "EventItem_Ipv4NetworkEvent",
            "Filename_Suffix": "EventItem_Ipv4NetworkEvent",
            "Timestamp_Fields": [
                "EventBufferTime_Ipv4NetworkEvent>Ipv4NetworkEvent"
            ],
            "Summary_Fields": [
                "ProcessPath",
                "Process",
                "LocalIP",
                "LocalPort",
                "RemoteIP",
                "RemotePort",
                "Protocol",
                "Pid"
            ],
            "Extra_Fields": [
                "Username>User",
                "EventBufferType>SubAuditType",
                "Process||Pid>Extra1",
                "RemoteIP||RemotePort>Extra2",
                "Protocol>Extra3",
                "Hostname",
                "AgentID"
            ]
        },
        {
            "Name": "EventItem_ProcessEvent",
            "Filename_Suffix": "EventItem_ProcessEvent",
            "Timestamp_Fields": [
                "EventBufferTime_ProcessEvent>ProcessEvent"
            ],
            "Summary_Fields": [
                "ProcessPath",
                "Process",
                "ProcessCmdLine",
                "ParentProcessPath",
                "ParentProcess",
                "EventType",
                "Pid",
                "ParentPid",
                "StartTime"
            ],
            "Extra_Fields": [
                "Username>User",
                "Md5>MD5",
                "EventBufferType>SubAuditType",
                "Process||Pid>Extra1",
                "ParentProcess||ParentPid>Extra2",
                "EventType>Extra3",
                "Hostname",
                "AgentID"
            ]
        },
        {
            "Name": "EventItem_RegKeyEvent",
            "Filename_Suffix": "EventItem_RegKeyEvent",
            "Timestamp_Fields": [
                "EventBufferTime_RegKeyEvent>RegKeyEvent"
            ],
            "Summary_Fields": [
                "ProcessPath",
                "Process",
                "Path",
                "ValueName",
                "Text",
                "ValueType",
                "EventType",
                "Pid"
            ],
            "Extra_Fields": [
                "Username>User",
                "EventBufferType>SubAuditType",
                "Process||Pid>Extra1",
                "EventType>Extra2",
                "Hostname",
                "AgentID"
            ]
        },
        {
            "Name": "EventItem_UrlMonitorEvent",
            "Filename_Suffix": "EventItem_UrlMonitorEvent",
            "Timestamp_Fields": [
                "EventBufferTime_UrlMonitorEvent>UrlMonitorEvent"
            ],
            "Summary_Fields": [
                "ProcessPath",
                "Process",
                "DNSHostname",
                "RequestUrl",
                "RemoteIpAddress",
                "Text",
                "LocalPort",
                "RemotePort",
                "UrlMethod",
                "UserAgent",
                "Pid"
            ],
            "Extra_Fields": [
                "Username>User",
                "Process||Pid>Extra1",
                "RemoteIpAddress>Extra2",
                "EventBufferType>SubAuditType",
                "Hostname",
                "AgentID"
            ]
        },
        {
            "Name": "EventLogItem",
            "Filename_Suffix": "EventLogItem",
            "Timestamp_Fields": [
                "genTime",
                "writeTime"
            ],
            "Summary_Fields": [
                "EID",
                "index",
                "log",
                "source",
                "type",
                "message",
                "unformattedMessage.string"
            ],
            "Extra_Fields": [
                "user>User",
                "log>SubAuditType",
                "source>Extra1",
                "type>Extra2",
                "category>Extra3",
                "Hostname",
                "AgentID"
            ]
        },      
        {   
            "Name": "FileDownloadHistoryItem",
            "Filename_Suffix": "FileDownloadHistoryItem",
            "Timestamp_Fields": [
                "LastModifiedDate",
                "LastCheckedDate",
                "LastAccessedDate",
                "StartDate",
                "EndDate"
            ],
            "Summary_Fields": [
                "TargetDirectory",
                "FileName",
                "SourceURL",
                "DownloadType",
                "BrowserName",
                "Profile"
            ],
            "Extra_Fields": [
                "Hostname",
                "AgentID",
                "BrowserName>Extra1",
                "Username>User",
                "BytesDownloaded>Size"
            ]
        },
        {   
            "Name": "FileItem",
            "Filename_Suffix": "FileItem",
            "Timestamp_Fields": [
                "Created",
                "Modified",
                "Accessed",
                "Changed",
                "FilenameCreated",
                "FilenameModified",
                "FilenameAccessed",
                "FilenameChanged"
            ],
            "Summary_Fields": [
                "FullPath"
            ],
            "Extra_Fields": [
                "Md5sum>MD5",
                "SizeInBytes>Size",
                "Username>User",
                "FileAttributes>Extra1",
                "Group||GroupID>Extra2",
                "Permissions>Extra3",
                "PEInfo.DigitalSignature.SignatureExists>SignatureExists",
                "PEInfo.DigitalSignature.SignatureVerified>SignatureVerified",
                "Hostname",
                "AgentID"
            ]
        },
        {   
            "Name": "FormHistoryItem",
            "Filename_Suffix": "FormHistoryItem",
            "Timestamp_Fields": [
                "FirstUsedDate",
                "LastUsedDate"
            ],
            "Summary_Fields": [
                "FormType",
                "FormFieldName",
                "FormFieldValue"
            ],
            "Extra_Fields": [
                "Username>User",
                "FormType>SubAuditType",
                "BrowserName>Extra1",
                "Hostname",
                "AgentID"
            ]
        },
        {
            "Name": "LoginHistoryItem",
            "Filename_Suffix": "LoginHistoryItem",
            "Timestamp_Fields": [
                "StartTime",
                "EndTime"
            ],
            "Summary_Fields": [
                "Username",
                "IPv4Address",
                "Hostname",
                "Terminal"
            ],
            "Extra_Fields": [
                "Hostname",
                "AgentID",
                "RecordType||Path>SubAuditType",
                "PID>Extra1",
                "IsFailedLogin>Extra2",
                "IsRemoteLogin>Extra3",
                "Username>User"
            ]
        },
        {
            "Name": "ModuleItem",
            "Filename_Suffix": "ModuleItem",
            "Timestamp_Fields": [],
            "Summary_Fields": [
                "Filename",
                "ParmList.Parm.Name",
                "AliasList.Alias.Name",
                "Address",
                "SrcVersion",
                "ModulePath",
                "ModuleName"
            ],
            "Extra_Fields": [
                "ModuleSize||Size>Size",
                "Status>Extra1",
                "Md5sum>MD5",
                "Hostname",
                "AgentID"
            ]
        },
        {
            "Name": "PersistenceType",
            "Filename_Suffix": "PersistenceItem",
            "Timestamp_Fields": [
                "Created",
                "FileAccessed",
                "FileChanged",
                "FileChanged",
                "FileCreated",
                "FileItem.PEInfo.PETimeStamp",
                "FileModified",
                "LastRun",
                "RegModified"
                
            ],
            "Summary_Fields": [
                "FilePath",
                "LinkFilePath",
                "ServicePath",
                "serviceDLL",
                "RegPath",
                "RegText",
                "Command",
                "ServiceName",
                "arguments",
                "descriptiveName",
                "mode",
                "status",
                "startedAs",
                "ServiceItem.pathmd5sum",
                "ServiceItem.serviceDLLmd5sum"
            ],
            "Extra_Fields": [
                "PersistenceType>SubAuditType",
                "md5sum>MD5",
                "pathmd5sum>MD5",
                "serviceDLLmd5sum>MD5",
                "FileItem.Md5sum>MD5",
                "ServiceItem.pathmd5sum>MD5",
                "ServiceItem.serviceDLLmd5sum>MD5",
                "pathSignatureExists>SignatureExists",
                "pathSignatureVerified>SignatureVerified",
                "serviceDLLSignatureExists>SignatureExists",
                "serviceDLLSignatureVerified>SignatureVerified",
                "SignatureExists",
                "SignatureVerified",
                "FileItem.SizeInBytes>Size",
                "RegOwner>User",
                "FileOwner>User",
                "startedAs>User",
                "Hostname",
                "AgentID"
            ]
        },
        {
            "Name": "PortItem",
            "Filename_Suffix": "PortItem",
            "Timestamp_Fields": [
                "CreationTime"
            ],
            "Summary_Fields": [
                "path",
                "process",
                "localIP",
                "remoteIP",
                "localPort",
                "remotePort",
                "protocol"
            ],
            "Extra_Fields": [
                "Hostname",
                "AgentID",
                "pid>Extra1",
                "state>SubAuditType"
            ]
        },
        {
            "Name": "PrefetchItem",
            "Filename_Suffix": "PrefetchItem",
            "Timestamp_Fields": [
                "Created",
                "LastRun"
            ],
            "Summary_Fields": [
                "FullPath",
                "ApplicationFullPath"
            ],
            "Extra_Fields": [
                "SizeInBytes>Size",
                "Hostname",
                "AgentID"
            ]
        },
        {
            "Name": "ProcessItem",
            "Filename_Suffix": "ProcessItem",
            "Timestamp_Fields": [
                "startTime",
                "userTime",
                "endTime",
                "kernelTime"
            ],
            "Summary_Fields": [
                "arguments",
                "name",
                "path"
            ],
            "Extra_Fields": [
                "Hostname",
                "AgentID",
                "Username>User",
                "pid>Extra1",
                "parentpid>Extra2"
            ]
        },
        {
            "Name": "QuarantineEventItem",
            "Filename_Suffix": "QuarantineEventItem",
            "Timestamp_Fields": [
                "TimeStamp"
            ],
            "Summary_Fields": [
                "User",
                "AgentName",
                "DataURLString",
                "OriginURLString",
                "SenderName",
                "SenderAddress",
                "OriginTitle"
            ],
            "Extra_Fields": [
                "User",
                "Hostname",
                "AgentID"
            ]
        },
        {
            "Name": "RegistryItem",
            "Filename_Suffix": "RegistryItem",
            "Timestamp_Fields": [
                "Modified"
            ],
            "Summary_Fields": [
                "Path",
                "Text"
            ],
            "Extra_Fields": [
                "ReportedLengthInBytes>Size",
                "Username>User",
                "Type>Extra1",
                "Hostname",
                "AgentID"
            ]
        },
        {
            "Name": "RouteEntryItem",
            "Filename_Suffix": "RouteEntryItem",
            "Timestamp_Fields": [],
            "Summary_Fields": [
                "Interface",
                "Destination"
            ],
            "Extra_Fields": [
                "Hostname",
                "AgentID"
            ]
        },
        {
            "Name": "ServiceItem",
            "Filename_Suffix": "ServiceItem",
            "Timestamp_Fields": [],
            "Summary_Fields": [
                "path",
                "name",
                "arguments",
                "descriptiveName",
                "type",
                "serviceDLL"
            ],
            "Extra_Fields": [
                "pathmd5sum>MD5",
                "serviceDLLmd5sum>MD5",
                "Hostname",
                "AgentID",
                "startedAs>User",
                "mode>Extra1",
                "status>Extra2"
            ]
        },
        {
            "Name": "ShellHistoryItem",
            "Filename_Suffix": "ShellHistoryItem",
            "Timestamp_Fields": [
                "Timestamp"
            ],
            "Summary_Fields": [
                "Command"
            ],
            "Extra_Fields": [
                "Shell>Extra1",
                "FileOrder>Extra2",
                "UserName>User",
                "Hostname",
                "AgentID"
            ]
        },
        {
            "Name": "SystemInfoItem",
            "Filename_Suffix": "SystemInfoItem",
            "Timestamp_Fields": [
                "installDate",
                "date",
                "appCreated"
            ],
            "Summary_Fields": [
                "Hostname",
                "AgentID",
                "platform",
                "OS",
                "productName",
                "buildNumber",
                "OSbitness",
                "kernelVersion",
                "processor",
                "drives",
                "timezone",
                "uptime",
                "containmentState",
                "domain",
                "loggedOnUser",
                "primaryIpAddress",
                "primaryIpv4Address",
                "networkArray.networkInfo.ipArray.ipInfo.ipAddress",
                "MAC",
                "networkArray.networkInfo.MAC"
            ],
            "Extra_Fields": [
                "DataLength>Size",
                "Hostname",
                "AgentID",
                "user>User",
                "platform>SubAuditType",
                "appVersion>Extra1"
            ]
        },
        {
            "Name": "SystemRestoreItem",
            "Filename_Suffix": "SystemRestoreItem",
            "Timestamp_Fields": [
                "Created",
                "FileItem.Created"
            ],
            "Summary_Fields": [
                "ChangeLogEntryType",
                "OriginalFileName"
            ],
            "Extra_Fields": [
                "Hostname",
                "AgentID"
            ]
        },
        {
            "Name": "TaskItem",
            "Filename_Suffix": "TaskItem",
            "Timestamp_Fields": [
                "MostRecentRunTime",
                "NextRunTime",
                "CreationDate",
                "TriggerList.Trigger.TriggerBegin",
                "TriggerList.Trigger.TriggerEnd"
            ],
            "Summary_Fields": [
                "crontabCommand",
                "ActionList.Action.ExecProgramPath",
                "ActionList.Action.ExecArguments",
                "Name",
                "path",
                "TriggerList.Trigger.TriggerEnabled",
                "Creator",
                "Comment",
                "AccountLogonType",
                "Status",
                "ActionList.Action.ActionType",
                "ActionList.Action.COMClassId",
                "ActionList.Action.COMData",
                "ActionList.Action.ExecWorkingDirectory",
                "TriggerList.Trigger.TriggerFrequency",
                "AccountRunLevel",
                "Flag"
            ],
            "Extra_Fields": [
                "Hostname",
                "AgentID",
                "AccountName||userName>User",
                "crontabPath>SubAuditType",
                "Status||crontabMinute||crontabHour||crontabDayOfMonth||crontabMonth||crontabDayOfWeek>Extra1",
                "TriggerList.Trigger.TriggerEnabled||path>Extra2",
                "TriggerList.Trigger.TriggerFrequency||crontabJobIdentifier||crontabEvent||crontabPeriod||crontabDelay>Extra3",
                "md5sum>MD5"
            ]
        },
        {
            "Name": "UrlHistoryItem",
            "Filename_Suffix": "UrlHistoryItem",
            "Timestamp_Fields": [
                "LastVisitDate"
            ],
            "Summary_Fields": [
                "URL",
                "BrowserName",
                "VisitType",
                "VisitFrom",
                "Typed"
            ],
            "Extra_Fields": [
                "ReportedLengthInBytes>Size",
                "Hostname",
                "AgentID",
                "Username>User",
                "Profile>Extra1"
            ]
        },
        {
            "Name": "UserItem",
            "Filename_Suffix": "UserItem",
            "Timestamp_Fields": [
                "LastLogin"
            ],
            "Summary_Fields": [
                "fullname",
                "description",
                "SecurityType",
                "disabled",
                "lockedout",
                "passwordrequired",
                "userpasswordage"
            ],
            "Extra_Fields": [
                "Username>User",
                "SecurityType>Extra1",
                "Hostname",
                "AgentID"
            ]
        },
        {
            "Name": "VolumeItem",
            "Filename_Suffix": "VolumeItem",
            "Timestamp_Fields": [
                "CreationTime"
            ],
            "Summary_Fields": [
                "VolumeName",
                "Name",
                "DevicePath"
            ],
            "Extra_Fields": [
                "Hostname",
                "AgentID"
            ]
        }`

    template_end := `
    ]
}`
    return template_head + template_audits + template_end
}
