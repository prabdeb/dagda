package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
)

type (
	// ScanReport type of Dagda scan JSON
	ScanReport []struct {
		ID             string `json:"id"`
		ImageName      string `json:"image_name"`
		StaticAnalysis struct {
			MalwareBinaries []interface{} `json:"malware_binaries"`
			OsPackages      struct {
				OkOsPackages      int `json:"ok_os_packages"`
				OsPackagesDetails []struct {
					IsFalsePositive bool          `json:"is_false_positive"`
					IsVulnerable    bool          `json:"is_vulnerable"`
					Product         string        `json:"product"`
					Version         string        `json:"version"`
					Vulnerabilities []interface{} `json:"vulnerabilities"`
				} `json:"os_packages_details"`
				TotalOsPackages int `json:"total_os_packages"`
				VulnOsPackages  int `json:"vuln_os_packages"`
			} `json:"os_packages"`
			ProgLangDependencies struct {
				DependenciesDetails struct {
					Java []struct {
						IsFalsePositive bool          `json:"is_false_positive"`
						IsVulnerable    bool          `json:"is_vulnerable"`
						Product         string        `json:"product"`
						ProductFilePath string        `json:"product_file_path"`
						Version         string        `json:"version"`
						Vulnerabilities []interface{} `json:"vulnerabilities"`
					} `json:"java"`
					Js []struct {
						IsFalsePositive bool          `json:"is_false_positive"`
						IsVulnerable    bool          `json:"is_vulnerable"`
						Product         string        `json:"product"`
						ProductFilePath string        `json:"product_file_path"`
						Version         string        `json:"version"`
						Vulnerabilities []interface{} `json:"vulnerabilities"`
					} `json:"js"`
					Nodejs []interface{} `json:"nodejs"`
					Php    []interface{} `json:"php"`
					Python []interface{} `json:"python"`
					Ruby   []interface{} `json:"ruby"`
				} `json:"dependencies_details"`
				VulnDependencies int `json:"vuln_dependencies"`
			} `json:"prog_lang_dependencies"`
		} `json:"static_analysis"`
		Status    string `json:"status"`
		Timestamp string `json:"timestamp"`
	}
	// VulnerabilityTypes is the type
	VulnerabilityTypes struct {
		// For CVE
		Cveid                     string   `json:"cveid"`
		CvssAccessComplexity      string   `json:"cvss_access_complexity"`
		CvssAccessVector          string   `json:"cvss_access_vector"`
		CvssAuthentication        string   `json:"cvss_authentication"`
		CvssAvailabilityImpact    string   `json:"cvss_availability_impact"`
		CvssBase                  float64  `json:"cvss_base"`
		CvssConfidentialityImpact string   `json:"cvss_confidentiality_impact"`
		CvssExploit               float64  `json:"cvss_exploit"`
		CvssImpact                float64  `json:"cvss_impact"`
		CvssIntegrityImpact       string   `json:"cvss_integrity_impact"`
		CvssVector                []string `json:"cvss_vector"`
		Cweid                     string   `json:"cweid"`
		ModDate                   string   `json:"mod_date"`
		PubDate                   string   `json:"pub_date"`
		Summary                   string   `json:"summary"`
		// For BID
		BugtraqID int      `json:"bugtraq_id"`
		Class     string   `json:"class"`
		Cve       []string `json:"cve"`
		Local     string   `json:"local"`
		Remote    string   `json:"remote"`
		Title     string   `json:"title"`
		// For Exploit DB
		Description string `json:"description"`
		ExploitDbID int    `json:"exploit_db_id"`
		Platform    string `json:"platform"`
		Port        int    `json:"port"`
		Type        string `json:"type"`
	}

	// Report type
	Report struct {
		Package      string
		Version      string
		CVE          string
		BID          string
		Severity     string
		Score        string
		Type         string
		SortPriority int
	}
)

func main() {
	finalReport := []Report{}
	scanReport := ScanReport{}
	jsonFile, err := os.Open("result.json")
	if err != nil {
		log.Fatal("Can not open report file")
	}
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	err = json.Unmarshal([]byte(byteValue), &scanReport)
	parseScanReport := scanReport[0]
	for _, a := range parseScanReport.StaticAnalysis.OsPackages.OsPackagesDetails {
		for _, b := range a.Vulnerabilities {
			vulnerabilities := b.(map[string]interface{})
			for d, e := range vulnerabilities {
				f, _ := json.Marshal(e)
				g := VulnerabilityTypes{}
				json.Unmarshal([]byte(f), &g)
				report := Report{}
				report.Type = "OS Package"
				report.Package = a.Product
				report.Version = a.Version
				if strings.HasPrefix(d, "CVE") {
					report.CVE = d
					report.BID = "N/A"
				} else {
					report.BID = d
					report.CVE = "N/A"
				}
				if len(g.Cve) > 0 {
					report.CVE = g.Cve[0]
				}
				if g.CvssAccessComplexity != "" {
					report.Severity = g.CvssAccessComplexity
					report.Score = strconv.FormatFloat(g.CvssBase, 'f', 1, 64)
					if report.Severity == "High" {
						report.SortPriority = 3
					}
					if report.Severity == "Medium" {
						report.SortPriority = 2
					}
					if report.Severity == "Low" {
						report.SortPriority = 1
					}
				} else {
					report.Severity = "Unknown"
					report.SortPriority = 0
					report.Score = "N/A"
				}
				finalReport = append(finalReport, report)
			}
		}
	}
	//fmt.Println("Total OS Packages: ", parseScanReport.StaticAnalysis.OsPackages.TotalOsPackages)
	//fmt.Println("Vuln OS Packages: ", parseScanReport.StaticAnalysis.OsPackages.VulnOsPackages)
	for _, a := range parseScanReport.StaticAnalysis.ProgLangDependencies.DependenciesDetails.Java {
		for _, b := range a.Vulnerabilities {
			vulnerabilities := b.(map[string]interface{})
			for d, e := range vulnerabilities {
				f, _ := json.Marshal(e)
				g := VulnerabilityTypes{}
				json.Unmarshal([]byte(f), &g)
				report := Report{}
				report.Type = "SW Package"
				report.Package = a.Product
				report.Version = a.Version
				if strings.HasPrefix(d, "CVE") {
					report.CVE = d
					report.BID = "N/A"
				} else {
					report.BID = d
					report.CVE = "N/A"
				}
				if len(g.Cve) > 0 {
					report.CVE = g.Cve[0]
				}
				if g.CvssAccessComplexity != "" {
					report.Severity = g.CvssAccessComplexity
					report.Score = strconv.FormatFloat(g.CvssBase, 'f', 1, 64)
					if report.Severity == "High" {
						report.SortPriority = 3
					}
					if report.Severity == "Medium" {
						report.SortPriority = 2
					}
					if report.Severity == "Low" {
						report.SortPriority = 1
					}
				} else {
					report.Severity = "Unknown"
					report.SortPriority = 0
					report.Score = "N/A"
				}
				finalReport = append(finalReport, report)
			}
		}
	}
	//fmt.Println("Vuln Dependencies: ", parseScanReport.StaticAnalysis.ProgLangDependencies.VulnDependencies)

	riskData := map[string]int{}
	for _, v := range finalReport {
		if v.Severity != "" {
			riskData[v.Severity]++
		} else {
			riskData["Unknown"]++
		}
	}

	sort.Slice(finalReport, func(i, j int) bool {
		return finalReport[i].SortPriority > finalReport[j].SortPriority
	})

	fmt.Println(htmlStart)
	fmt.Println(htmlHeader)
	fmt.Println(bodyStart)
	fmt.Println(getTabRisk(riskData["High"], riskData["Medium"], riskData["Low"], riskData["Unknown"]))
	fmt.Println(getVulnerabilities(finalReport))
	fmt.Println(bodyEnd)
	fmt.Println(htmlEnd)
}
