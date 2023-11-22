package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

// Structs to mirror the JSON structure of CVE data
type CVEData struct {
	CVEDataType         string    `json:"CVE_data_type"`
	CVEDataFormat       string    `json:"CVE_data_format"`
	CVEDataVersion      string    `json:"CVE_data_version"`
	CVEDataNumberOfCVEs string    `json:"CVE_data_numberOfCVEs"`
	CVEDataTimestamp    string    `json:"CVE_data_timestamp"`
	CVEItems            []CVEItem `json:"CVE_Items"`
}

type CVEItem struct {
	CVE struct {
		DataType     string `json:"data_type"`
		DataFormat   string `json:"data_format"`
		DataVersion  string `json:"data_version"`
		DataMeta     struct {
			ID       string `json:"ID"`
			Assigner string `json:"ASSIGNER"`
		} `json:"CVE_data_meta"`
		ProblemType struct {
			ProblemTypeData []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			} `json:"problemtype_data"`
		} `json:"problemtype"`
		References struct {
			ReferenceData []struct {
				URL       string   `json:"url"`
				Name      string   `json:"name"`
				RefSource string   `json:"refsource"`
				Tags      []string `json:"tags"`
			} `json:"reference_data"`
		} `json:"references"`
		Description struct {
			DescriptionData []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"description_data"`
		} `json:"description"`
	} `json:"cve"`
	Configurations struct {
		Nodes []struct {
			Operator string `json:"operator"`
			CpeMatch []struct {
				Vulnerable bool   `json:"vulnerable"`
				Cpe23Uri   string `json:"cpe23Uri"`
			} `json:"cpe_match"`
		} `json:"nodes"`
	} `json:"configurations"`
	Impact struct {
		BaseMetricV2 struct {
			CvssV2 struct {
				VectorString          string  `json:"vectorString"`
				AccessVector          string  `json:"accessVector"`
				AccessComplexity      string  `json:"accessComplexity"`
				Authentication        string  `json:"authentication"`
				ConfidentialityImpact string  `json:"confidentialityImpact"`
				IntegrityImpact       string  `json:"integrityImpact"`
				AvailabilityImpact    string  `json:"availabilityImpact"`
				BaseScore             float64 `json:"baseScore"`
			} `json:"cvssV2"`
			Severity                string  `json:"severity"`
			ExploitabilityScore     float64 `json:"exploitabilityScore"`
			ImpactScore             float64 `json:"impactScore"`
			ObtainAllPrivilege      bool    `json:"obtainAllPrivilege"`
			ObtainUserPrivilege     bool    `json:"obtainUserPrivilege"`
			ObtainOtherPrivilege    bool    `json:"obtainOtherPrivilege"`
			UserInteractionRequired bool    `json:"userInteractionRequired"`
		} `json:"baseMetricV2"`
	} `json:"impact"`
	PublishedDate    string `json:"publishedDate"`
	LastModifiedDate string `json:"lastModifiedDate"`
}

func main() {
	// Assuming the file name is passed as a command line argument
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run script.go <filename.json>")
		return
	}
	fileName := os.Args[1]

	// Read the JSON file
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		panic(err)
	}

	// Unmarshal JSON data into CVEData struct
	var cveData CVEData
	if err := json.Unmarshal(data, &cveData); err != nil {
		panic(err)
	}

	// Process each CVE item
	for _, item := range cveData.CVEItems {
		cveID := item.CVE.DataMeta.ID
		year := strings.Split(cveID, "-")[1] // Extract year from CVE ID

		// Create year directory if it doesn't exist
		yearDir := filepath.Join("database/cve", year)
		if _, err := os.Stat(yearDir); os.IsNotExist(err) {
			if err := os.MkdirAll(yearDir, os.ModePerm); err != nil {
				panic(err)
			}
		}

		// Create CVE-specific directory
		cveDir := filepath.Join(yearDir, cveID)
		if err := os.MkdirAll(cveDir, os.ModePerm); err != nil {
			panic(err)
		}

		// Marshal the complete CVE item back to JSON
		cveJSON, err := json.MarshalIndent(item, "", "  ")
		if err != nil {
			panic(err)
		}

		// Write to nvd.json in the CVE-specific directory
		if err := ioutil.WriteFile(filepath.Join(cveDir, "nvd.json"), cveJSON, os.ModePerm); err != nil {
			panic(err)
		}

		fmt.Printf("Processed %s\n", cveID)
	}

	fmt.Println("All CVEs processed.")
}
