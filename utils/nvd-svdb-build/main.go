package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/0sm0s1z/nvd-svdb-build/dbmodel"
)

func main() {
	// Setup database connection (update the connection string as needed)
	dsn := "host=localhost user=postgres password=password dbname=sirius port=5432 sslmode=disable"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})

	if err != nil {
		panic("failed to connect to database")
	}

	// Drop tables (if needed)
	// ===========
	// db.Debug().Migrator().DropTable(
	// db.Migrator().DropTable(
	// 	&dbmodel.CVEData{},
	// 	&dbmodel.CVEItem{},
	// 	&dbmodel.CVEDataMeta{},
	// 	&dbmodel.ProblemType{},
	// 	&dbmodel.ProblemTypeData{},
	// 	&dbmodel.Reference{},
	// 	&dbmodel.Configurations{},
	// 	&dbmodel.Node{},
	// 	&dbmodel.CpeMatch{},
	// 	&dbmodel.Impact{},
	// 	&dbmodel.BaseMetricV2{},
	// )

	// Auto migrate to create tables based on the model from the database package
	// db.Debug().AutoMigrate(
	db.AutoMigrate(
		&dbmodel.CVEData{},
		&dbmodel.CVEItem{},
		&dbmodel.CVEDataMeta{},
		&dbmodel.ProblemType{},
		&dbmodel.ProblemTypeData{},
		&dbmodel.Reference{},
		&dbmodel.Configurations{},
		&dbmodel.Node{},
		&dbmodel.CpeMatch{},
		&dbmodel.Impact{},
		&dbmodel.BaseMetricV2{},
	)

	// Process and save CVEs
	if err := processAndSaveCVEs(db, "../../database/cve/"); err != nil {
		panic(err)
	}

	// Get CVE by ID
	// cve, err := GetCVE(db, "CVE-2017-0143")
	// if err != nil {
	// 	panic(err)
	// }

	// if len(cve.CVEItems) > 0 {
	// 	fmt.Println("CVEItem Descriptions:")
	// 	for _, desc := range cve.CVEItems[0].Descriptions {
	// 		fmt.Printf("Lang: %s, Value: %s\n", desc.Lang, desc.Value)
	// 	}

	// 	fmt.Println("CVEItem References:")
	// 	for _, ref := range cve.CVEItems[0].References {
	// 		fmt.Printf("URL: %s, Name: %s, RefSource: %s\n", ref.URL, ref.Name, ref.RefSource)
	// 	}
	// }

	fmt.Println("CVE data processing complete.")
}

func processAndSaveCVEs(db *gorm.DB, pathToCVEFiles string) error {
	var count, total int

	// First, count total files
	filepath.Walk(pathToCVEFiles, func(path string, info os.FileInfo, err error) error {
		if strings.HasSuffix(path, "nvd.json") {
			total++
		}
		return nil
	})

	return filepath.Walk(pathToCVEFiles, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(path, "nvd.json") {
			count++
			// Use \r to return to the beginning of the line
			fmt.Printf("\rProcessing file %d of %d", count, total)

			data, err := ioutil.ReadFile(path)
			if err != nil {
				fmt.Printf("\rError reading file %s: %v\n", path, err)
				return err
			}

			var jsonCVEData JSONCVEItem // Struct matching the JSON structure
			if err := json.Unmarshal(data, &jsonCVEData); err != nil {
				fmt.Printf("\rError unmarshalling JSON from file %s: %v\n", path, err)
				return err
			}

			dbCVEData := mapJSONToDBModel(jsonCVEData)
			if result := db.Create(&dbCVEData); result.Error != nil {
				fmt.Printf("\rError saving CVEData from file %s to database: %v\n", path, result.Error)
				return result.Error
			}
		}
		return nil
	})

	// Clear line after processing is done
	fmt.Printf("\r%s\r", strings.Repeat(" ", 50))
	fmt.Println("Processing complete.")

	return nil
}

// Structs to mirror the JSON structure of CVE data
type JSONCVEData struct {
	CVEDataType         string        `json:"CVE_data_type"`
	CVEDataFormat       string        `json:"CVE_data_format"`
	CVEDataVersion      string        `json:"CVE_data_version"`
	CVEDataNumberOfCVEs string        `json:"CVE_data_numberOfCVEs"`
	CVEDataTimestamp    string        `json:"CVE_data_timestamp"`
	CVEItems            []JSONCVEItem `json:"CVE_Items"`
}

type JSONCVEItem struct {
	CVE struct {
		DataType    string `json:"data_type"`
		DataFormat  string `json:"data_format"`
		DataVersion string `json:"data_version"`
		DataMeta    struct {
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

func mapJSONToDBModel(jsonItem JSONCVEItem) dbmodel.CVEData {
	var dbData dbmodel.CVEData

	var dbItem dbmodel.CVEItem

	// Map fields from jsonItem to dbItem
	dbItem.CVEDataType = jsonItem.CVE.DataType
	dbItem.CVEDataFormat = jsonItem.CVE.DataFormat
	dbItem.DataVersion = jsonItem.CVE.DataVersion

	// Map nested DataMeta
	dbItem.DataMeta.ID = jsonItem.CVE.DataMeta.ID
	dbItem.DataMeta.Assigner = jsonItem.CVE.DataMeta.Assigner

	// Map ProblemType (assuming a similar structure in dbmodel)
	// You'll need to adapt this part based on the exact structure of ProblemType in your dbmodel
	for _, ptData := range jsonItem.CVE.ProblemType.ProblemTypeData {
		var dbPTData dbmodel.ProblemTypeData
		for _, desc := range ptData.Description {
			dbDesc := dbmodel.Description{
				Lang:  desc.Lang,
				Value: desc.Value,
			}
			dbPTData.Descriptions = append(dbPTData.Descriptions, &dbDesc)
		}
		dbItem.ProblemType.ProblemTypeData = append(dbItem.ProblemType.ProblemTypeData, &dbPTData)
	}

	// Map References (similarly handle the slice of Reference)
	for _, ref := range jsonItem.CVE.References.ReferenceData {
		var dbRef dbmodel.Reference
		dbRef.URL = ref.URL
		dbRef.Name = ref.Name
		dbRef.RefSource = ref.RefSource

		dbItem.References = append(dbItem.References, &dbRef)
	}

	// Map Description
	for _, desc := range jsonItem.CVE.Description.DescriptionData {
		var dbDesc dbmodel.Description
		dbDesc.Value = desc.Value
		dbDesc.Lang = desc.Lang
		// Map Tags (assuming Tag struct in dbmodel)
		dbItem.Descriptions = append(dbItem.Descriptions, &dbDesc)
	}

	// Map Configurations, Impact, etc.
	// Continue mapping for other nested fields...

	dbData.CVEItems = append(dbData.CVEItems, &dbItem)

	return dbData
}

// GetCVE retrieves a CVEData by the CVE ID (which is in CVEDataMeta)
func GetCVE(db *gorm.DB, cveID string) (dbmodel.CVEData, error) {
	var cveData dbmodel.CVEData

	// First, find the CVEDataMeta by the CVE ID
	var cveMeta dbmodel.CVEDataMeta
	resultMeta := db.Where("ID = ?", cveID).First(&cveMeta)
	if resultMeta.Error != nil {
		return cveData, resultMeta.Error
	}

	// Find the CVEItem associated with the CVEDataMeta ID and preload related entities
	var cveItem dbmodel.CVEItem
	resultItem := db.Joins("JOIN cve_data_meta ON cve_data_meta.cve_item_id = cve_items.id").
		Where("cve_data_meta.id = ?", cveID).
		First(&cveItem)
	if resultItem.Error != nil {
		return cveData, resultItem.Error
	}

	// Find the CVEData that contains this CVEItem and preload Descriptions and References
	resultData := db.Preload("CVEItems").
		Preload("CVEItems.DataMeta").
		Preload("CVEItems.ProblemType").
		Preload("CVEItems.ProblemType.ProblemTypeData").
		Preload("CVEItems.ProblemType.ProblemTypeData.Descriptions").
		Preload("CVEItems.References").
		Preload("CVEItems.Descriptions").
		Preload("CVEItems.Configurations").
		Preload("CVEItems.Configurations.Nodes").
		Preload("CVEItems.Configurations.Nodes.CpeMatch").
		Preload("CVEItems.Impact").
		Where("id = ?", cveItem.CVEDataID).First(&cveData)

	return cveData, resultData.Error
}
