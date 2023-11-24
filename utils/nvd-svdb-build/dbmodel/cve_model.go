package dbmodel

import "gorm.io/gorm"

type CVEData struct {
	gorm.Model
	CVEDataType         string
	CVEDataFormat       string
	CVEDataVersion      string
	CVEDataNumberOfCVEs string
	CVEDataTimestamp    string
	CVEItems            []*CVEItem `gorm:"foreignKey:CVEDataID"`
}

type CVEItem struct {
	gorm.Model
	CVEDataType      string
	CVEDataFormat    string
	DataVersion      string
	DataMeta         CVEDataMeta
	ProblemType      ProblemType
	References       []*Reference   `gorm:"foreignKey:CVEItemID"`
	DescriptionID    uint           // Foreign key to Description's ID
	Descriptions     []*Description `gorm:"foreignKey:CVEItemID"`
	Configurations   Configurations
	Impact           Impact
	PublishedDate    string
	LastModifiedDate string
	CVEDataID        uint
}

type CVEDataMeta struct {
	gorm.Model
	ID        string `gorm:"uniqueIndex"`
	Assigner  string
	CVEItemID uint // Foreign key to link back to CVEItem
}

type ProblemType struct {
	gorm.Model
	ProblemTypeData []*ProblemTypeData `gorm:"foreignKey:ProblemTypeID"`
	CVEItemID       uint
}

type ProblemTypeData struct {
	gorm.Model
	ProblemTypeID uint
	Descriptions  []*Description `gorm:"foreignKey:ProblemTypeDataID"`
}

type Description struct {
	gorm.Model
	Lang              string
	Value             string
	ProblemTypeDataID uint
	CVEItemID         uint
}

type Reference struct {
	gorm.Model
	URL       string
	Name      string
	RefSource string
	CVEItemID uint
}


type Configurations struct {
	gorm.Model
	Nodes     []*Node `gorm:"foreignKey:ConfigurationID"`
	CVEItemID uint
}

type Node struct {
	gorm.Model
	Operator        string
	CpeMatch        []*CpeMatch `gorm:"foreignKey:NodeID"`
	ConfigurationID uint
}

type BaseMetricV2 struct {
	CvssV2                  CvssV2 `gorm:"embedded"`
	Severity                string
	ExploitabilityScore     float64
	ImpactScore             float64
	ObtainAllPrivilege      bool
	ObtainUserPrivilege     bool
	ObtainOtherPrivilege    bool
	UserInteractionRequired bool
	ImpactID                uint
}

// Inline CvssV2 struct
type CvssV2 struct {
	VectorString          string
	AccessVector          string
	AccessComplexity      string
	Authentication        string
	ConfidentialityImpact string
	IntegrityImpact       string
	AvailabilityImpact    string
	BaseScore             float64
}

type CpeMatch struct {
	gorm.Model
	Vulnerable bool
	Cpe23Uri   string
	NodeID     uint
}

type Impact struct {
	gorm.Model
	BaseMetricV2 BaseMetricV2 `gorm:"embedded"`
	CVEItemID    uint
}
