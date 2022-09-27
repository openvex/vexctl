package csaf

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type CSAF struct {
	Document        DocumentMetadata `json:"document"`
	ProductTree     ProductBranch    `json:"product_tree"`
	Vulnerabilities []Vulnerability  `json:"vulnerabilities"`
}

type DocumentMetadata struct {
	Title    string `json:"title"`
	Tracking struct {
		CurrentReleaseDate time.Time `json:"current_release_date"`
	} `json:"tracking"`
}

type Vulnerability struct {
	CVE           string              `json:"cve"`
	ProductStatus map[string][]string `json:"product_status"`
	Threats       []ThreatData        `json:"threats"`
}

type ThreatData struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	ProductIDs []string `json:"product_ids"`
}

type ProductBranch struct {
	Category string          `json:"category"`
	Name     string          `json:"name"`
	Branches []ProductBranch `json:"branches"`
	Product  Product         `json:"product,omitempty"`
}

type Product struct {
	Name                 string            `json:"name"`
	ID                   string            `json:"product_id"`
	IdentificationHelper map[string]string `json:"product_identification_helper"`
}

func Open(path string) (*CSAF, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("opening CSAF document: %w", err)
	}

	csafDoc := &CSAF{}
	if err := json.Unmarshal(data, csafDoc); err != nil {
		return nil, fmt.Errorf("unmarshalling CSAF document: %w", err)
	}
	return csafDoc, nil
}

func (csafDoc *CSAF) FirstProductName() string {
	return csafDoc.ProductTree.FindFirstProduct()
}

// FindFirstProduct recursively searches for the first product in the tree
func (branch *ProductBranch) FindFirstProduct() string {
	if branch.Product.ID != "" {
		return branch.Product.ID
	}

	// No noested branches
	if branch.Branches == nil {
		return ""
	}

	for _, b := range branch.Branches {
		if p := b.FindFirstProduct(); p != "" {
			return p
		}
	}

	return ""
}

// FindFirstProduct recursively searches for the first product in the tree
func (branch *ProductBranch) FindProductIdentifier(helperType, helperValue string) *Product {
	if len(branch.Product.IdentificationHelper) != 0 {
		for k := range branch.Product.IdentificationHelper {
			if k != helperType {
				continue
			}
			if branch.Product.IdentificationHelper[k] == helperValue {
				return &branch.Product
			}
		}
	}

	// No noested branches
	if branch.Branches == nil {
		return nil
	}

	for _, b := range branch.Branches {
		if p := b.FindProductIdentifier(helperType, helperValue); p != nil {
			return p
		}
	}

	return nil
}
