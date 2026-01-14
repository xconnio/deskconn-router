package main

import (
	"fmt"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Desktops struct{}

func (Desktops) TableName() string {
	return "desktops"
}

func openReadOnlyDB(path string) (*gorm.DB, error) {
	dsn := fmt.Sprintf("file:%s?mode=ro&_busy_timeout=5000", path)
	return gorm.Open(sqlite.Open(dsn), &gorm.Config{})
}

func getRealms(db *gorm.DB) ([]string, error) {
	var realms []string
	err := db.Model(&Desktops{}).Pluck("realm", &realms).Error
	return realms, err
}
