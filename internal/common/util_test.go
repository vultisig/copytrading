package common

import (
	"testing"
)

func TestGetSortingCondition(t *testing.T) {
	tests := []struct {
		sort                   string
		expectedOrderBy        string
		expectedOrderDirection string
	}{
		{"created_at", "created_at", "ASC"},
		{"-created_at", "created_at", "DESC"},
		{"non_exist", "created_at", "ASC"},
		{"-non_exist", "created_at", "DESC"},
		{"title", "title", "ASC"},
		{"-title", "title", "DESC"},
		{"updated_at", "updated_at", "ASC"},
		{"-updated_at", "updated_at", "DESC"},
	}

	for _, tt := range tests {
		orderBy, orderDirection := GetSortingCondition(tt.sort)

		if orderBy != tt.expectedOrderBy {
			t.Errorf("sort: %s -> orderBy: %s, expected: %s", tt.sort, orderBy, tt.expectedOrderBy)
		}

		if orderDirection != tt.expectedOrderDirection {
			t.Errorf("sort: %s -> orderDirection: %s, expected: %s", tt.sort, orderDirection, tt.expectedOrderDirection)
		}
	}
}
