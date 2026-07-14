package azure

import (
	"math"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/monitor/azquery"
)

func parseHealth(tables []*azquery.Table) RawHealth {
	var out RawHealth
	for _, table := range tables {
		for _, row := range table.Rows {
			values := rowMap(table, row)
			kind := ptrString(values["Kind"])
			last := parseTime(values["Last"])
			if kind == "health" {
				out.LastHealthEvent = last
				out.ConnectorFailures = ptrInt64(values["ConnectorFailures"])
				out.AnalyticsRuleFailures = ptrInt64(values["AnalyticsFailures"])
				out.AutomationFailures = ptrInt64(values["AutomationFailures"])
			} else if kind == "audit" {
				out.LastAuditEvent = last
			}
		}
	}
	return out
}

func parseTelemetry(tables []*azquery.Table, now time.Time) []TelemetrySource {
	var out []TelemetrySource
	for _, table := range tables {
		for _, row := range table.Rows {
			values := rowMap(table, row)
			recent := ptrInt64(values["Recent"])
			baseline := float64(ptrInt64(values["Baseline"]))
			source := TelemetrySource{Table: ptrString(values["TableName"]), LastEvent: parseTime(values["LastEvent"]), RecentEvents: recent, BaselineMedian: baseline, MaximumAgeMinutes: 60}
			if source.LastEvent != nil {
				source.Healthy = now.Sub(*source.LastEvent) <= time.Hour
			}
			if baseline > 0 {
				delta := (float64(recent) - baseline) / baseline * 100
				if delta < 0 {
					source.DropPercent = math.Abs(delta)
				} else {
					source.IncreasePercent = delta
				}
			}
			out = append(out, source)
		}
	}
	return out
}

func rowMap(table *azquery.Table, row azquery.Row) map[string]any {
	out := make(map[string]any, len(table.Columns))
	for i, column := range table.Columns {
		if i < len(row) && column.Name != nil {
			out[*column.Name] = row[i]
		}
	}
	return out
}
func parseTime(value any) *time.Time {
	switch v := value.(type) {
	case time.Time:
		t := v.UTC()
		return &t
	case string:
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			t = t.UTC()
			return &t
		}
	}
	return nil
}
