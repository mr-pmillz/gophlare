package api

import (
	"net/http"
	"strings"

	"github.com/mr-pmillz/gophlare/flareapi"
	"github.com/spf13/cobra"
)

const (
	identifierPath = "/firework/v4/identifiers/{identifier_id}"
	reportPath     = "/firework/v2/reporting/reports/{report_id}"
	policyPath     = "/firework/v4/matching-policies/{policy_uuid}"
	assignmentPath = "/firework/v4/matching-policies/{policy_uuid}/assignments"
)

func ResourceCommands() []*cobra.Command {
	definitions := []struct {
		command string
		method  string
		path    string
	}{
		{"identifiers list", http.MethodGet, "/firework/v4/identifiers/"},
		{"identifiers create", http.MethodPost, "/firework/v4/identifiers/"},
		{"identifiers get", http.MethodGet, identifierPath},
		{"identifiers update", http.MethodPut, identifierPath},
		{"identifiers delete", http.MethodDelete, identifierPath},
		{"identifiers toggle", http.MethodPost, "/firework/v2/assets/{asset_id}/toggle"},
		{"identifier-groups list", http.MethodGet, "/firework/v2/assets/groups/"},
		{"identifier-groups create", http.MethodPost, "/firework/v2/assets/groups/"},
		{"identifier-groups get", http.MethodGet, "/firework/v2/assets/groups/{assets_group_id}"},
		{"identifier-groups delete", http.MethodDelete, "/firework/v2/assets/groups/{assets_group_id}"},
		{"alerts list", http.MethodGet, "/firework/v2/assets/{asset_id}/alerts"},
		{"alerts create", http.MethodPost, "/firework/v2/assets/{asset_id}/alerts"},
		{"alerts update", http.MethodPut, "/firework/v2/assets/{asset_id}/alerts/{alert_id}"},
		{"alerts delete", http.MethodDelete, "/firework/v2/assets/{asset_id}/alerts/{alert_id}"},
		{"group-alerts list", http.MethodGet, "/firework/v2/assets/groups/{assets_group_id}/alerts"},
		{"group-alerts create", http.MethodPost, "/firework/v2/assets/groups/{assets_group_id}/alerts"},
		{"group-alerts update", http.MethodPut, "/firework/v2/assets/groups/{assets_group_id}/alerts/{alert_id}"},
		{"group-alerts delete", http.MethodDelete, "/firework/v2/assets/groups/{assets_group_id}/alerts/{alert_id}"},
		{"events get", http.MethodGet, "/firework/v4/events/"},
		{"events search", http.MethodPost, "/firework/v4/events/global/_search"},
		{"events list", http.MethodPost, "/firework/v4/events/tenant/_search"},
		{"events identifier", http.MethodPost, "/firework/v4/events/identifiers/{identifier_id}/_search"},
		{"events group", http.MethodPost, "/firework/v4/events/identifier_groups/{identifier_group_id}/_search"},
		{"events actions", http.MethodPost, "/firework/v4/events/actions"},
		{"events metadata", http.MethodPatch, "/firework/v4/events/tenant/metadata"},
		{"events expand", http.MethodGet, "/firework/v4/events/_expand"},
		{"events explain", http.MethodGet, "/firework/v4/events/identifiers/{identifier_id}/_explain"},
		{"events assistance", http.MethodGet, "/firework/v2/activities/{index}/{source}/{id}/ai_assistance"},
		{"credentials search", http.MethodPost, "/firework/v4/credentials/global/_search"},
		{"credentials actions", http.MethodPost, "/firework/v4/credentials/actions"},
		{"credentials list", http.MethodGet, "/firework/v2/me/feed/credentials"},
		{"credentials identifier", http.MethodGet, "/firework/v3/identifiers/{identifier_id}/feed/credentials"},
		{"profile get", http.MethodGet, "/firework/v2/me/profile"},
		{"profile update", http.MethodPut, "/firework/v2/me/profile"},
		{"profile tenants", http.MethodGet, "/firework/v2/me/tenants"},
		{"members list", http.MethodGet, "/firework/v2/organizations/{organization_id}/members"},
		{"members create", http.MethodPost, "/firework/v2/organizations/{organization_id}/members"},
		{"members get", http.MethodGet, "/firework/v2/organizations/{organization_id}/members/{user_id}"},
		{"members update", http.MethodPut, "/firework/v2/organizations/{organization_id}/members/{user_id}"},
		{"members enable", http.MethodPost, "/firework/v2/organizations/{organization_id}/members/{user_id}/enable"},
		{"members disable", http.MethodPost, "/firework/v2/organizations/{organization_id}/members/{user_id}/disable"},
		{"members permissions", http.MethodPost, "/firework/v2/organizations/{organization_id}/members/{user_id}/permissions"},
		{"members tenants", http.MethodGet, "/firework/v2/organizations/{organization_id}/members/{user_id}/tenants"},
		{"tenants list", http.MethodGet, "/firework/v2/organizations/{organization_id}/tenants"},
		{"tenants create", http.MethodPost, "/firework/v2/organizations/{organization_id}/tenants"},
		{"tenants get", http.MethodGet, "/firework/v2/tenants/{tenant_id}"},
		{"tenants update", http.MethodPut, "/firework/v2/tenants/{tenant_id}"},
		{"tenants archive", http.MethodPost, "/firework/v2/tenants/{tenant_id}/archive"},
		{"tenants members", http.MethodGet, "/firework/v2/tenants/{tenant_id}/users"},
		{"tenants add-member", http.MethodPost, "/firework/v2/tenants/{tenant_id}/users"},
		{"tenants remove-member", http.MethodDelete, "/firework/v2/tenants/{tenant_id}/users/{user_id}"},
		{"reports list", http.MethodGet, "/firework/v2/reporting/reports"},
		{"reports create", http.MethodPost, "/firework/v2/reporting/reports"},
		{"reports get", http.MethodGet, reportPath},
		{"reports update", http.MethodPatch, reportPath},
		{"reports delete", http.MethodDelete, reportPath},
		{"reports archive", http.MethodPost, "/firework/v2/reporting/reports/{report_id}/archive"},
		{"reports download", http.MethodGet, "/firework/v2/reporting/reports/{report_id}/download"},
		{"entities list", http.MethodPost, "/firework/v4/entities/global/_search"},
		{"entities get", http.MethodGet, "/firework/v4/entities/{id}"},
		{"entities relations", http.MethodPost, "/firework/v4/entities/{id}/relations"},
		{"matching-policies list", http.MethodGet, "/firework/v4/matching-policies"},
		{"matching-policies create", http.MethodPost, "/firework/v4/matching-policies"},
		{"matching-policies get", http.MethodGet, policyPath},
		{"matching-policies update", http.MethodPut, policyPath},
		{"matching-policies delete", http.MethodDelete, policyPath},
		{"matching-policies identifier", http.MethodGet, "/firework/v4/matching-policies/by_identifier_id/{identifier_id}"},
		{"policy-assignments list", http.MethodGet, assignmentPath},
		{"policy-assignments assign", http.MethodPost, assignmentPath},
		{"policy-assignments unassign", http.MethodDelete, assignmentPath},
		{"recommendations list", http.MethodGet, "/firework/v4/identifier-recommendations/"},
		{"recommendations actions", http.MethodPost, "/firework/v4/identifier-recommendations/actions"},
		{"intel create", http.MethodPost, "/firework/v4/threat_flow/intel/requests"},
		{"intel get", http.MethodGet, "/firework/v4/threat_flow/intel/requests/{id}"},
		{"intel report", http.MethodGet, "/firework/v4/threat_flow/reports/{report_id}"},
		{"intel create-report-request", http.MethodPost, "/firework/v4/threat_flow/reports/requests"},
		{"intel report-request", http.MethodGet, "/firework/v4/threat_flow/reports/requests/{request_info_id}"},
		{"sandbox upload-url", http.MethodPost, "/firework/v4/sandbox/uploads"},
		{"audit-logs search", http.MethodPost, "/firework/v4/audit-logs/_search"},
	}
	var commands []*cobra.Command
	parents := make(map[string]*cobra.Command)
	settings := make(map[string]*options)
	for _, definition := range definitions {
		parts := strings.SplitN(definition.command, " ", 2)
		parent, exists := parents[parts[0]]
		if !exists {
			parent = &cobra.Command{Use: parts[0], Short: "Manage Flare " + strings.ReplaceAll(parts[0], "-", " "), SilenceUsage: true}
			parents[parts[0]] = parent
			settings[parts[0]] = addFlags(parent)
			commands = append(commands, parent)
		}
		for _, operation := range flareapi.Operations() {
			if operation.Method == definition.method && operation.Path == definition.path {
				child := operationCommand(operation, settings[parts[0]])
				child.Use = parts[1]
				parent.AddCommand(child)
				break
			}
		}
	}
	return commands
}
