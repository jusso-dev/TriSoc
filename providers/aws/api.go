package aws

import (
	"context"
	"fmt"
	"sort"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securitylake"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type API interface {
	Discover(context.Context, Target) (Snapshot, error)
}
type SDKAPI struct{ config awssdk.Config }

func NewDefaultAPI(ctx context.Context, target Target) (API, error) {
	options := []func(*awsconfig.LoadOptions) error{}
	if target.Profile != "" {
		options = append(options, awsconfig.WithSharedConfigProfile(target.Profile))
	}
	if target.HomeRegion != "" {
		options = append(options, awsconfig.WithRegion(target.HomeRegion))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("load AWS SDK configuration: %w", err)
	}
	if target.RoleARN != "" {
		client := sts.NewFromConfig(cfg)
		provider := stscreds.NewAssumeRoleProvider(client, target.RoleARN, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = "trisoc-attestor"
			if target.ExternalID != "" {
				o.ExternalID = awssdk.String(target.ExternalID)
			}
		})
		cfg.Credentials = awssdk.NewCredentialsCache(provider)
	}
	return &SDKAPI{config: cfg}, nil
}

func (a *SDKAPI) Discover(ctx context.Context, target Target) (Snapshot, error) {
	if err := validateTarget(target); err != nil {
		return Snapshot{}, err
	}
	identity, err := sts.NewFromConfig(a.config).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return Snapshot{}, wrap("sts.GetCallerIdentity", err)
	}
	out := Snapshot{Provider: "aws", CallerAccountID: awssdk.ToString(identity.Account), CollectorIdentity: awssdk.ToString(identity.Arn), HomeRegion: target.HomeRegion, GovernedRegions: append([]string(nil), target.GovernedRegions...), Architecture: target.Architecture, DelegatedAdministratorsRequired: target.RequireDelegatedAdministrators, RequiredSecurityHubStandards: append([]string(nil), target.RequiredSecurityHubStandards...), RequiredSecurityHubStandardsConfigured: len(target.RequiredSecurityHubStandards) > 0, SecurityLakeRequired: target.RequireSecurityLake}
	orgClient := organizations.NewFromConfig(a.config)
	org, err := orgClient.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
	if err != nil {
		return Snapshot{}, wrap("organizations.DescribeOrganization", err)
	}
	if org.Organization != nil {
		out.Organization.Enabled = true
		out.Organization.ID = awssdk.ToString(org.Organization.Id)
		out.Organization.ManagementAccountID = awssdk.ToString(org.Organization.MasterAccountId)
	}
	pager := organizations.NewListAccountsPaginator(orgClient, &organizations.ListAccountsInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return Snapshot{}, wrap("organizations.ListAccounts", err)
		}
		out.Organization.AccountCount += len(page.Accounts)
		if out.Organization.AccountCount > 10000 {
			return Snapshot{}, fmt.Errorf("AWS account inventory exceeds 10000 item safety limit")
		}
	}
	for _, region := range target.GovernedRegions {
		regional := a.config
		regional.Region = region
		gd, err := discoverGuardDuty(ctx, regional, region)
		if err != nil {
			return Snapshot{}, err
		}
		out.GuardDuty = append(out.GuardDuty, gd)
		hub, standards, err := discoverSecurityHub(ctx, regional, region)
		if err != nil {
			return Snapshot{}, err
		}
		out.SecurityHub = append(out.SecurityHub, hub)
		out.EnabledSecurityHubStandards = append(out.EnabledSecurityHubStandards, standards...)
		recorder, err := discoverConfig(ctx, regional, region)
		if err != nil {
			return Snapshot{}, err
		}
		out.ConfigRecorders = append(out.ConfigRecorders, recorder...)
	}
	out.GuardDutyAllRegions = allRegions(out.GuardDuty, target.GovernedRegions)
	out.SecurityHubAllRegions = allRegions(out.SecurityHub, target.GovernedRegions)
	out.ConfigRecordersAllRegions = allRecorders(out.ConfigRecorders, target.GovernedRegions)
	out.RequiredSecurityHubStandardsPresent = containsAll(out.EnabledSecurityHubStandards, target.RequiredSecurityHubStandards)
	home := a.config
	home.Region = target.HomeRegion
	trails, err := discoverTrails(ctx, home)
	if err != nil {
		return Snapshot{}, err
	}
	out.Trails = trails
	if target.RequireDelegatedAdministrators {
		gdAdmins, err := guardduty.NewFromConfig(home).ListOrganizationAdminAccounts(ctx, &guardduty.ListOrganizationAdminAccountsInput{})
		if err != nil {
			return Snapshot{}, wrap("guardduty.ListOrganizationAdminAccounts", err)
		}
		out.GuardDutyDelegatedAdministrator = len(gdAdmins.AdminAccounts) > 0
		hubAdmins, err := securityhub.NewFromConfig(home).ListOrganizationAdminAccounts(ctx, &securityhub.ListOrganizationAdminAccountsInput{})
		if err != nil {
			return Snapshot{}, wrap("securityhub.ListOrganizationAdminAccounts", err)
		}
		out.SecurityHubDelegatedAdministrator = len(hubAdmins.AdminAccounts) > 0
	}
	if target.RequireSecurityLake {
		lakeClient := securitylake.NewFromConfig(home)
		lakes, err := lakeClient.ListDataLakes(ctx, &securitylake.ListDataLakesInput{Regions: target.GovernedRegions})
		if err != nil {
			return Snapshot{}, wrap("securitylake.ListDataLakes", err)
		}
		for _, lake := range lakes.DataLakes {
			item := SecurityLake{Region: awssdk.ToString(lake.Region), Enabled: strings.EqualFold(string(lake.CreateStatus), "COMPLETED")}
			if lake.EncryptionConfiguration != nil {
				item.Encryption = awssdk.ToString(lake.EncryptionConfiguration.KmsKeyId)
			}
			item.LifecycleConfigured = lake.LifecycleConfiguration != nil
			out.SecurityLakes = append(out.SecurityLakes, item)
		}
		out.SecurityLakeAllRegions = allLakes(out.SecurityLakes, target.GovernedRegions)
	}
	if target.Architecture == SecurityLakeWithOpenSearch || target.Architecture == FullAWSNativeSOC {
		for _, region := range target.GovernedRegions {
			regional := a.config
			regional.Region = region
			client := opensearch.NewFromConfig(regional)
			domains, err := client.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
			if err != nil {
				return Snapshot{}, wrap("opensearch.ListDomainNames", err)
			}
			for _, domain := range domains.DomainNames {
				name := awssdk.ToString(domain.DomainName)
				config, err := client.DescribeDomainConfig(ctx, &opensearch.DescribeDomainConfigInput{DomainName: &name})
				if err != nil {
					return Snapshot{}, wrap("opensearch.DescribeDomainConfig", err)
				}
				item := OpenSearchDomain{Region: region, Name: name}
				if config.DomainConfig != nil {
					if config.DomainConfig.EncryptionAtRestOptions != nil && config.DomainConfig.EncryptionAtRestOptions.Options != nil {
						item.EncryptionAtRest = awssdk.ToBool(config.DomainConfig.EncryptionAtRestOptions.Options.Enabled)
					}
					if config.DomainConfig.NodeToNodeEncryptionOptions != nil && config.DomainConfig.NodeToNodeEncryptionOptions.Options != nil {
						item.NodeToNodeEncryption = awssdk.ToBool(config.DomainConfig.NodeToNodeEncryptionOptions.Options.Enabled)
					}
					if config.DomainConfig.DomainEndpointOptions != nil && config.DomainConfig.DomainEndpointOptions.Options != nil {
						item.HTTPSRequired = awssdk.ToBool(config.DomainConfig.DomainEndpointOptions.Options.EnforceHTTPS)
					}
				}
				out.OpenSearchDomains = append(out.OpenSearchDomains, item)
				if len(out.OpenSearchDomains) > 1000 {
					return Snapshot{}, fmt.Errorf("OpenSearch inventory exceeds 1000 item safety limit")
				}
			}
		}
	}
	sort.Strings(out.EnabledSecurityHubStandards)
	return out, nil
}

func discoverGuardDuty(ctx context.Context, cfg awssdk.Config, region string) (RegionalService, error) {
	client := guardduty.NewFromConfig(cfg)
	output, err := client.ListDetectors(ctx, &guardduty.ListDetectorsInput{})
	if err != nil {
		return RegionalService{}, wrap("guardduty.ListDetectors", err)
	}
	item := RegionalService{Region: region, Enabled: len(output.DetectorIds) > 0}
	if item.Enabled {
		item.ID = output.DetectorIds[0]
		detector, err := client.GetDetector(ctx, &guardduty.GetDetectorInput{DetectorId: &item.ID})
		if err != nil {
			return item, wrap("guardduty.GetDetector", err)
		}
		item.Status = string(detector.Status)
		item.Enabled = strings.EqualFold(item.Status, "ENABLED")
	}
	return item, nil
}
func discoverSecurityHub(ctx context.Context, cfg awssdk.Config, region string) (RegionalService, []string, error) {
	client := securityhub.NewFromConfig(cfg)
	hub, err := client.DescribeHub(ctx, &securityhub.DescribeHubInput{})
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not subscribed") || strings.Contains(strings.ToLower(err.Error()), "invalidaccess") {
			return RegionalService{Region: region, Enabled: false}, []string{}, nil
		}
		return RegionalService{}, nil, wrap("securityhub.DescribeHub", err)
	}
	item := RegionalService{Region: region, Enabled: hub.HubArn != nil, ID: awssdk.ToString(hub.HubArn), Status: "ENABLED"}
	var standards []string
	pager := securityhub.NewGetEnabledStandardsPaginator(client, &securityhub.GetEnabledStandardsInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return item, nil, wrap("securityhub.GetEnabledStandards", err)
		}
		for _, standard := range page.StandardsSubscriptions {
			standards = append(standards, awssdk.ToString(standard.StandardsArn))
		}
	}
	return item, standards, nil
}
func discoverConfig(ctx context.Context, cfg awssdk.Config, region string) ([]ConfigRecorder, error) {
	client := configservice.NewFromConfig(cfg)
	output, err := client.DescribeConfigurationRecorderStatus(ctx, &configservice.DescribeConfigurationRecorderStatusInput{})
	if err != nil {
		return nil, wrap("config.DescribeConfigurationRecorderStatus", err)
	}
	items := make([]ConfigRecorder, 0, len(output.ConfigurationRecordersStatus))
	for _, status := range output.ConfigurationRecordersStatus {
		items = append(items, ConfigRecorder{Region: region, Name: awssdk.ToString(status.Name), Recording: status.Recording, LastStatus: string(status.LastStatus)})
	}
	return items, nil
}
func discoverTrails(ctx context.Context, cfg awssdk.Config) ([]Trail, error) {
	client := cloudtrail.NewFromConfig(cfg)
	output, err := client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{IncludeShadowTrails: awssdk.Bool(false)})
	if err != nil {
		return nil, wrap("cloudtrail.DescribeTrails", err)
	}
	items := make([]Trail, 0, len(output.TrailList))
	for _, trail := range output.TrailList {
		item := normaliseTrail(trail)
		status, err := client.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{Name: trail.TrailARN})
		if err != nil {
			return nil, wrap("cloudtrail.GetTrailStatus", err)
		}
		item.Logging = awssdk.ToBool(status.IsLogging)
		selectors, err := client.GetEventSelectors(ctx, &cloudtrail.GetEventSelectorsInput{TrailName: trail.TrailARN})
		if err != nil {
			return nil, wrap("cloudtrail.GetEventSelectors", err)
		}
		for _, selector := range selectors.EventSelectors {
			if awssdk.ToBool(selector.IncludeManagementEvents) {
				if selector.ReadWriteType == cloudtrailtypes.ReadWriteTypeAll || selector.ReadWriteType == cloudtrailtypes.ReadWriteTypeReadOnly {
					item.ManagementRead = true
				}
				if selector.ReadWriteType == cloudtrailtypes.ReadWriteTypeAll || selector.ReadWriteType == cloudtrailtypes.ReadWriteTypeWriteOnly {
					item.ManagementWrite = true
				}
			}
		}
		items = append(items, item)
	}
	return items, nil
}

func normaliseTrail(trail cloudtrailtypes.Trail) Trail {
	return Trail{ARN: awssdk.ToString(trail.TrailARN), Name: awssdk.ToString(trail.Name), HomeRegion: awssdk.ToString(trail.HomeRegion), OrganizationTrail: awssdk.ToBool(trail.IsOrganizationTrail), MultiRegion: awssdk.ToBool(trail.IsMultiRegionTrail), LogFileValidation: awssdk.ToBool(trail.LogFileValidationEnabled), KMSEncrypted: trail.KmsKeyId != nil}
}

func validateTarget(t Target) error {
	if t.HomeRegion == "" || len(t.GovernedRegions) == 0 {
		return fmt.Errorf("home region and at least one governed region are required")
	}
	allowed := map[Architecture]bool{SecurityLakeOnly: true, SecurityLakeWithOpenSearch: true, SecurityHubFindingsCentric: true, ExistingThirdPartySIEMExport: true, FullAWSNativeSOC: true}
	if !allowed[t.Architecture] {
		return fmt.Errorf("unsupported AWS architecture %q", t.Architecture)
	}
	seen := map[string]bool{}
	for _, region := range t.GovernedRegions {
		if region == "" || seen[region] {
			return fmt.Errorf("governed regions must be unique and non-empty")
		}
		seen[region] = true
	}
	return nil
}
func allRegions(items []RegionalService, regions []string) bool {
	for _, region := range regions {
		found := false
		for _, item := range items {
			if item.Region == region && item.Enabled {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func allRecorders(items []ConfigRecorder, regions []string) bool {
	for _, region := range regions {
		found := false
		for _, item := range items {
			if item.Region == region && item.Recording {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func allLakes(items []SecurityLake, regions []string) bool {
	for _, region := range regions {
		found := false
		for _, item := range items {
			if item.Region == region && item.Enabled {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func containsAll(have, want []string) bool {
	for _, required := range want {
		found := false
		for _, item := range have {
			if strings.Contains(strings.ToLower(item), strings.ToLower(required)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func wrap(operation string, err error) error {
	return fmt.Errorf("AWS operation %s: %w", operation, err)
}
