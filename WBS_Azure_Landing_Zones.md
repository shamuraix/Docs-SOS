# Azure Landing Zones Implementation - Work Breakdown Structure (WBS)
## Single-Region Hub-and-Spoke with Custom Archetype Configuration using Terraform Local Deployment

## 1. Prerequisites and Setup

1.1. Environment Preparation
   - 1.1.1. Ensure owner permissions at Azure tenant root scope
   - 1.1.2. Install Terraform v1.5.0+ and Azure CLI
   - 1.1.3. Prepare subscriptions for platform resources (connectivity, management, identity)
   - 1.1.4. Register required resource providers in Azure subscriptions

1.2. ALZ Terraform Repository Setup
   - 1.2.1. Clone the ALZ Terraform repository from GitHub
   - 1.2.2. Create local working directory structure
   - 1.2.3. Configure authentication with Azure (az login or service principal)
   - 1.2.4. Set up local state management or Azure Storage Account for Terraform state

## 2. Custom Archetype Configuration

2.1. Archetype Definition Creation
   - 2.1.1. Create custom archetype definitions folder structure
   - 2.1.2. Define archetype for "private" (replacing "corp") management group
   - 2.1.3. Define archetype for "public" (replacing "online") management group
   - 2.1.4. Configure custom policy assignments for archetypes

2.2. Archetype Library Configuration
   - 2.2.1. Create archetype_definition_private.json and archetype_definition_public.json
   - 2.2.2. Configure policy and role mappings in archetype definitions
   - 2.2.3. Create archetype_exclusions if needed for specific scenarios
   - 2.2.4. Document custom archetype library structure

2.3. Feature Flag Configuration
   - 2.3.1. Create variables for enabling/disabling optional features
   - 2.3.2. Set DDoS Protection parameter to disable this feature
   - 2.3.3. Configure parameters to disable Azure Bastion host
   - 2.3.4. Set parameters to disable Microsoft Defender for Cloud

## 3. Core Configuration Files

3.1. Base Terraform Files
   - 3.1.1. Create `providers.tf` with provider configuration
   - 3.1.2. Create `variables.tf` with all required input variables
   - 3.1.3. Create `terraform.tfvars` with specific configuration values
   - 3.1.4. Create `outputs.tf` for important resource references

3.2. Management Group Module Configuration
   - 3.2.1. Configure management group module with custom archetype library path
   - 3.2.2. Set up management group parameters to use custom archetypes
   - 3.2.3. Configure subscription associations to management groups
   - 3.2.4. Map management groups to custom archetype definitions

## 4. Network Infrastructure

4.1. Hub Network Configuration
   - 4.1.1. Configure hub virtual network and address space
   - 4.1.2. Set `deploy_ddos_protection` parameter to `false` to disable DDoS
   - 4.1.3. Configure subnets and security groups for hub network
   - 4.1.4. Configure Azure Firewall with minimal public IP exposure

4.2. Spoke Networks Configuration
   - 4.2.1. Define spoke virtual networks and address spaces
   - 4.2.2. Configure subnets for workload requirements
   - 4.2.3. Set up network security groups for spokes
   - 4.2.4. Configure virtual network peering between hub and spokes

4.3. Network Security Settings
   - 4.3.1. Configure route tables with user-defined routes
   - 4.3.2. Set `deploy_bastion_host` parameter to `false`
   - 4.3.3. Configure Azure Firewall rules and policies
   - 4.3.4. Configure minimal public IP usage for necessary components

## 5. Policy and Security Configuration

5.1. Custom Policy Configuration
   - 5.1.1. Configure ALZ policy module parameters
   - 5.1.2. Exclude Defender for Cloud policies in archetype definitions 
   - 5.1.3. Configure required security baseline policies
   - 5.1.4. Set custom parameters for policy assignments

5.2. RBAC Configuration
   - 5.2.1. Define custom roles in archetype definitions
   - 5.2.2. Configure role assignments at management group level
   - 5.2.3. Configure role assignments for platform resources
   - 5.2.4. Document RBAC model and assignments

## 6. Local Terraform Deployment

6.1. Deployment Preparation
   - 6.1.1. Create deployment script for local execution
   - 6.1.2. Configure environment variables as needed
   - 6.1.3. Validate all configuration files
   - 6.1.4. Document deployment sequence and dependencies

6.2. Terraform Execution
   - 6.2.1. Run `terraform init` to initialize providers and modules
   - 6.2.2. Run `terraform validate` to check configuration
   - 6.2.3. Run `terraform plan` to preview changes
   - 6.2.4. Run `terraform apply` to deploy the infrastructure

6.3. Validation and Testing
   - 6.3.1. Verify management group hierarchy with custom naming
   - 6.3.2. Confirm disabled features are not deployed (DDoS, Defender, Bastion)
   - 6.3.3. Test network connectivity through Azure Firewall
   - 6.3.4. Validate policy assignments and compliance

## 7. Documentation and Handover

7.1. As-Built Documentation
   - 7.1.1. Document deployed infrastructure components
   - 7.1.2. Create network architecture diagrams
   - 7.1.3. Document custom archetype definitions
   - 7.1.4. Create configuration reference guide

7.2. Operational Documentation
   - 7.2.1. Document operational procedures
   - 7.2.2. Create troubleshooting guide
   - 7.2.3. Document monitoring and alerting configuration
   - 7.2.4. Create maintenance procedures

## 8. State Management

8.1. Terraform State Protection
   - 8.1.1. Configure backend state locking
   - 8.1.2. Set up state backups
   - 8.1.3. Document state management procedures
   - 8.1.4. Create recovery process for state corruption

8.2. Ongoing Management
   - 8.2.1. Document process for future configuration changes
   - 8.2.2. Create procedures for adding new subscriptions
   - 8.2.3. Define process for policy updates and modifications
   - 8.2.4. Establish continuous compliance monitoring