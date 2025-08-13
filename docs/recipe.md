# Recipes in Vultisig Plugins

## Overview

The Recipes system in Vultisig provides a powerful way to define and constrain transaction capabilities within plugins. Recipes specify which methods and constraints can be used for specific blockchain resources, regulate transaction arguments, and provide SDK utilities for transaction generation.

## Key Concepts

### Resource Definition
Recipes define blockchain resources through a structured path format:
```
<chain_id>.<protocol_id>.<function_id>
```
Example: `ethereum.erc20.transfer`

### Constraint Types
Recipes support multiple constraint types for parameters:
- **Fixed**: Exact value matching
- **Range**: Greater than/Less than comparisons
- **Magic**: Special constraints (e.g., non-zero addresses, future deadlines)
- **Any**: UNSAFE Allows to use any parameter

### Recipe Schema
The schema defines:
- Supported resources and their parameters
- Required constraints for each parameter
- Protocol configuration requirements
- Plugin compatibility information

## Using Recipes in Plugins

### Defining Recipe Specifications

Plugins must implement `GetRecipeSpecification()` to declare their capabilities:

```go
func (p *Plugin) GetRecipeSpecification() (*rtypes.RecipeSchema, error) {
    return &rtypes.RecipeSchema{
        Version:       1,
        PluginId:      "your_plugin_id",
        PluginName:    "Your Plugin Name",
        PluginVersion: 1,
        SupportedResources: []*rtypes.ResourcePattern{
            {
                ResourcePath: &rtypes.ResourcePath{
                    ChainId:    "ethereum",
                    ProtocolId: "erc20",
                    FunctionId: "transfer",
                    Full:       "ethereum.erc20.transfer",
                },
                Target: rtypes.TargetType_TARGET_TYPE_ADDRESS,
                ParameterCapabilities: []*rtypes.ParameterConstraintCapability{
                    {
                        ParameterName:  "recipient",
                        SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
                        Required:       true,
                    },
                    {
                        ParameterName:  "amount",
                        SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
                        Required:       true,
                    },
                },
            },
        },
        Configuration: cfg, // Optional configuration schema
        Requirements: &rtypes.PluginRequirements{
            MinVultisigVersion: 1,
            SupportedChains:    []string{"ethereum"},
        },
    }, nil
}
```

### Using the EVM SDK

The Recipes repository provides an EVM SDK for generating raw transactions:

```go
func (p *Plugin) generateTransferTx(ctx context.Context, senderAddress, to, tokenID string, amount *big.Int) ([]byte, error) {
	tx, err := p.eth.MakeAnyTransfer(
		ctx, 
		common.HexToAddress(senderAddress), 
		common.HexToAddress(to), 
		common.HexToAddress(tokenID), 
		amount, 
		)
	if err != nil {
		return nil, fmt.Errorf("p.eth.MakeAnyTransfer: %v", err)
	}
	
	return tx, nil
}
```

## Validation System

Recipes include a robust validation system for transaction parameters:

### Built-in Validations
- Address format checking
- Non-zero value requirements
- Slippage protection thresholds
- Deadline validation
- Protocol-specific rules

The Recipes system provides a flexible yet secure way to define and handle blockchain transactions within Vultisig plugins, ensuring all transactions comply with the specified constraints and security requirements.

### ABI Support
Now recipes package includes this 
- ERC20
- UniswapRouter_v2

# Magic Constants
Magic Constants are special predefined values in the Vultisig Recipes system that represent dynamic or context-sensitive parameters rather than fixed values. They allow recipes to specify constraints that adapt to runtime conditions while maintaining security guarantees. 

Example:
```
  VULTISIG_TREASURY = 1;
```