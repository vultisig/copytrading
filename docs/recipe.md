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

Plugins must implement `Spec` interface:
```go
type Spec interface {
	GetRecipeSpecification() (*rtypes.RecipeSchema, error)
	ValidatePluginPolicy(policyDoc types.PluginPolicy) error
	Suggest(configuration map[string]any) (*rtypes.PolicySuggest, error)
}
```

```go
func (p *Plugin) GetRecipeSpecification() (*rtypes.RecipeSchema, error) {
	cfg, err := plugin.RecipeConfiguration(map[string]any{
		"type": "object",
		"properties": map[string]any{
			types.PolicyTarget: map[string]any{
				"type": "string",
			},
			types.PolicyDenominator: map[string]any{
				"type": "integer",
			},
		},
		"required": []any{
			types.PolicyTarget,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to build pb recipe config: %w", err)
	}

	return &rtypes.RecipeSchema{
		Version:       1, // Schema version
		PluginId:      "vultisig-copytrader-0000",
		PluginName:    "Copy trading plugin",
		PluginVersion: 1, // Convert from "0.1.0" to int32
		SupportedResources: []*rtypes.ResourcePattern{
			{
				ResourcePath: &rtypes.ResourcePath{
					ChainId:    "ethereum",
					ProtocolId: "uniswapV2_router",
					FunctionId: "swapExactTokensForTokens",
					Full:       "ethereum.uniswapV2_router.swapExactTokensForTokens",
				},
				Target: rtypes.TargetType_TARGET_TYPE_ADDRESS,
				ParameterCapabilities: []*rtypes.ParameterConstraintCapability{
					{
						ParameterName:  "amountIn",
						SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
						Required:       true,
					},
					{
						ParameterName:  "amountOutMin",
						SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_ANY,
						Required:       true,
					},
					{
						ParameterName:  "path",
						SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_ANY,
						Required:       true,
					},
					{
						ParameterName:  "to",
						SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
						Required:       true,
					},
					{
						ParameterName:  "deadline",
						SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_ANY,
						Required:       true,
					},
				},
				Required: true,
			},
		},
		Configuration: cfg,
		Requirements: &rtypes.PluginRequirements{
			MinVultisigVersion: 1,
			SupportedChains:    []string{"ethereum"},
		},
	}, nil
}
```

In `Configuration` field you need to define config for your plugin. Here you can place any variables necessary for your plugin and not directly related to transactions (e.g. scheduler operation, links to third-party resources, conditions for calling transactions, etc.).  
In `Supported Resources` for EVM (for other tba), all function call parameters must be strictly defined according to the abi of smart contract. For constants where there is no need to have fixed value, you can specify ANY.

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