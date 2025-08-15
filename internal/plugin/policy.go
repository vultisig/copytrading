package plugin

import (
	"encoding/base64"
	"fmt"

	rcommon "github.com/vultisig/recipes/common"
	"github.com/vultisig/recipes/engine"
	rtypes "github.com/vultisig/recipes/types"
	"github.com/vultisig/verifier/plugin"
	vtypes "github.com/vultisig/verifier/types"

	"github.com/vultisig/copytrading/internal/types"
)

func (p *Plugin) ValidateProposedTransactions(policy vtypes.PluginPolicy, txs []vtypes.PluginKeysignRequest) error {
	err := p.ValidatePluginPolicy(policy)
	if err != nil {
		return fmt.Errorf("failed to validate plugin policy: %v", err)
	}

	recipe, err := policy.GetRecipe()
	if err != nil {
		return fmt.Errorf("failed to get recipe from policy: %v", err)
	}

	eng := engine.NewEngine()

	for _, tx := range txs {
		for _, keysignMessage := range tx.Messages {
			txBytes, err := base64.StdEncoding.DecodeString(keysignMessage.Message)
			if err != nil {
				return fmt.Errorf("failed to decode transaction: %w", err)
			}

			_, err = eng.Evaluate(recipe, rcommon.Chain(keysignMessage.Chain), txBytes)
			if err != nil {
				return fmt.Errorf("failed to evaluate transaction: %w", err)
			}
		}
	}

	return nil
}

func (p *Plugin) ValidatePluginPolicy(policyDoc vtypes.PluginPolicy) error {
	spec, err := p.GetRecipeSpecification()
	if err != nil {
		return err
	}
	return plugin.ValidatePluginPolicy(policyDoc, spec)
}

func (p *Plugin) GetRecipeSpecification() (*rtypes.RecipeSchema, error) {
	cfg, err := plugin.RecipeConfiguration(map[string]any{
		"type": "object",
		"properties": map[string]any{
			types.PolicyTarget: map[string]any{
				"type": "string",
			},
			types.PolicyDenominator: map[string]any{
				"type": "int",
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
