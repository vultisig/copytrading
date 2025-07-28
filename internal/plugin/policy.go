package plugin

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kaptinlin/jsonschema"
	"github.com/vultisig/recipes/chain"
	"github.com/vultisig/recipes/engine"
	rtypes "github.com/vultisig/recipes/types"
	vtypes "github.com/vultisig/verifier/types"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
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
			messageChain, err := chain.GetChain(strings.ToLower(keysignMessage.Chain.String()))
			if err != nil {
				return fmt.Errorf("failed to get chain: %w", err)
			}

			decodedTx, err := messageChain.ParseTransaction(keysignMessage.Message)
			if err != nil {
				return fmt.Errorf("failed to parse transaction: %w", err)
			}

			transactionAllowed, _, err := eng.Evaluate(recipe, messageChain, decodedTx)
			if err != nil {
				return fmt.Errorf("failed to evaluate transaction: %w", err)
			}

			if !transactionAllowed {
				return fmt.Errorf("transaction %s on %s not allowed by policy", keysignMessage.Hash, keysignMessage.Chain)
			}
		}
	}

	return nil
}

func RecipeConfiguration(jsonSchema map[string]any) (*structpb.Struct, error) {
	b, err := json.Marshal(jsonSchema)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal schema: %w", err)
	}

	_, err = jsonschema.NewCompiler().Compile(b)
	if err != nil {
		return nil, fmt.Errorf("failed to compile schema: %w", err)
	}

	pb, err := structpb.NewStruct(jsonSchema)
	if err != nil {
		return nil, fmt.Errorf("failed to build pb schema: %w", err)
	}
	return pb, nil
}

func (p *Plugin) ValidatePluginPolicy(policyDoc vtypes.PluginPolicy) error {
	spec, err := p.GetRecipeSpecification()
	if err != nil {
		return err
	}
	return validatePluginPolicy(policyDoc, spec)
}

func validatePluginPolicy(policyDoc vtypes.PluginPolicy, spec *rtypes.RecipeSchema) error {
	policyBytes, err := base64.StdEncoding.DecodeString(policyDoc.Recipe)
	if err != nil {
		return fmt.Errorf("failed to decode policy recipe: %w", err)
	}

	var rPolicy rtypes.Policy
	err = proto.Unmarshal(policyBytes, &rPolicy)
	if err != nil {
		return fmt.Errorf("failed to unmarshal policy: %w", err)
	}

	err = engine.NewEngine().ValidatePolicyWithSchema(&rPolicy, spec)
	if err != nil {
		return fmt.Errorf("failed to validate policy: %w", err)
	}
	return nil
}

func (p *Plugin) GetRecipeSpecification() (*rtypes.RecipeSchema, error) {
	return &rtypes.RecipeSchema{
		Version:         1, // Schema version
		ScheduleVersion: 1, // Schedule specification version
		// TODO: configure
		PluginId:      string(vtypes.PluginVultisigCopytrader_0000),
		PluginName:    "Copy trading plugin",
		PluginVersion: 1, // Convert from "0.1.0" to int32
		SupportedResources: []*rtypes.ResourcePattern{
			{
				ResourcePath: &rtypes.ResourcePath{
					ChainId:    "ethereum",
					ProtocolId: "uniswapv2_router",
					FunctionId: "swapExactTokensForTokens",
					Full:       "ethereum.uniswapv2_router.swapExactTokensForTokens",
				},
				ParameterCapabilities: []*rtypes.ParameterConstraintCapability{
					{
						ParameterName: "aim",
						SupportedTypes: []rtypes.ConstraintType{
							rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
							rtypes.ConstraintType_CONSTRAINT_TYPE_WHITELIST,
						},
						Required: true,
					},
					{
						ParameterName: "source_token",
						SupportedTypes: []rtypes.ConstraintType{
							rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
							rtypes.ConstraintType_CONSTRAINT_TYPE_WHITELIST,
						},
						Required: true,
					},
					{
						ParameterName: "destination_token",
						SupportedTypes: []rtypes.ConstraintType{
							rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
							rtypes.ConstraintType_CONSTRAINT_TYPE_WHITELIST,
						},
						Required: true,
					},
					{
						ParameterName: "amount",
						SupportedTypes: []rtypes.ConstraintType{
							rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
							rtypes.ConstraintType_CONSTRAINT_TYPE_MAX,
							rtypes.ConstraintType_CONSTRAINT_TYPE_RANGE,
						},
						Required: true,
					},
				},
				Required: true,
			},
		},
		Requirements: &rtypes.PluginRequirements{
			MinVultisigVersion: 1,
			SupportedChains:    []string{"ethereum"},
		},
	}, nil
}
