package plugin

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"time"

	gcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/mobile-tss-lib/tss"
	rcommon "github.com/vultisig/recipes/common"
	"github.com/vultisig/recipes/ethereum"
	"github.com/vultisig/recipes/sdk/evm/codegen/uniswapv2_router"
	rtypes "github.com/vultisig/recipes/types"
	"github.com/vultisig/recipes/util"
	"github.com/vultisig/verifier/address"
	vcommon "github.com/vultisig/verifier/common"
	"github.com/vultisig/verifier/plugin/tx_indexer/pkg/storage"
	vtypes "github.com/vultisig/verifier/types"
	"github.com/vultisig/vultiserver/contexthelper"
	"golang.org/x/sync/errgroup"

	"github.com/vultisig/copytrading/internal/common"
)

func (p *Plugin) HandleSwapTask(c context.Context, t *asynq.Task) error {
	ctx, cancel := context.WithTimeout(c, 5*time.Minute)
	defer cancel()

	if err := contexthelper.CheckCancellation(ctx); err != nil {
		p.logger.WithError(err).Warn("Context cancelled, skipping trigger")
		return err
	}
	var swapTask *SwapTask
	if err := json.Unmarshal(t.Payload(), &swapTask); err != nil {
		p.logger.WithError(err).Error("Failed to unmarshal swapTask payload")
		return fmt.Errorf("failed to unmarshal swapTask payload: %s, %w", err, asynq.SkipRetry)
	}

	cPairs, err := p.db.GetPoliciesByResourceAndLeader(ctx, swapTask.Resource, swapTask.Sender)
	if err != nil {
		p.logger.WithError(err).Error("Failed to get pairs by leader")
		return fmt.Errorf("failed to get pairs by leader: %s, %w", err, asynq.SkipRetry)
	}

	for _, pair := range cPairs {
		pluginPolicy, err := p.db.GetPluginPolicy(ctx, pair.PolicyID)
		if err != nil {
			p.logger.WithError(err).Error("Failed to get plugin policy from database")
			continue
		}

		reqs, err := p.ProposeTransactions(ctx, *pluginPolicy, swapTask)
		if err != nil {
			p.logger.WithError(err).Error("p.ProposeTransaction")
			return fmt.Errorf("failed to propose transaction: %s, %w", err, asynq.SkipRetry)
		}

		var eg errgroup.Group
		for _, _req := range reqs {
			req := _req
			eg.Go(func() error {
				return p.initSign(ctx, req, *pluginPolicy)
			})
		}
		err = eg.Wait()
		if err != nil {
			p.logger.WithError(err).Error("eg.Wait")
			return fmt.Errorf("failed to wait for signing tasks: %s, %w", err, asynq.SkipRetry)
		}
	}
	return nil
}

func (p *Plugin) ProposeTransactions(ctx context.Context, policy vtypes.PluginPolicy, task *SwapTask) ([]vtypes.PluginKeysignRequest, error) {
	err := p.ValidatePluginPolicy(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to validate plugin policy: %w", err)
	}

	vault, err := common.GetVaultFromPolicy(p.vaultStorage, policy, p.vaultEncryptionSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to get vault from policy: %w", err)
	}

	ethAddress, _, _, err := address.GetAddress(vault.PublicKeyEcdsa, vault.HexChainCode, vcommon.Ethereum)
	if err != nil {
		return nil, fmt.Errorf("failed to get eth address: %w", err)
	}

	recipe, err := policy.GetRecipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get recipe from policy: %w", err)
	}

	chain := rcommon.Ethereum
	ethEvmID, err := chain.EvmID()
	if err != nil {
		return nil, fmt.Errorf("failed to get EVM ID for chain %s: %w", chain, err)
	}

	var (
		mu  = &sync.Mutex{}
		txs = make([]vtypes.PluginKeysignRequest, 0)
	)
	var eg errgroup.Group

	for _, rule := range recipe.Rules {
		resource, er := util.ParseResource(rule.GetResource())
		if er != nil {
			return nil, fmt.Errorf("failed to parse resource: %w", er)
		}

		if resource.GetProtocolId() != task.Resource {
			continue
		}

		params, er := RuleToPolicySwapParams(rule)
		if er != nil {
			return nil, fmt.Errorf("failed to convert rule to policy params: %w", er)
		}

		if params.Aim != task.Sender.String() {
			continue
		}

		eg.Go(func() error {
			tx, e := p.genUnsignedTx(
				ctx,
				ethAddress,
				params,
				task,
			)
			if e != nil {
				return fmt.Errorf("p.genUnsignedTx: %w", e)
			}

			txHex := gcommon.Bytes2Hex(tx)

			txData, e := ethereum.DecodeUnsignedPayload(tx)
			if e != nil {
				return fmt.Errorf("ethereum.DecodeUnsignedPayload: %w", e)
			}
			txHashToSign := types.LatestSignerForChainID(ethEvmID).Hash(types.NewTx(txData))

			txToTrack, e := p.txIndexerService.CreateTx(ctx, storage.CreateTxDto{
				PluginID:      policy.PluginID,
				PolicyID:      policy.ID,
				ChainID:       vcommon.Chain(chain),
				FromPublicKey: policy.PublicKey,
				ToPublicKey:   UniswapV2RouterAddress,
				ProposedTxHex: txHex,
			})
			if e != nil {
				return fmt.Errorf("p.txIndexerService.CreateTx: %w", e)
			}

			msgHash := sha256.Sum256(txHashToSign.Bytes())

			// Create signing request
			signRequest := vtypes.PluginKeysignRequest{
				KeysignRequest: vtypes.KeysignRequest{
					PublicKey: policy.PublicKey,
					Messages: []vtypes.KeysignMessage{
						{
							TxIndexerID:  txToTrack.ID.String(),
							Message:      base64.StdEncoding.EncodeToString(txHashToSign.Bytes()),
							Chain:        vcommon.Chain(chain),
							Hash:         base64.StdEncoding.EncodeToString(msgHash[:]),
							HashFunction: vtypes.HashFunction_SHA256,
						},
					},
					PolicyID: policy.ID,
					PluginID: policy.PluginID.String(),
				},
				Transaction: txHex,
			}

			mu.Lock()
			txs = append(txs, signRequest)
			mu.Unlock()
			return nil
		})
	}

	err = eg.Wait()
	if err != nil {
		p.logger.Errorf("eg.Wait: %v", err)
		return []vtypes.PluginKeysignRequest{}, fmt.Errorf("eg.Wait: %w", err)
	}

	return nil, nil
}

func (p *Plugin) initSign(
	ctx context.Context,
	req vtypes.PluginKeysignRequest,
	pluginPolicy vtypes.PluginPolicy,
) error {
	sigs, err := p.signer.Sign(ctx, req)
	if err != nil {
		p.logger.WithError(err).Error("Keysign failed")
		return fmt.Errorf("failed to sign transaction: %w", err)
	}

	if len(sigs) != 1 {
		p.logger.
			WithField("sigs_count", len(sigs)).
			Error("expected only 1 message+sig per request for evm")
		return fmt.Errorf("failed to sign transaction: invalid signature count: %d", len(sigs))
	}
	var sig tss.KeysignResponse
	for _, s := range sigs {
		sig = s
	}

	err = p.SigningComplete(ctx, sig, req)
	if err != nil {
		p.logger.WithError(err).Error("failed to complete signing process (broadcast tx)")
		return fmt.Errorf("failed to complete signing process: %w", err)
	}
	return nil
}

func (p *Plugin) SigningComplete(
	ctx context.Context,
	signature tss.KeysignResponse,
	signRequest vtypes.PluginKeysignRequest,
) error {
	tx, err := p.eth.Send(
		ctx,
		gcommon.FromHex(signRequest.Transaction),
		gcommon.Hex2Bytes(signature.R),
		gcommon.Hex2Bytes(signature.S),
		gcommon.Hex2Bytes(signature.RecoveryID),
	)
	if err != nil {
		p.logger.WithError(err).WithField("tx_hex", signRequest.Transaction).Error("p.eth.Send")
		return fmt.Errorf("p.eth.Send(tx_hex=%s): %w", signRequest.Transaction, err)
	}

	p.logger.WithFields(logrus.Fields{
		"from_public_key": signRequest.PublicKey,
		"to_address":      tx.To().Hex(),
		"hash":            tx.Hash().Hex(),
		"chain":           vcommon.Ethereum.String(),
	}).Info("tx successfully signed and broadcasted")
	return nil
}

func RuleToPolicySwapParams(rule *rtypes.Rule) (*PolicySwapParams, error) {
	if len(rule.ParameterConstraints) == 0 {
		return nil, fmt.Errorf("no parameter constraints found")
	}

	if len(rule.ParameterConstraints) > 4 {
		return nil, fmt.Errorf("too many parameter constraints found")
	}

	var params PolicySwapParams
	for _, constraint := range rule.ParameterConstraints {
		if constraint.ParameterName == "aim" {
			if constraint.Constraint.Type != rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED {
				return nil, fmt.Errorf("aim constraint is not a fixed value")
			}
			params.Aim = constraint.Constraint.GetFixedValue()
		}

		if constraint.ParameterName == "source_token" {
			if constraint.Constraint.Type != rtypes.ConstraintType_CONSTRAINT_TYPE_ANY {
				return nil, fmt.Errorf("source_token constraint is not any value")
			}
			params.SourceToken = constraint.Constraint.GetFixedValue()
		}

		if constraint.ParameterName == "destination_token" {
			if constraint.Constraint.Type != rtypes.ConstraintType_CONSTRAINT_TYPE_ANY {
				return nil, fmt.Errorf("destination_token constraint is not any value")
			}
			params.DestinationToken = constraint.Constraint.GetFixedValue()
		}

		if constraint.ParameterName == "amount" {
			switch constraint.Constraint.Type {
			case rtypes.ConstraintType_CONSTRAINT_TYPE_MAX:
				params.MaxAmount = constraint.Constraint.GetMaxValue()
			default:
				return nil, fmt.Errorf("invalid constraint type")
			}
		}
	}

	return &params, nil
}

func (p *Plugin) genUnsignedTx(
	ctx context.Context,
	senderAddress string,
	params *PolicySwapParams,
	task *SwapTask,
) ([]byte, error) {
	amt, ok := new(big.Int).SetString(params.MaxAmount, 10)
	if !ok {
		return nil, fmt.Errorf("failed to parse amount: %s", params.MaxAmount)
	}
	if amt.Cmp(task.Amount) > 0 {
		amt = task.Amount
	}

	deadline := new(big.Int).SetInt64(time.Now().Add(20 * time.Minute).Unix())

	data := uniswapv2_router.NewUniswapv2Router().PackSwapExactTokensForTokens(
		amt,
		big.NewInt(1),
		task.Path,
		gcommon.BigToAddress(big.NewInt(1)),
		deadline,
	)

	tx, err := p.eth.MakeTx(
		ctx,
		gcommon.HexToAddress(senderAddress),
		gcommon.HexToAddress(UniswapV2RouterAddress),
		big.NewInt(0),
		data,
	)
	if err != nil {
		return nil, fmt.Errorf("p.eth.MakeAnyTransfer: %v", err)
	}
	return tx, nil
}
