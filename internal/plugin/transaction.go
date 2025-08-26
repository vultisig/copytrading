package plugin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	gcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/mobile-tss-lib/tss"
	"github.com/vultisig/recipes/sdk/evm"
	"github.com/vultisig/recipes/sdk/evm/codegen/erc20"
	"github.com/vultisig/recipes/sdk/evm/codegen/uniswapv2_router"
	rtypes "github.com/vultisig/recipes/types"
	"github.com/vultisig/verifier/plugin/tx_indexer/pkg/storage"
	vtypes "github.com/vultisig/verifier/types"
	"github.com/vultisig/vultiserver/contexthelper"
	"github.com/vultisig/vultisig-go/address"
	vgcommon "github.com/vultisig/vultisig-go/common"
	"golang.org/x/sync/errgroup"

	"github.com/vultisig/copytrading/internal/common"
	ctypes "github.com/vultisig/copytrading/internal/types"
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
				return p.initSign(ctx, req, false)
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

	ethAddress, _, _, err := address.GetAddress(vault.PublicKeyEcdsa, vault.HexChainCode, vgcommon.Ethereum)
	if err != nil {
		return nil, fmt.Errorf("failed to get eth address: %w", err)
	}

	recipe, err := policy.GetRecipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get recipe from policy: %w", err)
	}

	chain := vgcommon.Ethereum

	var (
		mu  = &sync.Mutex{}
		txs = make([]vtypes.PluginKeysignRequest, 0)
	)
	var eg errgroup.Group

	cfg := recipe.GetConfiguration().GetFields()
	cfgTarget := cfg[ctypes.PolicyTarget].GetStringValue()

	if len(task.Path) == 0 {
		return nil, fmt.Errorf("invalid task path")
	}
	startSwapToken := task.Path[0]

	for _, rule := range recipe.Rules {
		if rule.GetResource() != task.Resource {
			continue
		}
		if cfgTarget != task.Sender.String() {
			continue
		}

		params, er := RuleToPolicySwapParams(rule)
		if er != nil {
			return nil, fmt.Errorf("failed to convert rule to policy params: %w", er)
		}

		owner, router := gcommon.HexToAddress(ethAddress), gcommon.HexToAddress(UniswapV2RouterAddress)

		erc20Contract := erc20.NewErc20()
		allowanceData := erc20Contract.PackAllowance(owner, router)
		currentAllowance, err := evm.CallReadonly(
			ctx,
			p.ethRpc,
			erc20Contract,
			startSwapToken,
			allowanceData,
			erc20Contract.UnpackAllowance,
			nil,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to check allowance: %w", err)
		}

		amount, ok := new(big.Int).SetString(params.Amount, 10)
		if !ok {
			return nil, fmt.Errorf("failed to parse amount")
		}

		// Check allowance, approve if needed
		if currentAllowance.Cmp(amount) < 0 {
			tx, err := p.eth.MakeTx(
				ctx,
				owner,
				startSwapToken,
				big.NewInt(0),
				erc20Contract.PackApprove(router, amount),
			)
			if err != nil {
				return nil, fmt.Errorf("failed to make approve tx: %w", err)
			}

			txHex := gcommon.Bytes2Hex(tx)

			txToTrack, e := p.txIndexerService.CreateTx(ctx, storage.CreateTxDto{
				PluginID:      policy.PluginID,
				PolicyID:      policy.ID,
				ChainID:       chain,
				FromPublicKey: policy.PublicKey,
				ToPublicKey:   startSwapToken.String(),
				ProposedTxHex: txHex,
			})
			if e != nil {
				return nil, fmt.Errorf("p.txIndexerService.CreateTx: %w", e)
			}

			signRequest, e := vtypes.NewPluginKeysignRequestEvm(
				policy, txToTrack.ID.String(), chain, tx)
			if e != nil {
				return nil, fmt.Errorf("vtypes.NewPluginKeysignRequestEvm: %w", e)
			}

			err = p.initSign(ctx, *signRequest, true)
			if err != nil {
				return nil, fmt.Errorf("failed to init sign: %w", err)
			}
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

			txToTrack, e := p.txIndexerService.CreateTx(ctx, storage.CreateTxDto{
				PluginID:      policy.PluginID,
				PolicyID:      policy.ID,
				ChainID:       chain,
				FromPublicKey: policy.PublicKey,
				ToPublicKey:   UniswapV2RouterAddress,
				ProposedTxHex: txHex,
			})
			if e != nil {
				return fmt.Errorf("p.txIndexerService.CreateTx: %w", e)
			}

			signRequest, e := vtypes.NewPluginKeysignRequestEvm(
				policy, txToTrack.ID.String(), chain, tx)

			mu.Lock()
			txs = append(txs, *signRequest)
			mu.Unlock()
			return nil
		})
	}

	err = eg.Wait()
	if err != nil {
		p.logger.Errorf("eg.Wait: %v", err)
		return []vtypes.PluginKeysignRequest{}, fmt.Errorf("eg.Wait: %w", err)
	}

	return txs, nil
}

func (p *Plugin) initSign(
	ctx context.Context,
	req vtypes.PluginKeysignRequest,
	waitMined bool,
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

	tx, err := p.SigningComplete(ctx, sig, req)
	if err != nil {
		p.logger.WithError(err).Error("failed to complete signing process (broadcast tx)")
		return fmt.Errorf("failed to complete signing process: %w", err)
	}

	if waitMined {
		p.logger.Println("waiting for tx being mined")
		receipt, err := bind.WaitMined(ctx, p.ethRpc, tx)
		if err != nil {
			p.logger.WithError(err).Error("failed to wait tx being mined")
			return fmt.Errorf("failed to wait tx being mined: %w", err)
		}
		if receipt.Status != types.ReceiptStatusSuccessful {
			return fmt.Errorf("tx failed: receipt status %s", receipt.Status)
		}
	}
	return nil
}

func (p *Plugin) SigningComplete(
	ctx context.Context,
	signature tss.KeysignResponse,
	signRequest vtypes.PluginKeysignRequest,
) (*types.Transaction, error) {
	txBytes, err := base64.StdEncoding.DecodeString(signRequest.Transaction)
	if err != nil {
		return nil, fmt.Errorf("failed to decode b64 proposed tx: %w", err)
	}
	txHex := gcommon.Bytes2Hex(txBytes)

	tx, err := p.eth.Send(
		ctx,
		txBytes,
		gcommon.Hex2Bytes(signature.R),
		gcommon.Hex2Bytes(signature.S),
		gcommon.Hex2Bytes(signature.RecoveryID),
	)
	if err != nil {
		p.logger.WithError(err).WithField("tx_hex", txHex).Error("p.eth.Send")
		return nil, fmt.Errorf("p.eth.Send(tx_hex=%s): %w", txHex, err)
	}

	p.logger.WithFields(logrus.Fields{
		"from_public_key": signRequest.PublicKey,
		"to_address":      tx.To().Hex(),
		"hash":            tx.Hash().Hex(),
		"chain":           vgcommon.Ethereum.String(),
	}).Info("tx successfully signed and broadcasted")
	return tx, nil
}

func RuleToPolicySwapParams(rule *rtypes.Rule) (*PolicySwapParams, error) {
	if len(rule.ParameterConstraints) == 0 {
		return nil, fmt.Errorf("no parameter constraints found")
	}

	if len(rule.ParameterConstraints) > 5 {
		return nil, fmt.Errorf("too many parameter constraints found")
	}

	var params PolicySwapParams
	for _, constraint := range rule.ParameterConstraints {
		if constraint.ParameterName == "amountIn" {
			switch constraint.Constraint.Type {
			case rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED:
				params.Amount = constraint.Constraint.GetFixedValue()
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
	amt, ok := new(big.Int).SetString(params.Amount, 10)
	if !ok {
		return nil, fmt.Errorf("failed to parse amount: %s", params.Amount)
	}
	if amt.Cmp(task.Amount) > 0 {
		amt = task.Amount
	}

	deadline := new(big.Int).SetInt64(time.Now().Add(20 * time.Minute).Unix())

	data := uniswapv2_router.NewUniswapv2Router().PackSwapExactTokensForTokens(
		amt,
		big.NewInt(1),
		task.Path,
		gcommon.HexToAddress(senderAddress),
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
