package keeper

import (
	"math"
	"math/big"

	ethermint "github.com/tharsis/ethermint/types"

	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"

	ethparams "github.com/ethereum/go-ethereum/params"

	"github.com/tharsis/ethermint/crypto/ethsecp256k1"

	"github.com/ethereum/go-ethereum/crypto"

	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	gogotypes "github.com/gogo/protobuf/types"
	"github.com/tharsis/ethermint/x/evm/types"
)

func (k *Keeper) newAccountWithAddressForMetaos(ctx sdk.Context, addr sdk.AccAddress) authtypes.AccountI {
	acc := ethermint.ProtoAccount()

	err := acc.SetAddress(addr)
	if err != nil {
		panic(err)
	}

	return k.newAccountForMetaos(ctx, acc)
}

// NewAccountForMetaos sets the next account number to a given account interface
func (k *Keeper) newAccountForMetaos(ctx sdk.Context, acc authtypes.AccountI) authtypes.AccountI {
	if err := acc.SetAccountNumber(k.getNextAccountNumberForMetaos(ctx)); err != nil {
		panic(err)
	}
	//authtypes.StoreKey

	return acc
}

// GetNextAccountNumberForMetaos returns and increments the global account number counter.
// If the global account number is not set, it initializes it with value 0.
func (k *Keeper) getNextAccountNumberForMetaos(ctx sdk.Context) uint64 {
	var accNumber uint64

	store := ctx.KVStore(k.AccStoreKey)

	bz := store.Get(authtypes.GlobalAccountNumberKey)
	if bz == nil {
		// initialize the account numbers
		accNumber = 0
	} else {
		val := gogotypes.UInt64Value{}

		err := k.cdc.Unmarshal(bz, &val)
		if err != nil {
			panic(err)
		}

		accNumber = val.GetValue()
	}

	bz = k.cdc.MustMarshal(&gogotypes.UInt64Value{Value: accNumber + 1})
	store.Set(authtypes.GlobalAccountNumberKey, bz)

	return accNumber
}

// getResponse
// determine the algorithm type of the key
func (k *Keeper) getEthereumTxResponseForMetaos(ctx sdk.Context, sender string, tx *ethtypes.Transaction) (*types.MsgEthereumTxResponse, error) {

	var response *types.MsgEthereumTxResponse
	var err error

	ethAddr := common.HexToAddress(sender)
	cosmosAddr := sdk.AccAddress(ethAddr.Bytes())
	account := k.accountKeeper.GetAccount(ctx, cosmosAddr)
	pubKey := account.GetPubKey()
	if pubKey == nil {
		k.Logger(ctx).Debug(
			"cosmos_addr", cosmosAddr.String(),
			"info_msg", "can not get publicKey for address",
		)
		response, err = k.ApplyTransaction(ctx, tx)
	} else {
		pubKeyAlgo := pubKey.Type()

		if pubKeyAlgo == ethsecp256k1.KeyType {
			response, err = k.ApplyTransaction(ctx, tx)
		} else {
			response, err = k.ApplyTransactionSm2(ctx, tx)
		}
	}
	return response, err
}

// getSinger sm2 signer or eth_secpk1256 singer
func (k *Keeper) getSingerForMetaos(chainConfig *ethparams.ChainConfig, ctx sdk.Context) ethtypes.Signer {
	if k.Signer == nil {
		return ethtypes.MakeSigner(chainConfig, big.NewInt(ctx.BlockHeight()))
	}
	return k.Signer
}

// ApplyTransactionSm2 runs and attempts to perform a state transition with the given transaction (i.e Message), that will
// only be persisted (committed) to the underlying KVStore if the transaction does not fail.
//
// Gas tracking
//
// Ethereum consumes gas according to the EVM opcodes instead of general reads and writes to store. Because of this, the
// state transition needs to ignore the SDK gas consumption mechanism defined by the GasKVStore and instead consume the
// amount of gas used by the VM execution. The amount of gas used is tracked by the EVM and returned in the execution
// result.
//
// Prior to the execution, the starting tx gas meter is saved and replaced with an infinite gas meter in a new context
// in order to ignore the SDK gas consumption config values (read, write, has, delete).
// After the execution, the gas used from the message execution will be added to the starting gas consumed, taking into
// consideration the amount of gas returned. Finally, the context is updated with the EVM gas consumed value prior to
// returning.
//
// For relevant discussion see: https://github.com/cosmos/cosmos-sdk/discussions/9072
func (k *Keeper) ApplyTransactionSm2(ctx sdk.Context, tx *ethtypes.Transaction) (*types.MsgEthereumTxResponse, error) {
	var (
		bloom        *big.Int
		bloomReceipt ethtypes.Bloom
	)

	cfg, err := k.EVMConfig(ctx)
	if err != nil {
		return nil, sdkerrors.Wrap(err, "failed to load evm config")
	}
	txConfig := k.TxConfig(ctx, tx.Hash())

	// get the signer according to the chain rules from the config and block height
	//signer := ethtypes.MakeSigner(cfg.ChainConfig, big.NewInt(ctx.BlockHeight()))
	signer := k.Signer
	msg, err := tx.AsMessage(signer, cfg.BaseFee)
	if err != nil {
		return nil, sdkerrors.Wrap(err, "failed to return ethereum transaction as core message")
	}

	// snapshot to contain the tx processing and post processing in same scope
	var commit func()
	tmpCtx := ctx
	if k.hooks != nil {
		// Create a cache context to revert state when tx hooks fails,
		// the cache context is only committed when both tx and hooks executed successfully.
		// Didn't use `Snapshot` because the context stack has exponential complexity on certain operations,
		// thus restricted to be used only inside `ApplyMessage`.
		tmpCtx, commit = ctx.CacheContext()
	}

	// pass true to commit the StateDB
	res, err := k.ApplyMessageWithConfig(tmpCtx, msg, nil, true, cfg, txConfig)
	if err != nil {
		return nil, sdkerrors.Wrap(err, "failed to apply ethereum core message")
	}

	logs := types.LogsToEthereum(res.Logs)

	// Compute block bloom filter
	if len(logs) > 0 {
		bloom = k.GetBlockBloomTransient(ctx)
		bloom.Or(bloom, big.NewInt(0).SetBytes(ethtypes.LogsBloom(logs)))
		bloomReceipt = ethtypes.BytesToBloom(bloom.Bytes())
	}

	if !res.Failed() {
		cumulativeGasUsed := res.GasUsed
		if ctx.BlockGasMeter() != nil {
			limit := ctx.BlockGasMeter().Limit()
			consumed := ctx.BlockGasMeter().GasConsumed()
			cumulativeGasUsed = uint64(math.Min(float64(cumulativeGasUsed+consumed), float64(limit)))
		}

		var contractAddr common.Address
		if msg.To() == nil {
			contractAddr = crypto.CreateAddress(msg.From(), msg.Nonce())
		}

		receipt := &ethtypes.Receipt{
			Type:              tx.Type(),
			PostState:         nil, // TODO: intermediate state root
			Status:            ethtypes.ReceiptStatusSuccessful,
			CumulativeGasUsed: cumulativeGasUsed,
			Bloom:             bloomReceipt,
			Logs:              logs,
			TxHash:            txConfig.TxHash,
			ContractAddress:   contractAddr,
			GasUsed:           res.GasUsed,
			BlockHash:         txConfig.BlockHash,
			BlockNumber:       big.NewInt(ctx.BlockHeight()),
			TransactionIndex:  txConfig.TxIndex,
		}

		// Only call hooks if tx executed successfully.
		if err = k.PostTxProcessing(tmpCtx, msg.From(), tx.To(), receipt); err != nil {
			// If hooks return error, revert the whole tx.
			res.VmError = types.ErrPostTxProcessing.Error()
			k.Logger(ctx).Error("tx post processing failed", "error", err)
		} else if commit != nil {
			// PostTxProcessing is successful, commit the tmpCtx
			commit()
			ctx.EventManager().EmitEvents(tmpCtx.EventManager().Events())
		}
	}

	// refund gas in order to match the Ethereum gas consumption instead of the default SDK one.
	if err = k.RefundGas(ctx, msg, msg.Gas()-res.GasUsed, cfg.Params.EvmDenom); err != nil {
		return nil, sdkerrors.Wrapf(err, "failed to refund gas leftover gas to sender %s", msg.From())
	}

	if len(logs) > 0 {
		// Update transient block bloom filter
		k.SetBlockBloomTransient(ctx, bloom)

		k.SetLogSizeTransient(ctx, uint64(txConfig.LogIndex)+uint64(len(logs)))
	}

	k.SetTxIndexTransient(ctx, uint64(txConfig.TxIndex)+1)

	totalGasUsed, err := k.AddTransientGasUsed(ctx, res.GasUsed)
	if err != nil {
		return nil, sdkerrors.Wrap(err, "failed to add transient gas used")
	}

	// reset the gas meter for current cosmos transaction
	k.ResetGasMeterAndConsumeGas(ctx, totalGasUsed)
	return res, nil
}