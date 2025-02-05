package simulation

import (
	"math/rand"

	"github.com/cosmos/cosmos-sdk/baseapp"
	sdk "github.com/cosmos/cosmos-sdk/types"
	simtypes "github.com/cosmos/cosmos-sdk/types/simulation"
	"github.com/sonr-io/sonr/internal/blockchain/x/channel/keeper"
	"github.com/sonr-io/sonr/internal/blockchain/x/channel/types"
)

func SimulateMsgCreateChannel(
	ak types.AccountKeeper,
	bk types.BankKeeper,
	k keeper.Keeper,
) simtypes.Operation {
	return func(r *rand.Rand, app *baseapp.BaseApp, ctx sdk.Context, accs []simtypes.Account, chainID string,
	) (simtypes.OperationMsg, []simtypes.FutureOperation, error) {
		simAccount, _ := simtypes.RandomAcc(r, accs)
		msg := &types.MsgCreateChannel{
			Creator: simAccount.Address.String(),
		}

		// TODO: Handling the CreateChannel simulation

		return simtypes.NoOpMsg(types.ModuleName, msg.Type(), "CreateChannel simulation not implemented"), nil, nil
	}
}
