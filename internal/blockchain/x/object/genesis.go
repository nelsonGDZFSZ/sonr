package object

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/sonr-io/sonr/internal/blockchain/x/object/keeper"
	"github.com/sonr-io/sonr/internal/blockchain/x/object/types"
)

// InitGenesis initializes the capability module's state from a provided genesis
// state.
func InitGenesis(ctx sdk.Context, k keeper.Keeper, genState types.GenesisState) {
	// Set all the whatIs
	for _, elem := range genState.WhatIsList {
		k.SetWhatIs(ctx, elem)
	}
	// this line is used by starport scaffolding # genesis/module/init
	k.SetParams(ctx, genState.Params)
}

// ExportGenesis returns the capability module's exported genesis.
func ExportGenesis(ctx sdk.Context, k keeper.Keeper) *types.GenesisState {
	genesis := types.DefaultGenesis()
	genesis.Params = k.GetParams(ctx)

	genesis.WhatIsList = k.GetAllWhatIs(ctx)
	// this line is used by starport scaffolding # genesis/module/export

	return genesis
}
