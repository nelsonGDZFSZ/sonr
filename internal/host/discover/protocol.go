package discover

import (
	"context"

	"github.com/kataras/golog"
	"github.com/pkg/errors"
	ct "github.com/sonr-io/sonr/internal/blockchain/x/channel/types"
	host "github.com/sonr-io/sonr/internal/host"
	"github.com/sonr-io/sonr/pkg/config"
	device "github.com/sonr-io/sonr/pkg/fs"
	types "go.buf.build/grpc/go/sonr-io/core/types/v1"
)

var (
	logger             = golog.Child("protocols/discover")
	ErrParameters      = errors.New("Failed to create new ExchangeProtocol, invalid parameters")
	ErrInvalidPeer     = errors.New("Peer object provided to ExchangeProtocol is Nil")
	ErrTopicNotCreated = errors.New("Lobby Topic has not been Created")
)

// DiscoverProtocol handles Global and Local Sonr Peer Exchange Protocol
type DiscoverProtocol struct {
	node     host.SonrHost
	callback config.MotorCallback
	ctx      context.Context
	global   ct.Channel
	local    *Local
	mode     device.Role
}

// New creates new DiscoveryProtocol
func New(ctx context.Context, host host.SonrHost, cb config.MotorCallback, options ...Option) (*DiscoverProtocol, error) {
	// Create BeamStore
	b, err := ct.NewChannel(ctx, host, &ct.ChannelDoc{
		Label: "_discover",
		Did:   "did:snr:discover",
	})
	if err != nil {
		return nil, err
	}

	// Create Exchange Protocol
	protocol := &DiscoverProtocol{
		ctx:      ctx,
		global:   b,
		node:     host,
		callback: cb,
	}

	// Set options
	opts := defaultOptions()
	for _, opt := range options {
		opt(opts)
	}
	opts.Apply(protocol)
	logger.Debug("✅  ExchangeProtocol is Activated \n")
	return protocol, nil
}

// FindPeerId method returns PeerID by SName
func (p *DiscoverProtocol) Get(sname string) (*types.Peer, error) {
	// peer := &types.Peer{}
	// Get Peer from KadDHT store
	// if buf, err := p.global.Get(sname); err == nil {
	// 	// Unmarshal Peer
	// 	err := proto.Unmarshal(buf, peer)
	// 	if err != nil {
	// 		logger.Errorf("%s - Failed to unmarshal Peer", err)
	// 		return nil, err
	// 	}
	// 	return peer, nil
	// } else {
	// 	logger.Warn("Failed to get Peer from BeamStore: %s", err)
	// 	return nil, err
	// }
	return nil, errors.New("Unimplemented method 'Get'")
}

// Put method updates peer instance in the store
func (p *DiscoverProtocol) Put(peer *types.Peer) error {
	// logger.Debug("Updating Peer in BeamStore")
	// // Marshal Peer
	// buf, err := proto.Marshal(peer)
	// if err != nil {
	// 	logger.Errorf("Failed to Marshal Peer: %s", err)
	// 	return err
	// }

	// // Add Peer to KadDHT store
	// err = p.global.Put(peer.GetSName(), buf)
	// if err != nil {
	// 	logger.Errorf("Failed to put item in BeamStore: %s", err)
	// 	return err
	// }
	return errors.New("Unimplemented method 'Put'")
}

// Update method publishes peer data to the topic
func (p *DiscoverProtocol) Update() error {
	if p.mode.IsMotor() {
		// Verify Peer is not nil
		peer, err := p.node.Peer()
		if err != nil {
			return err
		}

		// Publish Event
		err = p.local.Publish(peer)
		if err != nil {
			return err
		}
	}
	return nil
}

// Close method closes the ExchangeProtocol
func (p *DiscoverProtocol) Close() error {
	p.local.eventHandler.Cancel()
	p.local.subscription.Cancel()
	err := p.local.topic.Close()
	if err != nil {
		logger.Errorf("%s - Failed to Close Local Lobby Topic for Exchange", err)
	}
	return nil
}
