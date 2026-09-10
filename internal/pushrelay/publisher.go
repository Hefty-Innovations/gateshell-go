package pushrelay

import (
	"context"
	"errors"
	"fmt"
)

// Publisher adapts a Client into an alerts.Publisher (structurally --
// this package does not import internal/alerts to avoid a needless
// dependency; its Publish signature already matches alerts.Publisher).
type Publisher struct {
	client     *Client
	serverName string
	allFn      func() []Registration
	removeFn   func(token string) error
	findFn     func(token string) (Registration, bool)
}

// NewPublisher builds a Publisher that titles every notification with
// serverName and sends to every device allFn currently returns (typically
// TokenStore.All) -- looked up fresh on every publish, since the relay is
// stateless and needs the tokens on each call.
//
// removeFn is called for a device APNs reports as permanently gone, so a
// deleted app's token stops costing a delivery attempt on every alert.
func NewPublisher(
	client *Client,
	serverName string,
	allFn func() []Registration,
	removeFn func(token string) error,
	findFn func(token string) (Registration, bool),
) *Publisher {
	return &Publisher{
		client: client, serverName: serverName,
		allFn: allFn, removeFn: removeFn, findFn: findFn,
	}
}

// SendTest delivers a message to one registered device. "Send Test Alert"
// is a per-device check -- tapping it on a Mac should prove that Mac can
// receive -- so it must not fan out, and it must report the real reason it
// failed rather than a bare success.
func (p *Publisher) SendTest(ctx context.Context, deviceToken, message string) error {
	if p.findFn == nil {
		return errors.New("pushrelay: cannot look up devices")
	}
	registration, ok := p.findFn(deviceToken)
	if !ok {
		return errors.New("pushrelay: this device is not registered with the agent")
	}
	err := p.client.Send(ctx, registration.Token, registration.Environment, p.serverName, message)
	if errors.Is(err, ErrTokenUnregistered) {
		if p.removeFn != nil {
			_ = p.removeFn(registration.Token)
		}
		return fmt.Errorf("Apple rejected %s's push token as no longer valid; it has been removed. Re-open GateShell on that device to register again", registration.DisplayLabel())
	}
	if err != nil {
		return fmt.Errorf("delivering to %s failed: %w", registration.DisplayLabel(), err)
	}
	return nil
}

func (p *Publisher) Publish(ctx context.Context, message string) error {
	registrations := p.allFn()
	if len(registrations) == 0 {
		return errors.New("pushrelay: no device token registered")
	}

	// Every device gets its own attempt: one dead or unreachable device
	// must not suppress delivery to the others, which is what a single
	// early return would do.
	var errs []error
	for _, r := range registrations {
		err := p.client.Send(ctx, r.Token, r.Environment, p.serverName, message)
		switch {
		case err == nil:
		case errors.Is(err, ErrTokenUnregistered):
			// Reported, not silent: dropping a device while telling the
			// caller "sent" is how a device can stop receiving alerts with
			// nothing anywhere to explain it.
			if p.removeFn != nil {
				_ = p.removeFn(r.Token)
			}
			errs = append(errs, fmt.Errorf("%s is no longer reachable and was unregistered", r.DisplayLabel()))
		default:
			errs = append(errs, fmt.Errorf("%s: %w", r.DisplayLabel(), err))
		}
	}
	return errors.Join(errs...)
}
