package storage

import "github.com/george-593/ssh-honeypot/internal/event"

type Storage interface {
	Store(e event.Event) error
	Close() error
}
