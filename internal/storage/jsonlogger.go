package storage

import (
	"encoding/json"
	"os"
	"sync"

	"github.com/george-593/ssh-honeypot/internal/event"
)

type JSONLogger struct {
	mu  sync.Mutex
	f   *os.File
	enc *json.Encoder
}

func NewJSONLogger(path string) (*JSONLogger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}

	return &JSONLogger{
		f:   f,
		enc: json.NewEncoder(f),
	}, nil
}

func (j *JSONLogger) Store(e event.Event) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.enc.Encode(e)
}

func (j *JSONLogger) Close() error {
	err := j.f.Close()
	return err
}
