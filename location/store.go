// Package location provides a store for named map locations and nearest-neighbour lookup.
package location

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
)

// Location is a named point in the game world.
type Location struct {
	Name  string  `json:"name"`
	MapID uint32  `json:"mapId"`
	X     float64 `json:"x"`
	Y     float64 `json:"y"`
	Z     float64 `json:"z"`
}

// Vec3 is a 3D coordinate used for distance queries.
type Vec3 struct {
	X, Y, Z float32
}

// Store holds all known game locations.
type Store struct {
	locations []Location
}

// Count returns the number of loaded locations.
func (s *Store) Count() int {
	if s == nil {
		return 0
	}
	return len(s.locations)
}

// Load reads a JSON array of Location objects from path.
// Returns an error if the file exists but cannot be parsed.
func Load(path string) (*Store, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read locations %s: %w", path, err)
	}
	var items []Location
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, fmt.Errorf("parse locations: %w", err)
	}
	return &Store{locations: items}, nil
}

// Nearest returns the closest location to pos for the given mapID.
// If mapID is 0, all maps are searched. Returns ok=false when no match.
func (s *Store) Nearest(mapID uint32, pos Vec3) (Location, bool) {
	if s == nil || len(s.locations) == 0 {
		return Location{}, false
	}
	best := Location{}
	bestDist := math.MaxFloat64
	for _, loc := range s.locations {
		if mapID != 0 && loc.MapID != 0 && loc.MapID != mapID {
			continue
		}
		dx := float64(pos.X) - loc.X
		dy := float64(pos.Y) - loc.Y
		dz := float64(pos.Z) - loc.Z
		d := math.Sqrt(dx*dx + dy*dy + dz*dz)
		if d < bestDist {
			bestDist = d
			best = loc
		}
	}
	if bestDist == math.MaxFloat64 {
		return Location{}, false
	}
	return best, true
}
