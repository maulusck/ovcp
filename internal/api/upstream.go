package api

import (
	"net/http"

	"github.com/ovcp/ovcp/internal/store"
	"github.com/ovcp/ovcp/internal/upstream"
)

const upstreamConfigKey = "upstream_config"

func LoadUpstreamConfig(s *store.Store) upstream.Config {
	return store.LoadJSON(s, upstreamConfigKey, upstream.Config{})
}

func SaveUpstreamConfig(s *store.Store, cfg upstream.Config) error {
	return store.SaveJSON(s, upstreamConfigKey, cfg)
}

// applyUpstreams re-programs routing/NAT from cfg — a no-op when disabled.
// upstream.Apply serializes every caller within this process itself, so
// there's nothing to guard here.
func (s *Server) applyUpstreams(cfg upstream.Config) error {
	if !s.UpstreamsEnabled {
		return nil
	}
	return upstream.Apply(cfg, s.LoadConfig().Subnet)
}

func (s *Server) handleUpstreamsGet(w http.ResponseWriter, r *http.Request, u *store.User) {
	jsonOK(w, LoadUpstreamConfig(s.Store))
}

func (s *Server) handleUpstreamAdd(w http.ResponseWriter, r *http.Request, u *store.User) {
	if !s.UpstreamsEnabled {
		jsonErr(w, 400, "upstreams disabled: nftables not found or turned off")
		return
	}
	var in struct{ ID, Iface, Gateway, Description string }
	if !decode(r, &in) || in.ID == "" || in.Iface == "" {
		jsonErr(w, 400, "id and iface required")
		return
	}
	cfg, _, err := LoadUpstreamConfig(s.Store).WithAdded(upstream.Upstream{
		ID: in.ID, Iface: in.Iface, Gateway: in.Gateway, Description: in.Description,
	})
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	if err := SaveUpstreamConfig(s.Store, cfg); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	if err := s.applyUpstreams(cfg); err != nil {
		jsonErr(w, opStatus(err), err.Error())
		return
	}
	s.Store.Audit(u.Username, "upstream_add", in.ID)
	jsonOK(w, cfg)
}

func (s *Server) handleUpstreamDelete(w http.ResponseWriter, r *http.Request, u *store.User) {
	id := r.PathValue("id")
	cfg, found := LoadUpstreamConfig(s.Store).Without(id)
	if !found {
		jsonErr(w, 404, "upstream not found")
		return
	}
	if err := SaveUpstreamConfig(s.Store, cfg); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	if err := s.applyUpstreams(cfg); err != nil {
		jsonErr(w, opStatus(err), err.Error())
		return
	}
	s.Store.Audit(u.Username, "upstream_del", id)
	jsonOK(w, cfg)
}

// handleUpstreamSetDefault: the ad-hoc exit switch — id="" turns it off,
// back to the host's own default route.
func (s *Server) handleUpstreamSetDefault(w http.ResponseWriter, r *http.Request, u *store.User) {
	var in struct{ ID string }
	if !decode(r, &in) {
		jsonErr(w, 400, "bad json")
		return
	}
	cfg := LoadUpstreamConfig(s.Store)
	cfg.Default = in.ID
	if err := cfg.Validate(); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	if err := SaveUpstreamConfig(s.Store, cfg); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	if err := s.applyUpstreams(cfg); err != nil {
		jsonErr(w, opStatus(err), err.Error())
		return
	}
	action := "upstream_default_set"
	if in.ID == "" {
		action = "upstream_default_off"
	}
	s.Store.Audit(u.Username, action, in.ID)
	jsonOK(w, cfg)
}
