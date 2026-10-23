// Package legacyimport provides read-only local inspection, never legacy activation.
package legacyimport

import (
	"gopkg.in/yaml.v3"
	"io"
)

type Resource struct {
	Kind      string   `json:"kind"`
	Name      string   `json:"name"`
	Namespace string   `json:"namespace,omitempty"`
	Images    []string `json:"images,omitempty"`
	Mounts    []string `json:"mounts,omitempty"`
	Claims    []string `json:"claims,omitempty"`
	Storage   string   `json:"storage,omitempty"`
}

// Inspect emits an allowlist only. Environment values, config data and secrets are omitted.
func Inspect(r io.Reader) ([]Resource, error) {
	dec := yaml.NewDecoder(r)
	var out []Resource
	for {
		var doc struct {
			Kind     string `yaml:"kind"`
			Metadata struct {
				Name      string `yaml:"name"`
				Namespace string `yaml:"namespace"`
			} `yaml:"metadata"`
			Spec struct {
				Resources struct {
					Requests struct {
						Storage string `yaml:"storage"`
					} `yaml:"requests"`
				} `yaml:"resources"`
				Template struct {
					Spec struct {
						Containers []struct {
							Image  string `yaml:"image"`
							Mounts []struct {
								Path string `yaml:"mountPath"`
							} `yaml:"volumeMounts"`
						} `yaml:"containers"`
						Volumes []struct {
							PVC struct {
								Claim string `yaml:"claimName"`
							} `yaml:"persistentVolumeClaim"`
						} `yaml:"volumes"`
					} `yaml:"spec"`
				} `yaml:"template"`
			} `yaml:"spec"`
		}
		e := dec.Decode(&doc)
		if e == io.EOF {
			return out, nil
		}
		if e != nil {
			return nil, e
		}
		if doc.Kind == "" {
			continue
		}
		v := Resource{Kind: doc.Kind, Name: doc.Metadata.Name, Namespace: doc.Metadata.Namespace, Storage: doc.Spec.Resources.Requests.Storage}
		for _, c := range doc.Spec.Template.Spec.Containers {
			v.Images = append(v.Images, c.Image)
			for _, m := range c.Mounts {
				v.Mounts = append(v.Mounts, m.Path)
			}
		}
		for _, vol := range doc.Spec.Template.Spec.Volumes {
			if vol.PVC.Claim != "" {
				v.Claims = append(v.Claims, vol.PVC.Claim)
			}
		}
		out = append(out, v)
	}
}
