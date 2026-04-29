package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// LegalDocument stores the current and historical versions of platform legal documents.
// Covered types: EPA (Equity Participation Agreement), MSA (Master Services Agreement),
// DPA (Data Processing Agreement) — governed by Kenya Companies Act 2015 and DPA 2019.
type LegalDocument struct {
	ent.Schema
}

func (LegalDocument) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),

		field.Enum("doc_type").
			Values("EPA", "MSA", "DPA").
			Comment("Document type: EPA=Equity Participation Agreement, MSA=Master Services Agreement, DPA=Data Processing Agreement"),

		field.String("version").
			NotEmpty().
			MaxLen(32).
			Comment("Version string e.g. v1.0, v2.1"),

		field.Text("html_content").
			Comment("Full document body as HTML (rendered in portal)"),

		field.Time("effective_date").
			Comment("Date from which this version takes effect"),

		field.Bool("is_current").
			Default(false).
			Comment("Only one document per doc_type may be current; set via update, not create"),

		field.Time("created_at").
			Immutable().
			Default(time.Now),
	}
}

func (LegalDocument) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("doc_type", "version").Unique(),
		index.Fields("doc_type", "is_current"),
	}
}
