package kratos

import (
	"time"
)

type KratosTraits struct {
	Email											string									`json:"email"`
	FirstName									string									`json:"firstName"`
	LastName									string									`json:"lastName"`
	Role											string									`json:"role"`
}

type KratosAddress struct {
	Id	                			string 									`json:"id"`
	Value	                		string 									`json:"value"`
	ExpirationTime            time.Time 							`json:"expires_at"`
	VerifiedTime              time.Time 							`json:"verified_at"`
  Verified  								bool										`json:"verified"`
  VerifiedVia								string									`json:"via"`
}

type KratosUser struct {
  Id												string									`json:"id"`
	SchemaId	                string 									`json:"traits_schema_id"`
	SchemaUrl	                string 									`json:"traits_schema_url"`
	Traits  									KratosTraits	 					`json:"traits"`
	Addresses									[]KratosAddress					`json:"addresses"`
}