package catalog

import (
	"fmt"
	"sort"

	"github.com/miekg/dns"
)

// Ownership records which catalog created and therefore may remove a zone.
type Ownership struct {
	Catalog string
	Label   string
}

type ActionKind string

const (
	ActionAdd               ActionKind = "add"
	ActionRemove            ActionKind = "remove"
	ActionReconfigure       ActionKind = "reconfigure"
	ActionRecreate          ActionKind = "recreate"
	ActionTransferOwnership ActionKind = "transfer_ownership"
	ActionConflict          ActionKind = "conflict"
)

// Action is one deterministic reconciliation decision. ResetState means
// transfer and provisioning history must not be reused for the new member label.
type Action struct {
	Kind          ActionKind
	Zone          string
	Catalog       string
	FromCatalog   string
	Label         string
	PreviousLabel string
	ResetState    bool
	Reason        string
}

// Plan compares the last accepted catalogs with the newest accepted catalogs.
// catalogOrder defines clash precedence; unspecified catalogs sort after it.
func Plan(
	previous map[string]*Catalog,
	next map[string]*Catalog,
	ownership map[string]Ownership,
	catalogOrder []string,
	reservedZones []string,
) ([]Action, error) {
	previous = normalizeCatalogMap(previous)
	next = normalizeCatalogMap(next)
	ownership = normalizeOwnership(ownership)
	order, err := orderedCatalogNames(next, catalogOrder)
	if err != nil {
		return nil, err
	}
	reserved := make(map[string]bool, len(reservedZones))
	for _, zoneName := range reservedZones {
		zoneName = normalizeName(zoneName)
		if _, catalogOwned := ownership[zoneName]; catalogOwned {
			return nil, fmt.Errorf("zone %s is both catalog-owned and reserved", zoneName)
		}
		reserved[zoneName] = true
	}

	var actions []Action
	handled := make(map[string]bool)
	transferredFrom := make(map[string]string)

	// An ownership transfer is valid only while the old catalog still publishes
	// COO and the destination catalog simultaneously publishes the member.
	for _, zoneName := range sortedOwnershipZones(ownership) {
		owner := ownership[zoneName]
		oldCatalog := next[owner.Catalog]
		if oldCatalog == nil {
			continue
		}
		oldMember, stillPresent := oldCatalog.Members[zoneName]
		if !stillPresent || oldMember.ChangeOfOwnership == "" {
			continue
		}
		newCatalog := next[oldMember.ChangeOfOwnership]
		newMember, destinationPresent := memberIn(newCatalog, zoneName)
		if !destinationPresent || oldMember.ChangeOfOwnership == owner.Catalog {
			continue
		}
		actions = append(actions, Action{
			Kind:          ActionTransferOwnership,
			Zone:          zoneName,
			Catalog:       newCatalog.Name,
			FromCatalog:   owner.Catalog,
			Label:         newMember.Label,
			PreviousLabel: owner.Label,
			ResetState:    owner.Label != newMember.Label,
		})
		ownership[zoneName] = Ownership{Catalog: newCatalog.Name, Label: newMember.Label}
		transferredFrom[zoneName] = owner.Catalog
		handled[zoneName] = true
	}

	// Existing ownership is retained unless the owning catalog removes the
	// member or a valid COO transfer above moves it.
	for _, zoneName := range sortedOwnershipZones(ownership) {
		if handled[zoneName] {
			continue
		}
		owner := ownership[zoneName]
		nextCatalog := next[owner.Catalog]
		nextMember, present := memberIn(nextCatalog, zoneName)
		if !present {
			actions = append(actions, Action{
				Kind:          ActionRemove,
				Zone:          zoneName,
				FromCatalog:   owner.Catalog,
				PreviousLabel: owner.Label,
			})
			handled[zoneName] = true
			continue
		}
		previousMember, existed := memberIn(previous[owner.Catalog], zoneName)
		switch {
		case owner.Label != nextMember.Label:
			actions = append(actions, Action{
				Kind:          ActionRecreate,
				Zone:          zoneName,
				Catalog:       owner.Catalog,
				Label:         nextMember.Label,
				PreviousLabel: owner.Label,
				ResetState:    true,
			})
		case existed && !membersEqual(previousMember, nextMember):
			actions = append(actions, Action{
				Kind:          ActionReconfigure,
				Zone:          zoneName,
				Catalog:       owner.Catalog,
				Label:         nextMember.Label,
				PreviousLabel: owner.Label,
			})
		}
		handled[zoneName] = true
	}

	// Add unowned members according to configured catalog precedence. Existing
	// ownership always wins a clash; later catalogs receive an explicit conflict.
	claimed := make(map[string]string, len(ownership))
	for zoneName, owner := range ownership {
		claimed[zoneName] = owner.Catalog
	}
	for zoneName := range reserved {
		claimed[zoneName] = "operator configuration"
	}
	for _, catalogName := range order {
		catalogSnapshot := next[catalogName]
		for _, zoneName := range sortedMemberZones(catalogSnapshot) {
			member := catalogSnapshot.Members[zoneName]
			if handled[zoneName] {
				if transferredFrom[zoneName] == catalogName {
					continue
				}
				if claimedBy := claimed[zoneName]; claimedBy != "" && claimedBy != catalogName {
					if member.ChangeOfOwnership == claimedBy {
						continue
					}
					actions = append(actions, conflictAction(zoneName, catalogName, claimedBy))
				}
				continue
			}
			if claimedBy := claimed[zoneName]; claimedBy != "" {
				if claimedBy != catalogName {
					actions = append(actions, conflictAction(zoneName, catalogName, claimedBy))
				}
				continue
			}
			actions = append(actions, Action{
				Kind:    ActionAdd,
				Zone:    zoneName,
				Catalog: catalogName,
				Label:   member.Label,
			})
			claimed[zoneName] = catalogName
			handled[zoneName] = true
		}
	}

	sortActions(actions, order)
	return actions, nil
}

func conflictAction(zoneName, catalogName, claimedBy string) Action {
	return Action{
		Kind:    ActionConflict,
		Zone:    zoneName,
		Catalog: catalogName,
		Reason:  fmt.Sprintf("member already owned or claimed by catalog %s", claimedBy),
	}
}

func membersEqual(left, right Member) bool {
	return left.Zone == right.Zone &&
		left.Label == right.Label &&
		groupsEqual(left.Groups, right.Groups) &&
		extensionMapsEqual(left.Extensions, right.Extensions)
}

func groupsEqual(left, right []TXTValue) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if len(left[i].Strings) != len(right[i].Strings) {
			return false
		}
		for j := range left[i].Strings {
			if left[i].Strings[j] != right[i].Strings[j] {
				return false
			}
		}
	}
	return true
}

func extensionMapsEqual(left, right map[string][]dns.RR) bool {
	if len(left) != len(right) {
		return false
	}
	for prefix, leftRecords := range left {
		rightRecords, ok := right[prefix]
		if !ok || len(leftRecords) != len(rightRecords) {
			return false
		}
		for i := range leftRecords {
			if leftRecords[i].String() != rightRecords[i].String() {
				return false
			}
		}
	}
	return true
}

func memberIn(catalog *Catalog, zoneName string) (Member, bool) {
	if catalog == nil {
		return Member{}, false
	}
	member, ok := catalog.Members[zoneName]
	return member, ok
}

func normalizeCatalogMap(catalogs map[string]*Catalog) map[string]*Catalog {
	normalized := make(map[string]*Catalog, len(catalogs))
	for name, snapshot := range catalogs {
		if snapshot == nil {
			continue
		}
		normalizedName := normalizeName(name)
		if snapshot.Name != "" {
			normalizedName = normalizeName(snapshot.Name)
		}
		normalized[normalizedName] = snapshot
	}
	return normalized
}

func normalizeOwnership(source map[string]Ownership) map[string]Ownership {
	normalized := make(map[string]Ownership, len(source))
	for zoneName, owner := range source {
		owner.Catalog = normalizeName(owner.Catalog)
		normalized[normalizeName(zoneName)] = owner
	}
	return normalized
}

func orderedCatalogNames(catalogs map[string]*Catalog, configured []string) ([]string, error) {
	var result []string
	seen := make(map[string]bool)
	for _, name := range configured {
		name = normalizeName(name)
		if seen[name] {
			return nil, fmt.Errorf("catalog order contains duplicate %s", name)
		}
		seen[name] = true
		if catalogs[name] != nil {
			result = append(result, name)
		}
	}
	var remaining []string
	for name := range catalogs {
		if !seen[name] {
			remaining = append(remaining, name)
		}
	}
	sort.Strings(remaining)
	return append(result, remaining...), nil
}

func sortedOwnershipZones(ownership map[string]Ownership) []string {
	zones := make([]string, 0, len(ownership))
	for zoneName := range ownership {
		zones = append(zones, zoneName)
	}
	sort.Strings(zones)
	return zones
}

func sortedMemberZones(catalog *Catalog) []string {
	if catalog == nil {
		return nil
	}
	zones := make([]string, 0, len(catalog.Members))
	for zoneName := range catalog.Members {
		zones = append(zones, zoneName)
	}
	sort.Strings(zones)
	return zones
}

func sortActions(actions []Action, catalogOrder []string) {
	rank := make(map[string]int, len(catalogOrder))
	for i, name := range catalogOrder {
		rank[name] = i
	}
	kindRank := map[ActionKind]int{
		ActionTransferOwnership: 0,
		ActionRemove:            1,
		ActionRecreate:          2,
		ActionReconfigure:       3,
		ActionAdd:               4,
		ActionConflict:          5,
	}
	sort.SliceStable(actions, func(i, j int) bool {
		if kindRank[actions[i].Kind] != kindRank[actions[j].Kind] {
			return kindRank[actions[i].Kind] < kindRank[actions[j].Kind]
		}
		if actions[i].Zone != actions[j].Zone {
			return actions[i].Zone < actions[j].Zone
		}
		leftRank, leftOK := rank[actions[i].Catalog]
		rightRank, rightOK := rank[actions[j].Catalog]
		if leftOK != rightOK {
			return leftOK
		}
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		return actions[i].Catalog < actions[j].Catalog
	})
}
