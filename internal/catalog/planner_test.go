package catalog

import (
	"testing"
)

func snapshot(name string, members ...Member) *Catalog {
	catalog := &Catalog{Name: normalizeName(name), Members: make(map[string]Member)}
	for _, member := range members {
		member.Zone = normalizeName(member.Zone)
		catalog.Members[member.Zone] = member
	}
	return catalog
}

func TestPlanAddsByCatalogPrecedenceAndReportsClash(t *testing.T) {
	next := map[string]*Catalog{
		"a.example.": snapshot(
			"a.example.",
			Member{Zone: "alpha.example.", Label: "a1"},
			Member{Zone: "beta.example.", Label: "a2"},
		),
		"b.example.": snapshot(
			"b.example.",
			Member{Zone: "alpha.example.", Label: "b1"},
		),
	}
	actions, err := Plan(nil, next, nil, []string{"a.example.", "b.example."}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 3 ||
		actions[0].Kind != ActionAdd || actions[0].Zone != "alpha.example." ||
		actions[1].Kind != ActionAdd || actions[1].Zone != "beta.example." ||
		actions[2].Kind != ActionConflict || actions[2].Catalog != "b.example." {
		t.Fatalf("actions=%+v", actions)
	}
}

func TestPlanOnlyOwningCatalogCanRemove(t *testing.T) {
	previous := map[string]*Catalog{
		"a.example.": snapshot("a.example.", Member{Zone: "alpha.example.", Label: "a1"}),
	}
	next := map[string]*Catalog{
		"a.example.": snapshot("a.example."),
		"b.example.": snapshot("b.example.", Member{Zone: "alpha.example.", Label: "b1"}),
	}
	actions, err := Plan(previous, next, map[string]Ownership{
		"alpha.example.": {Catalog: "a.example.", Label: "a1"},
	}, []string{"a.example.", "b.example."}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 2 ||
		actions[0].Kind != ActionRemove ||
		actions[1].Kind != ActionConflict {
		t.Fatalf("actions=%+v", actions)
	}
}

func TestPlanLabelChangeRecreatesAndResetsState(t *testing.T) {
	previous := map[string]*Catalog{
		"a.example.": snapshot("a.example.", Member{Zone: "alpha.example.", Label: "old"}),
	}
	next := map[string]*Catalog{
		"a.example.": snapshot("a.example.", Member{Zone: "alpha.example.", Label: "new"}),
	}
	actions, err := Plan(previous, next, map[string]Ownership{
		"alpha.example.": {Catalog: "a.example.", Label: "old"},
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 ||
		actions[0].Kind != ActionRecreate ||
		!actions[0].ResetState ||
		actions[0].PreviousLabel != "old" ||
		actions[0].Label != "new" {
		t.Fatalf("actions=%+v", actions)
	}
}

func TestPlanReconfiguresChangedProperties(t *testing.T) {
	previous := map[string]*Catalog{
		"a.example.": snapshot("a.example.", Member{
			Zone: "alpha.example.", Label: "a1", Groups: []TXTValue{{Strings: []string{"old"}}},
		}),
	}
	next := map[string]*Catalog{
		"a.example.": snapshot("a.example.", Member{
			Zone: "alpha.example.", Label: "a1", Groups: []TXTValue{{Strings: []string{"new"}}},
		}),
	}
	actions, err := Plan(previous, next, map[string]Ownership{
		"alpha.example.": {Catalog: "a.example.", Label: "a1"},
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 || actions[0].Kind != ActionReconfigure || actions[0].ResetState {
		t.Fatalf("actions=%+v", actions)
	}
}

func TestPlanTransfersOwnershipOnlyWithLiveCOOAndDestinationMember(t *testing.T) {
	previous := map[string]*Catalog{
		"a.example.": snapshot("a.example.", Member{Zone: "alpha.example.", Label: "old"}),
	}
	next := map[string]*Catalog{
		"a.example.": snapshot("a.example.", Member{
			Zone: "alpha.example.", Label: "old", ChangeOfOwnership: "b.example.",
		}),
		"b.example.": snapshot("b.example.", Member{Zone: "alpha.example.", Label: "new"}),
	}
	actions, err := Plan(previous, next, map[string]Ownership{
		"alpha.example.": {Catalog: "a.example.", Label: "old"},
	}, []string{"a.example.", "b.example."}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 ||
		actions[0].Kind != ActionTransferOwnership ||
		actions[0].FromCatalog != "a.example." ||
		actions[0].Catalog != "b.example." ||
		!actions[0].ResetState {
		t.Fatalf("actions=%+v", actions)
	}
}

func TestPlanTransferredOwnershipIsIdempotentWhileCOORemains(t *testing.T) {
	catalogs := map[string]*Catalog{
		"a.example.": snapshot("a.example.", Member{
			Zone: "alpha.example.", Label: "old", ChangeOfOwnership: "b.example.",
		}),
		"b.example.": snapshot("b.example.", Member{Zone: "alpha.example.", Label: "new"}),
	}
	actions, err := Plan(catalogs, catalogs, map[string]Ownership{
		"alpha.example.": {Catalog: "b.example.", Label: "new"},
	}, []string{"a.example.", "b.example."}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 0 {
		t.Fatalf("actions=%+v, want idempotent post-transfer state", actions)
	}
}

func TestPlanCOOChangeAloneDoesNotReconfigureMember(t *testing.T) {
	previous := map[string]*Catalog{
		"a.example.": snapshot("a.example.", Member{Zone: "alpha.example.", Label: "a1"}),
	}
	next := map[string]*Catalog{
		"a.example.": snapshot("a.example.", Member{
			Zone: "alpha.example.", Label: "a1", ChangeOfOwnership: "missing.example.",
		}),
	}
	actions, err := Plan(previous, next, map[string]Ownership{
		"alpha.example.": {Catalog: "a.example.", Label: "a1"},
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 0 {
		t.Fatalf("actions=%+v, COO metadata alone must not reprovision the member", actions)
	}
}

func TestPlanRejectsOwnershipStealWithoutCOO(t *testing.T) {
	previous := map[string]*Catalog{
		"a.example.": snapshot("a.example.", Member{Zone: "alpha.example.", Label: "a1"}),
	}
	next := map[string]*Catalog{
		"a.example.": snapshot("a.example.", Member{Zone: "alpha.example.", Label: "a1"}),
		"b.example.": snapshot("b.example.", Member{Zone: "alpha.example.", Label: "b1"}),
	}
	actions, err := Plan(previous, next, map[string]Ownership{
		"alpha.example.": {Catalog: "a.example.", Label: "a1"},
	}, []string{"a.example.", "b.example."}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 ||
		actions[0].Kind != ActionConflict ||
		actions[0].Catalog != "b.example." {
		t.Fatalf("actions=%+v", actions)
	}
}

func TestPlanRejectsDuplicateCatalogOrder(t *testing.T) {
	_, err := Plan(nil, map[string]*Catalog{
		"a.example.": snapshot("a.example."),
	}, nil, []string{"a.example.", "A.EXAMPLE."}, nil)
	if err == nil {
		t.Fatal("Plan accepted duplicate normalized catalog order")
	}
}

func TestPlanTreatsOperatorConfiguredZoneAsClash(t *testing.T) {
	next := map[string]*Catalog{
		"a.example.": snapshot("a.example.", Member{Zone: "static.example.", Label: "a1"}),
	}
	actions, err := Plan(nil, next, nil, nil, []string{"STATIC.EXAMPLE."})
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 ||
		actions[0].Kind != ActionConflict ||
		actions[0].Zone != "static.example." {
		t.Fatalf("actions=%+v", actions)
	}
}

func TestPlanRejectsContradictoryReservedOwnership(t *testing.T) {
	_, err := Plan(nil, nil, map[string]Ownership{
		"alpha.example.": {Catalog: "a.example.", Label: "a1"},
	}, nil, []string{"alpha.example."})
	if err == nil {
		t.Fatal("Plan accepted a zone as both catalog-owned and reserved")
	}
}
