package ckks_cipher

import (
	"math"
	"testing"
)

func TestCloneSymmetricKeyDoesNotAliasInput(t *testing.T) {
	key := []uint8{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	cloned := cloneSymmetricKey(key)

	if len(cloned) != len(key) {
		t.Fatalf("clone length mismatch: got=%d want=%d", len(cloned), len(key))
	}
	if &cloned[0] == &key[0] {
		t.Fatal("cloneSymmetricKey should allocate a distinct backing array")
	}

	key[0] = 99
	if cloned[0] == key[0] {
		t.Fatalf("clone changed after mutating source: got cloned[0]=%d", cloned[0])
	}

	cloned[1] = 88
	if key[1] == cloned[1] {
		t.Fatalf("source changed after mutating clone: got key[1]=%d", key[1])
	}
}

func TestFXORWritesIntoReceiver(t *testing.T) {
	tc := newMod2TestContext(t)
	ctOut := tc.encryptConst(t, 9)

	FXOR(tc.eval, tc.encryptConst(t, 2), tc.encryptConst(t, 3), ctOut)

	if got, want := tc.decodeSlot0(t, ctOut), 5.0; math.Abs(got-want) > 1e-5 {
		t.Fatalf("FXOR receiver=%g, want %g", got, want)
	}
}
