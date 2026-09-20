package tolkabi

import (
	"errors"

	"github.com/xssnick/tonutils-go/tvm/cell"
)

// DecodeOpaqueBOC parses a bounded, complete single-root BOC, including standard
// library references, pruned branches, Merkle proofs and Merkle updates. It does
// not resolve libraries or establish trust in a proof's claimed root hash.
//
// The payload is bounded before it is parsed and the cell count before any cell
// is built, so an untrusted BOC cannot buy more work than these limits allow.
// Everything below that — descriptors, exotic payloads, level masks and the
// hashes and depths a BOC may serialize alongside its cells — is checked by the
// parser itself, which is why this function is a set of limits and not a reader.
func DecodeOpaqueBOC(text string) (out *cell.Cell, err error) {
	defer catchPanic(&err)
	if len(text) > (MaxBOCBytes+2)/3*4 {
		return nil, errors.New("BOC data limit exceeded")
	}
	b, err := decodeBase64(text)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxBOCBytes {
		return nil, errors.New("BOC data limit exceeded")
	}
	root, err := cell.FromBOCWithOptions(b, cell.BOCParseOptions{MaxCells: MaxCells})
	if err != nil {
		return nil, err
	}
	// A deep DAG is cheap to serialize and expensive to decode, and an ABI needs
	// nothing near the depth a BOC may carry, so the bound here is ours and not
	// the format's. Pruned branches raise the depth a cell claims at a level
	// above zero, so every level is checked rather than the ordinary one.
	for level := 0; level <= 3; level++ {
		if root.Depth(level) > MaxDepth {
			return nil, errors.New("BOC depth limit exceeded")
		}
	}
	if err := checkLibraryLevels(root); err != nil {
		return nil, err
	}
	return root, nil
}

// The parser validates every exotic cell it builds but one case: a library
// reference must be level 0, and its level mask is not checked against that.
// Depth is already bounded above, so this walk is bounded by MaxCells alone.
// Delete it once tonutils checks the mask, as it does for the other three kinds.
func checkLibraryLevels(root *cell.Cell) error {
	seen := map[*cell.Cell]bool{}
	var visit func(*cell.Cell) error
	visit = func(c *cell.Cell) error {
		if seen[c] {
			return nil
		}
		seen[c] = true
		if len(seen) > MaxCells {
			return errors.New("BOC cell limit exceeded")
		}
		if c.IsSpecial() && c.GetType() == cell.LibraryCellType && c.LevelMask().Mask != 0 {
			return errors.New("library reference must be level 0")
		}
		for i := 0; i < int(c.RefsNum()); i++ {
			r, err := c.PeekRef(i)
			if err != nil {
				return err
			}
			if err := visit(r); err != nil {
				return err
			}
		}
		return nil
	}
	return visit(root)
}
