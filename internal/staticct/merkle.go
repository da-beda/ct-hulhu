package staticct

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/bits"
)

const maxHashTileLevel = 5

type merkleHash [sha256.Size]byte

func hashEmpty() merkleHash {
	return sha256.Sum256(nil)
}

func hashLeaf(leaf []byte) merkleHash {
	input := make([]byte, 1+len(leaf))
	input[0] = 0
	copy(input[1:], leaf)
	return sha256.Sum256(input)
}

func hashChildren(left, right merkleHash) merkleHash {
	var input [1 + 2*sha256.Size]byte
	input[0] = 1
	copy(input[1:1+sha256.Size], left[:])
	copy(input[1+sha256.Size:], right[:])
	return sha256.Sum256(input[:])
}

func hashTilePath(level int, index uint64, width int) (string, error) {
	if level < 0 || level > maxHashTileLevel {
		return "", fmt.Errorf("invalid hash tile level %d", level)
	}
	if width < 1 || width > tileWidth {
		return "", fmt.Errorf("invalid hash tile width %d", width)
	}
	path := fmt.Sprintf("tile/%d/%s", level, tileIndexPath(index))
	if width < tileWidth {
		path += fmt.Sprintf(".p/%d", width)
	}
	return path, nil
}

func staticLevelHashCount(treeSize int64, level int) (uint64, error) {
	if treeSize < 0 {
		return 0, fmt.Errorf("negative tree size %d", treeSize)
	}
	if level < 0 || level > maxHashTileLevel {
		return 0, fmt.Errorf("invalid hash tile level %d", level)
	}
	shift := uint(level * 8)
	return uint64(treeSize) >> shift, nil
}

func (c *Client) getHashTile(ctx context.Context, level int, tileIndex uint64, width int) ([]merkleHash, error) {
	path, err := hashTilePath(level, tileIndex, width)
	if err != nil {
		return nil, err
	}
	body, err := c.getCached(ctx, path)
	if err != nil && width < tileWidth {
		// Once a partial tile becomes full, a log may stop serving the old
		// partial URL. Full tiles are immutable and their prefix is equivalent.
		fullPath, pathErr := hashTilePath(level, tileIndex, tileWidth)
		if pathErr != nil {
			return nil, pathErr
		}
		fullBody, fullErr := c.getCached(ctx, fullPath)
		if fullErr != nil {
			return nil, fmt.Errorf("partial tile %s unavailable (%v); full fallback failed: %w", path, err, fullErr)
		}
		body = fullBody
	}
	if err != nil && body == nil {
		return nil, err
	}
	if len(body)%sha256.Size != 0 {
		return nil, fmt.Errorf("hash tile %s has %d bytes, not a multiple of %d", path, len(body), sha256.Size)
	}
	hashCount := len(body) / sha256.Size
	if width == tileWidth {
		if hashCount != tileWidth {
			return nil, fmt.Errorf("full hash tile %s contains %d hashes, want %d", path, hashCount, tileWidth)
		}
	} else if hashCount < width {
		return nil, fmt.Errorf("hash tile %s contains %d hashes, need at least %d", path, hashCount, width)
	}
	hashes := make([]merkleHash, width)
	for i := 0; i < width; i++ {
		copy(hashes[i][:], body[i*sha256.Size:(i+1)*sha256.Size])
	}
	return hashes, nil
}

func (c *Client) nodeHash(ctx context.Context, height int, nodeIndex uint64, treeSize int64) (merkleHash, error) {
	if height < 0 || height > 40 {
		return merkleHash{}, fmt.Errorf("invalid Merkle node height %d", height)
	}
	level := height / 8
	remainder := uint(height % 8)
	totalHashes, err := staticLevelHashCount(treeSize, level)
	if err != nil {
		return merkleHash{}, err
	}
	count := uint64(1) << remainder
	if nodeIndex > ^uint64(0)/count {
		return merkleHash{}, fmt.Errorf("Merkle node index overflow")
	}
	base := nodeIndex * count
	if base+count > totalHashes {
		return merkleHash{}, fmt.Errorf("Merkle node h=%d index=%d exceeds tree size %d", height, nodeIndex, treeSize)
	}
	tileIndex := base / tileWidth
	offset := int(base % tileWidth)
	tileStart := tileIndex * tileWidth
	remaining := totalHashes - tileStart
	width := tileWidth
	if remaining < tileWidth {
		width = int(remaining)
	}
	if offset+int(count) > width {
		return merkleHash{}, fmt.Errorf("Merkle node crosses unavailable hash-tile boundary")
	}
	hashes, err := c.getHashTile(ctx, level, tileIndex, width)
	if err != nil {
		return merkleHash{}, err
	}
	work := append([]merkleHash(nil), hashes[offset:offset+int(count)]...)
	for len(work) > 1 {
		next := make([]merkleHash, 0, len(work)/2)
		for i := 0; i < len(work); i += 2 {
			next = append(next, hashChildren(work[i], work[i+1]))
		}
		work = next
	}
	return work[0], nil
}

func isPowerOfTwo(v int64) bool {
	return v > 0 && (v&(v-1)) == 0
}

func largestPowerOfTwoLessThan(v int64) int64 {
	if v <= 1 {
		return 0
	}
	return int64(1) << (bits.Len64(uint64(v-1)) - 1)
}

func (c *Client) rangeRoot(ctx context.Context, start, count, treeSize int64) (merkleHash, error) {
	if start < 0 || count < 0 || start > treeSize || count > treeSize-start {
		return merkleHash{}, fmt.Errorf("invalid Merkle range start=%d count=%d tree=%d", start, count, treeSize)
	}
	if count == 0 {
		return hashEmpty(), nil
	}
	if isPowerOfTwo(count) && start%count == 0 {
		height := bits.TrailingZeros64(uint64(count))
		return c.nodeHash(ctx, height, uint64(start/count), treeSize)
	}
	leftCount := largestPowerOfTwoLessThan(count)
	if leftCount == 0 {
		return merkleHash{}, fmt.Errorf("cannot split Merkle range of %d", count)
	}
	left, err := c.rangeRoot(ctx, start, leftCount, treeSize)
	if err != nil {
		return merkleHash{}, err
	}
	right, err := c.rangeRoot(ctx, start+leftCount, count-leftCount, treeSize)
	if err != nil {
		return merkleHash{}, err
	}
	return hashChildren(left, right), nil
}

func (c *Client) rootWithLeaf(ctx context.Context, start, count, target int64, leaf merkleHash, treeSize int64) (merkleHash, error) {
	if count <= 0 || target < start || target >= start+count {
		return merkleHash{}, fmt.Errorf("target %d outside Merkle range [%d,%d)", target, start, start+count)
	}
	if count == 1 {
		return leaf, nil
	}
	leftCount := largestPowerOfTwoLessThan(count)
	if leftCount == 0 {
		return merkleHash{}, fmt.Errorf("cannot split Merkle range of %d", count)
	}
	if target < start+leftCount {
		left, err := c.rootWithLeaf(ctx, start, leftCount, target, leaf, treeSize)
		if err != nil {
			return merkleHash{}, err
		}
		right, err := c.rangeRoot(ctx, start+leftCount, count-leftCount, treeSize)
		if err != nil {
			return merkleHash{}, err
		}
		return hashChildren(left, right), nil
	}
	left, err := c.rangeRoot(ctx, start, leftCount, treeSize)
	if err != nil {
		return merkleHash{}, err
	}
	right, err := c.rootWithLeaf(ctx, start+leftCount, count-leftCount, target, leaf, treeSize)
	if err != nil {
		return merkleHash{}, err
	}
	return hashChildren(left, right), nil
}

func decodedLeafHash(entry string) (merkleHash, error) {
	leaf, err := base64.StdEncoding.DecodeString(entry)
	if err != nil {
		return merkleHash{}, fmt.Errorf("decoding leaf input: %w", err)
	}
	return hashLeaf(leaf), nil
}
