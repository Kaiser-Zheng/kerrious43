package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256" // SECURITY: domain-separation for KDF
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
)

const (
	magicStr               = "SECFILE"  // magic header
	formatVersion          = uint8(1)   // file format version
	defaultChunkSize       = 512 * 1024 // 512 KiB
	maxFileSize      int64 = 1 << 30    // 1 GiB
	saltSize               = 32
	baseNonceSize          = 12 // ChaCha20-Poly1305 nonce size
	tagSize                = 16
	encExt                 = ".enc"
	outDirEncrypt          = "encrypted_files"
	outDirDecrypt          = "decrypted_files"

	// Argon2id parameters (defaults for encrypt)
	aTime       = uint32(4)
	aMemoryKiB  = uint32(256 * 1024) // 256 MiB in KiB
	aParallel   = uint8(4)
	derivedKeyL = uint32(32)

	// SECURITY: caps/minima for KDF params accepted from files (defense vs DoS)
	kdfMinTimeCost  = uint32(1)
	kdfMaxTimeCost  = uint32(10)
	kdfMinMemoryKiB = uint32(64 * 1024)   // 64 MiB
	kdfMaxMemoryKiB = uint32(1024 * 1024) // 1 GiB
	kdfMinParallel  = uint8(1)
	kdfMaxParallel  = uint8(8)
)

// Header is serialized exactly in the order of fields below (little-endian for integers).
// Total serialized length: 73 bytes.
type Header struct {
	Magic     [7]byte // "SECFILE"
	Version   uint8
	TimeCost  uint32 // Argon2id t
	MemoryKiB uint32 // Argon2id m in KiB
	Parallel  uint8  // Argon2id p
	ChunkSize uint32 // intended plaintext chunk size
	Salt      [saltSize]byte
	BaseNonce [baseNonceSize]byte // per-file base nonce
	FileSize  uint64              // original plaintext size
}

// EncodeHeader returns the exact bytes written to file for use as AAD.
func EncodeHeader(h *Header) []byte {
	buf := &bytes.Buffer{}
	buf.Grow(73)
	buf.Write(h.Magic[:])
	buf.WriteByte(h.Version)
	_ = binary.Write(buf, binary.LittleEndian, h.TimeCost)
	_ = binary.Write(buf, binary.LittleEndian, h.MemoryKiB)
	buf.WriteByte(h.Parallel)
	_ = binary.Write(buf, binary.LittleEndian, h.ChunkSize)
	buf.Write(h.Salt[:])
	buf.Write(h.BaseNonce[:])
	_ = binary.Write(buf, binary.LittleEndian, h.FileSize)
	return buf.Bytes()
}

func WriteHeader(w io.Writer, h *Header) ([]byte, error) {
	b := EncodeHeader(h)
	_, err := w.Write(b)
	return b, err
}

func ReadHeader(r io.Reader) (*Header, []byte, error) {
	// Read exactly 73 bytes (entire header)
	headerBytes := make([]byte, 73)
	if _, err := io.ReadFull(r, headerBytes); err != nil {
		return nil, nil, fmt.Errorf("failed reading header: %w", err)
	}
	br := bytes.NewReader(headerBytes)

	h := &Header{}
	if _, err := io.ReadFull(br, h.Magic[:]); err != nil {
		return nil, nil, fmt.Errorf("failed reading magic: %w", err)
	}
	var expected [7]byte
	copy(expected[:], []byte(magicStr))
	if subtle.ConstantTimeCompare(h.Magic[:], expected[:]) != 1 {
		return nil, nil, errors.New("invalid file header (magic mismatch)")
	}

	if v, err := br.ReadByte(); err != nil {
		return nil, nil, fmt.Errorf("failed reading version: %w", err)
	} else {
		h.Version = v
	}
	if h.Version != formatVersion {
		return nil, nil, fmt.Errorf("unsupported version: %d", h.Version)
	}

	if err := binary.Read(br, binary.LittleEndian, &h.TimeCost); err != nil {
		return nil, nil, fmt.Errorf("failed reading timeCost: %w", err)
	}
	if err := binary.Read(br, binary.LittleEndian, &h.MemoryKiB); err != nil {
		return nil, nil, fmt.Errorf("failed reading memoryKiB: %w", err)
	}
	if v, err := br.ReadByte(); err != nil {
		return nil, nil, fmt.Errorf("failed reading parallelism: %w", err)
	} else {
		h.Parallel = v
	}
	if err := binary.Read(br, binary.LittleEndian, &h.ChunkSize); err != nil {
		return nil, nil, fmt.Errorf("failed reading chunkSize: %w", err)
	}
	if h.ChunkSize == 0 || h.ChunkSize > 8*1024*1024 {
		return nil, nil, fmt.Errorf("invalid chunk size in header: %d", h.ChunkSize)
	}
	if _, err := io.ReadFull(br, h.Salt[:]); err != nil {
		return nil, nil, fmt.Errorf("failed reading salt: %w", err)
	}
	if _, err := io.ReadFull(br, h.BaseNonce[:]); err != nil {
		return nil, nil, fmt.Errorf("failed reading base nonce: %w", err)
	}
	if err := binary.Read(br, binary.LittleEndian, &h.FileSize); err != nil {
		return nil, nil, fmt.Errorf("failed reading file size: %w", err)
	}
	if h.FileSize > uint64(maxFileSize) {
		return nil, nil, fmt.Errorf("file size in header exceeds limit: %d bytes", h.FileSize)
	}
	return h, headerBytes, nil
}

// SECURITY: zeroizer hardened with KeepAlive to prevent dead-store elimination.
func zeroize(b []byte) {
	if b == nil {
		return
	}
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

func genRandom(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

// SECURITY: domain-separated salt for Argon2id to avoid cross-protocol key reuse.
// salt' = SHA-256("SECFILE\x00kdfv1" || salt)
func contextSalt(salt []byte) []byte {
	h := sha256.New()
	h.Write([]byte("SECFILE\x00kdfv1"))
	h.Write(salt)
	sum := h.Sum(nil)
	return sum // 32 bytes
}

// SECURITY: wrapper that applies domain separation before calling Argon2id.
func deriveKey(pw, salt []byte, t uint32, mKiB uint32, p uint8, keyLen uint32) []byte {
	ctxSalt := contextSalt(salt)
	key := argon2.IDKey(pw, ctxSalt, t, mKiB, uint8(p), uint32(keyLen))
	zeroize(ctxSalt)
	return key
}

func deriveChunkNonce(base [baseNonceSize]byte, idx uint64) [baseNonceSize]byte {
	// XOR base nonce with little-endian chunk counter spread over 12 bytes
	var out [baseNonceSize]byte
	copy(out[:], base[:])
	var ctr [baseNonceSize]byte
	binary.LittleEndian.PutUint64(ctr[:8], idx)
	// remaining 4 bytes are zero (fine up to 2^96 unique nonces)
	for i := 0; i < baseNonceSize; i++ {
		out[i] ^= ctr[i]
	}
	return out
}

// SECURITY: construct AAD = headerBytes || chunkIdxLE || plenLE
func makeAAD(headerBytes []byte, chunkIdx uint64, plen uint32) []byte {
	aad := make([]byte, 0, len(headerBytes)+8+4)
	aad = append(aad, headerBytes...)
	var idxLE [8]byte
	binary.LittleEndian.PutUint64(idxLE[:], chunkIdx)
	aad = append(aad, idxLE[:]...)
	var lenLE [4]byte
	binary.LittleEndian.PutUint32(lenLE[:], plen)
	aad = append(aad, lenLE[:]...)
	return aad
}

type task struct {
	inPath     string
	outRoot    string
	inputRoot  string
	mode       string // "enc" or "dec"
	exeAbsPath string
}

type stats struct {
	total   int64
	success int64
	failed  int64
	skipped int64
}

var printMu sync.Mutex

func printfSafe(format string, args ...any) {
	printMu.Lock()
	fmt.Printf(format, args...)
	printMu.Unlock()
}

func printlnSafe(args ...any) {
	printMu.Lock()
	fmt.Println(args...)
	printMu.Unlock()
}

func promptPassword(confirm bool) ([]byte, error) {
	in := os.Stdin
	if !term.IsTerminal(int(in.Fd())) {
		return nil, errors.New("stdin is not a terminal; cannot securely read password")
	}
	fmt.Print("Enter password: ")
	pw1, err := term.ReadPassword(int(in.Fd()))
	fmt.Println()
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}
	if len(pw1) == 0 {
		zeroize(pw1)
		return nil, errors.New("empty password is not allowed")
	}
	if confirm {
		fmt.Print("Confirm password: ")
		pw2, err := term.ReadPassword(int(in.Fd()))
		fmt.Println()
		if err != nil {
			zeroize(pw1)
			return nil, fmt.Errorf("failed to read password confirmation: %w", err)
		}
		if len(pw2) != len(pw1) || subtle.ConstantTimeCompare(pw1, pw2) != 1 {
			zeroize(pw1)
			zeroize(pw2)
			return nil, errors.New("passwords do not match")
		}
		zeroize(pw2)
	}
	return pw1, nil
}

func shouldSkip(path string, exeAbsPath string) bool {
	if path == exeAbsPath {
		return true
	}
	// Avoid re-processing output directories if the user points to a parent directory
	base := filepath.Base(path)
	if base == outDirEncrypt || base == outDirDecrypt {
		return true
	}
	return false
}

func gatherFiles(inputPath string, mode string, exeAbsPath string) (string, []string, error) {
	absIn, err := filepath.Abs(inputPath)
	if err != nil {
		return "", nil, err
	}
	info, err := os.Stat(absIn)
	if err != nil {
		return "", nil, err
	}
	var inputRoot string
	var files []string

	if info.IsDir() {
		inputRoot = filepath.Dir(absIn)
		err = filepath.WalkDir(absIn, func(p string, d os.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if d.IsDir() {
				// Skip our known output dirs
				if shouldSkip(p, exeAbsPath) {
					return filepath.SkipDir
				}
				return nil
			}
			if shouldSkip(p, exeAbsPath) {
				return nil
			}
			if mode == "enc" && strings.HasSuffix(strings.ToLower(p), encExt) {
				// don't encrypt already-encrypted files
				return nil
			}
			if mode == "dec" && !strings.HasSuffix(strings.ToLower(p), encExt) {
				// only decrypt *.enc
				return nil
			}
			files = append(files, p)
			return nil
		})
		if err != nil {
			return "", nil, err
		}
	} else {
		inputRoot = filepath.Dir(absIn)
		if shouldSkip(absIn, exeAbsPath) {
			return "", nil, errors.New("refusing to process the executable itself")
		}
		if mode == "enc" && strings.HasSuffix(strings.ToLower(absIn), encExt) {
			return "", nil, errors.New("input is already an .enc file; refusing to encrypt")
		}
		if mode == "dec" && !strings.HasSuffix(strings.ToLower(absIn), encExt) {
			return "", nil, errors.New("input is not an .enc file; refusing to decrypt")
		}
		files = []string{absIn}
	}

	return inputRoot, files, nil
}

// ensureOutRoot creates the output root if missing. It does NOT prompt.
// Prompting is handled separately for a specific first-level target derived
// from the input parameter.
func ensureOutRoot(root string) error {
	info, err := os.Stat(root)
	if os.IsNotExist(err) {
		return os.MkdirAll(root, 0700)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("output root %q exists but is not a directory", root)
	}
	return nil
}

// firstLevelTargetPath returns the path directly under outRoot that corresponds
// to the *input parameter* (not every file inside a directory).
// - If input is a directory: outRoot / base(input)
// - If input is a file and encrypting: outRoot / (base(input) + ".enc")
// - If input is a file and decrypting: outRoot / trimSuffix(base(input), ".enc")
func firstLevelTargetPath(outRoot, inputPath, mode string) (string, error) {
	absIn, err := filepath.Abs(inputPath)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(absIn)
	if err != nil {
		return "", err
	}
	base := filepath.Base(absIn)
	if st.IsDir() {
		// For both enc and dec, the first-level entity is the directory name itself.
		return filepath.Join(outRoot, base), nil
	}
	// File input
	lbase := strings.ToLower(base)
	if mode == "enc" {
		if strings.HasSuffix(lbase, encExt) {
			return "", errors.New("input is already an .enc file; refusing to compute first-level target")
		}
		return filepath.Join(outRoot, base+encExt), nil
	}
	// mode == "dec"
	if !strings.HasSuffix(lbase, encExt) {
		return "", errors.New("input is not an .enc file; refusing to compute first-level target")
	}
	// remove suffix in a case-insensitive safe way but preserve original base's case
	trimmed := base[:len(base)-len(encExt)] // safe because HasSuffix(lbase, encExt) was true
	return filepath.Join(outRoot, trimmed), nil
}

// confirmIfFirstLevelTargetExists prompts only if the *specific* first-level
// target (as derived from the input parameter) already exists directly under outRoot.
func confirmIfFirstLevelTargetExists(outRoot, inputPath, mode string, needConfirm bool) error {
	target, err := firstLevelTargetPath(outRoot, inputPath, mode)
	if err != nil {
		return err
	}
	info, statErr := os.Stat(target)
	if os.IsNotExist(statErr) {
		return nil // nothing to prompt about
	}
	if statErr != nil {
		return statErr
	}
	// Target exists directly under outRoot.
	if !needConfirm {
		return nil
	}

	typ := "file"
	if info.IsDir() {
		typ = "directory"
	}

	// Prompt showing the full target path and its type so user clearly knows what will be overwritten.
	fmt.Printf("Target %q (%s) already exists. Overwrite/continue? [y/N]: ", target, typ)
	reader := bufio.NewReader(os.Stdin)
	resp, _ := reader.ReadString('\n')
	resp = strings.ToLower(strings.TrimSpace(resp))
	if resp == "y" || resp == "yes" {
		return nil
	}
	return errors.New("aborted by user")
}

func outPathFor(inPath, inputRoot, outRoot, mode string) (string, error) {
	rel, err := filepath.Rel(inputRoot, inPath)
	if err != nil {
		return "", err
	}
	var target string
	if mode == "enc" {
		if strings.HasSuffix(strings.ToLower(rel), encExt) {
			return "", errors.New("unexpected .enc extension on encryption")
		}
		target = filepath.Join(outRoot, rel) + encExt
	} else { // dec
		if !strings.HasSuffix(strings.ToLower(rel), encExt) {
			return "", errors.New("unexpected non-.enc file on decryption")
		}
		target = filepath.Join(outRoot, strings.TrimSuffix(rel, encExt))
	}
	return target, nil
}

func encryptFile(inPath, outPath string, pw []byte, stats *stats) error {
	fi, err := os.Stat(inPath)
	if err != nil {
		return err
	}
	if fi.Size() > maxFileSize {
		return fmt.Errorf("skipping %q: file too large (>%d bytes)", inPath, maxFileSize)
	}
	in, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(outPath), 0700); err != nil {
		return err
	}
	out, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer func() {
		out.Sync()
		out.Close()
	}()

	// Per-file: salt and base nonce
	salt, err := genRandom(saltSize)
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}
	var saltArr [saltSize]byte
	copy(saltArr[:], salt)
	zeroize(salt)

	baseNonce, err := genRandom(baseNonceSize)
	if err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}
	var baseNonceArr [baseNonceSize]byte
	copy(baseNonceArr[:], baseNonce)
	zeroize(baseNonce)

	// Derive key (SECURITY: domain-separated Argon2id)
	key := deriveKey(pw, saltArr[:], aTime, aMemoryKiB, aParallel, derivedKeyL)
	defer zeroize(key)

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return fmt.Errorf("failed to init AEAD: %w", err)
	}

	h := &Header{
		Version:   formatVersion,
		TimeCost:  aTime,
		MemoryKiB: aMemoryKiB,
		Parallel:  aParallel,
		ChunkSize: uint32(defaultChunkSize),
		FileSize:  uint64(fi.Size()),
	}
	copy(h.Magic[:], []byte(magicStr))
	copy(h.Salt[:], saltArr[:])
	copy(h.BaseNonce[:], baseNonceArr[:])

	headerBytes, err := WriteHeader(out, h)
	if err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}
	// progress
	var processed int64
	lastPct := -1

	buf := make([]byte, defaultChunkSize)
	defer zeroize(buf)

	// SECURITY: read directly from file; avoid extra plaintext buffering with bufio.Reader
	chunkIdx := uint64(0)
	for {
		n, readErr := io.ReadFull(in, buf)
		if readErr == io.EOF {
			break
		}
		if readErr == io.ErrUnexpectedEOF {
			// last partial chunk
		} else if readErr != nil && readErr != io.ErrUnexpectedEOF {
			return fmt.Errorf("read error: %w", readErr)
		}

		pt := buf[:n]

		// Write plaintext length (uint32 LE)
		var len32 uint32 = uint32(len(pt))
		if err := binary.Write(out, binary.LittleEndian, len32); err != nil {
			return fmt.Errorf("failed to write chunk length: %w", err)
		}

		nonce := deriveChunkNonce(h.BaseNonce, chunkIdx)

		// SECURITY: bind length into AAD
		aad := makeAAD(headerBytes, chunkIdx, len32)

		ct := aead.Seal(nil, nonce[:], pt, aad)

		if _, err := out.Write(ct); err != nil {
			return fmt.Errorf("failed to write ciphertext: %w", err)
		}

		// wipe plaintext chunk
		for i := 0; i < len(pt); i++ {
			pt[i] = 0
		}
		runtime.KeepAlive(pt) // SECURITY: ensure wipe isn't optimized away

		processed += int64(n)
		pct := int(float64(processed) * 100 / float64(fi.Size()))
		if pct != lastPct && (pct%5 == 0 || pct == 100) {
			printfSafe("[ENCRYPT] %s  %d%%  (%d/%d bytes)\n", inPath, pct, processed, fi.Size())
			lastPct = pct
		}
		chunkIdx++
		if readErr == io.ErrUnexpectedEOF {
			break
		}
	}

	return nil
}

// SECURITY: validate/cap KDF params from header before Argon2 to prevent DoS.
func validateKDFParams(t uint32, mKiB uint32, p uint8) error {
	if t < kdfMinTimeCost || t > kdfMaxTimeCost {
		return fmt.Errorf("argon2 timeCost out of bounds: %d (allowed %d..%d)", t, kdfMinTimeCost, kdfMaxTimeCost)
	}
	if mKiB < kdfMinMemoryKiB || mKiB > kdfMaxMemoryKiB {
		return fmt.Errorf("argon2 memoryKiB out of bounds: %d (allowed %d..%d)", mKiB, kdfMinMemoryKiB, kdfMaxMemoryKiB)
	}
	if p < kdfMinParallel || p > kdfMaxParallel {
		return fmt.Errorf("argon2 parallelism out of bounds: %d (allowed %d..%d)", p, kdfMinParallel, kdfMaxParallel)
	}
	// Also bound relative to CPU to tame CPU exhaustion (soft cap)
	maxRel := runtime.NumCPU() * 2
	if int(p) > maxRel {
		return fmt.Errorf("argon2 parallelism too high for this system: %d (max %d)", p, maxRel)
	}
	return nil
}

func decryptFile(inPath, outPath string, pw []byte, stats *stats) error {
	in, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer in.Close()

	h, headerBytes, err := ReadHeader(in)
	if err != nil {
		return err
	}
	if h.FileSize > uint64(maxFileSize) {
		return fmt.Errorf("file declares size > %d bytes; refusing", maxFileSize)
	}
	if h.ChunkSize == 0 || h.ChunkSize > 8*1024*1024 {
		return fmt.Errorf("invalid chunk size %d", h.ChunkSize)
	}

	// SECURITY: validate KDF params from header (pre-Argon2)
	if err := validateKDFParams(h.TimeCost, h.MemoryKiB, h.Parallel); err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0700); err != nil {
		return err
	}
	out, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer func() {
		out.Sync()
		out.Close()
	}()

	// Derive key from stored parameters (SECURITY: domain-separated Argon2id)
	key := deriveKey(pw, h.Salt[:], h.TimeCost, h.MemoryKiB, h.Parallel, derivedKeyL)
	defer zeroize(key)

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return fmt.Errorf("failed to init AEAD: %w", err)
	}

	var written uint64
	lastPct := -1
	chunkIdx := uint64(0)

	for written < h.FileSize {
		// Read plaintext length prefix
		var plen uint32
		if err := binary.Read(in, binary.LittleEndian, &plen); err != nil {
			return fmt.Errorf("failed to read chunk length: %w", err)
		}
		if plen == 0 || uint64(plen) > uint64(h.ChunkSize) {
			return fmt.Errorf("invalid chunk length: %d", plen)
		}
		remain := h.FileSize - written
		if uint64(plen) > remain {
			return fmt.Errorf("chunk length exceeds remaining file size (%d > %d)", plen, remain)
		}
		ctLen := int(plen) + tagSize
		ct := make([]byte, ctLen)
		if _, err := io.ReadFull(in, ct); err != nil {
			return fmt.Errorf("failed to read ciphertext: %w", err)
		}

		nonce := deriveChunkNonce(h.BaseNonce, chunkIdx)

		// SECURITY: bind length into AAD on decrypt side as well
		aad := makeAAD(headerBytes, chunkIdx, plen)

		pt, err := aead.Open(nil, nonce[:], ct, aad)
		if err != nil {
			zeroize(ct)
			return errors.New("authentication failed (ciphertext tampered or wrong password)")
		}
		zeroize(ct)

		if _, err := out.Write(pt); err != nil {
			zeroize(pt)
			return fmt.Errorf("failed to write plaintext: %w", err)
		}
		written += uint64(len(pt))
		zeroize(pt)
		runtime.KeepAlive(pt) // SECURITY: ensure wipe isn't optimized away

		pct := int(float64(written) * 100 / float64(h.FileSize))
		if pct != lastPct && (pct%5 == 0 || pct == 100) {
			printfSafe("[DECRYPT] %s  %d%%  (%d/%d bytes)\n", inPath, pct, written, h.FileSize)
			lastPct = pct
		}
		chunkIdx++
	}
	return nil
}

func worker(id int, jobs <-chan task, pw []byte, st *stats, wg *sync.WaitGroup) {
	defer wg.Done()
	for tk := range jobs {
		atomic.AddInt64(&st.total, 1)

		outPath, err := outPathFor(tk.inPath, tk.inputRoot, tk.outRoot, tk.mode)
		if err != nil {
			atomic.AddInt64(&st.failed, 1)
			printfSafe("[WORKER %d] %s\n", id, err.Error())
			continue
		}
		start := time.Now()
		var e error
		if tk.mode == "enc" {
			e = encryptFile(tk.inPath, outPath, pw, st)
		} else {
			e = decryptFile(tk.inPath, outPath, pw, st)
		}
		if e != nil {
			atomic.AddInt64(&st.failed, 1)
			printfSafe("[WORKER %d] %s — ERROR: %v\n", id, tk.inPath, e)
			continue
		}
		atomic.AddInt64(&st.success, 1)
		printfSafe("[WORKER %d] %s — OK (%.2fs)\n", id, tk.inPath, time.Since(start).Seconds())
	}
}

func main() {
	encrypt := flag.Bool("e", false, "encryption mode")
	decrypt := flag.Bool("d", false, "decryption mode")
	inPath := flag.String("in", "", "input file or directory")
	workers := flag.Int("workers", max(1, min(2, runtime.NumCPU())), "number of concurrent workers (beware of RAM usage with Argon2id)")
	autoYes := flag.Bool("y", false, "assume yes when confirming overwrite of output targets")
	flag.Parse()

	if (*encrypt && *decrypt) || (!*encrypt && !*decrypt) {
		fmt.Println("You must specify exactly one of -e (encrypt) or -d (decrypt).")
		os.Exit(1)
	}
	if *inPath == "" {
		fmt.Println("You must provide -in <path> (file or directory).")
		os.Exit(1)
	}

	mode := "enc"
	outRoot := outDirEncrypt
	needConfirm := true
	if *decrypt {
		mode = "dec"
		outRoot = outDirDecrypt
	}
	if *autoYes {
		needConfirm = false
	}

	exe, _ := os.Executable()
	exeAbs, _ := filepath.Abs(exe)

	inputRoot, files, err := gatherFiles(*inPath, mode, exeAbs)
	if err != nil {
		fmt.Println("Failed to gather files:", err)
		os.Exit(1)
	}
	if len(files) == 0 {
		fmt.Println("No files matched the criteria.")
		return
	}

	// Ensure output root exists (no prompt here).
	if err := ensureOutRoot(outRoot); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Prompt ONLY if the specific first-level target derived from -in already exists.
	if err := confirmIfFirstLevelTargetExists(outRoot, *inPath, mode, needConfirm); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Read password
	var pw []byte
	if mode == "enc" {
		pw, err = promptPassword(true)
	} else {
		pw, err = promptPassword(false)
	}
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer zeroize(pw)

	// Build tasks
	jobs := make(chan task, len(files))
	st := &stats{}
	var wg sync.WaitGroup

	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go worker(w+1, jobs, pw, st, &wg)
	}
	for _, f := range files {
		jobs <- task{
			inPath:     f,
			outRoot:    outRoot,
			inputRoot:  inputRoot,
			mode:       mode,
			exeAbsPath: exeAbs,
		}
	}
	close(jobs)
	wg.Wait()

	// Summary
	printlnSafe("----- SUMMARY -----")
	printlnSafe("Mode:          ", strings.ToUpper(mode))
	printlnSafe("Input root:    ", inputRoot)
	printlnSafe("Output root:   ", outRoot)
	printlnSafe("Total files:   ", st.total)
	printlnSafe("Succeeded:     ", st.success)
	printlnSafe("Failed:        ", st.failed)
	printlnSafe("Skipped:       ", st.skipped)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
