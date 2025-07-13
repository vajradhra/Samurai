package main

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"encoding/ascii85"
)

// 配置结构
type Config struct {
	MaxRounds   int
	Threads     int
	OutDir      string
	MinData     int
	FlagFormat  string
	AutoExtract bool
	MaxDepth    int
}

// 目标结构
type Target struct {
	Data    []byte
	Parent  *Target
	Depth   int
	Config  *Config
	Manager *Manager
	Hash    string // 用于去重
}

// 解码结果结构
type DecodeResult struct {
	Method      string
	Original    []byte
	Decoded     []byte
	Filtered    string
	Round       int
	Parent      *Target
	Children    []*DecodeResult
	DictMatches []DictMatch // 新增：字典匹配结果
	Confidence  float64     // 新增：置信度
}

// 字典结构
type Dictionary struct {
	Name     string
	Patterns []string
	Words    []string
	Regex    *regexp.Regexp
}

// 字典匹配结果
type DictMatch struct {
	Dictionary string
	Pattern    string
	Score      int
	Type       string // "exact", "partial", "regex"
}

// 解码器接口
type Decoder interface {
	Name() string
	Priority() int
	CanDecode(data []byte) bool
	Decode(data []byte) ([]byte, error)
}

// Base64解码器
type Base64Decoder struct{}

func (d *Base64Decoder) Name() string  { return "Base64" }
func (d *Base64Decoder) Priority() int { return 1 }

func (d *Base64Decoder) CanDecode(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	// 移除空白字符
	cleanData := bytes.TrimSpace(data)
	if len(cleanData) < 4 {
		return false
	}

	// 支持标准Base64和URL安全Base64
	pattern := regexp.MustCompile(`^[A-Za-z0-9+/_-]+={0,2}$`)
	return pattern.Match(cleanData)
}

func (d *Base64Decoder) Decode(data []byte) ([]byte, error) {
	// 移除空白字符
	cleanData := bytes.TrimSpace(data)

	// 尝试标准Base64解码
	if result, err := base64.StdEncoding.DecodeString(string(cleanData)); err == nil {
		return result, nil
	}

	// 尝试URL安全Base64解码
	if result, err := base64.URLEncoding.DecodeString(string(cleanData)); err == nil {
		return result, nil
	}

	// 尝试无填充的Base64解码
	if result, err := base64.RawStdEncoding.DecodeString(string(cleanData)); err == nil {
		return result, nil
	}

	// 尝试无填充的URL安全Base64解码
	if result, err := base64.RawURLEncoding.DecodeString(string(cleanData)); err == nil {
		return result, nil
	}

	return nil, fmt.Errorf("failed to decode base64")
}

// Base32解码器
type Base32Decoder struct{}

func (d *Base32Decoder) Name() string  { return "Base32" }
func (d *Base32Decoder) Priority() int { return 2 }

func (d *Base32Decoder) CanDecode(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	pattern := regexp.MustCompile(`^[A-Z2-7]+={0,6}$`)
	return pattern.Match(data)
}

func (d *Base32Decoder) Decode(data []byte) ([]byte, error) {
	return base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(string(data))
}

// 十六进制解码器
type HexDecoder struct{}

func (d *HexDecoder) Name() string  { return "Hex" }
func (d *HexDecoder) Priority() int { return 3 }

func (d *HexDecoder) CanDecode(data []byte) bool {
	if len(data) < 2 || len(data)%2 != 0 {
		return false
	}
	pattern := regexp.MustCompile(`^[0-9a-fA-F]+$`)
	return pattern.Match(data)
}

func (d *HexDecoder) Decode(data []byte) ([]byte, error) {
	return hex.DecodeString(string(data))
}

// URL解码器
type URLDecoder struct{}

func (d *URLDecoder) Name() string  { return "URL" }
func (d *URLDecoder) Priority() int { return 4 }

func (d *URLDecoder) CanDecode(data []byte) bool {
	return bytes.Contains(data, []byte("%"))
}

func (d *URLDecoder) Decode(data []byte) ([]byte, error) {
	decoded, err := url.QueryUnescape(string(data))
	if err != nil {
		return nil, err
	}
	return []byte(decoded), nil
}

// 二进制解码器
type BinaryDecoder struct{}

func (d *BinaryDecoder) Name() string  { return "Binary" }
func (d *BinaryDecoder) Priority() int { return 5 }

func (d *BinaryDecoder) CanDecode(data []byte) bool {
	if len(data) < 8 || len(data)%8 != 0 {
		return false
	}
	pattern := regexp.MustCompile(`^[01]+$`)
	return pattern.Match(data)
}

func (d *BinaryDecoder) Decode(data []byte) ([]byte, error) {
	binaryStr := string(data)
	var result []byte
	for i := 0; i < len(binaryStr); i += 8 {
		byteStr := binaryStr[i : i+8]
		val, err := strconv.ParseUint(byteStr, 2, 8)
		if err != nil {
			return nil, err
		}
		result = append(result, byte(val))
	}
	return result, nil
}

// Caesar密码解码器
type CaesarDecoder struct{}

func (d *CaesarDecoder) Name() string  { return "Caesar" }
func (d *CaesarDecoder) Priority() int { return 6 }

func (d *CaesarDecoder) CanDecode(data []byte) bool {
	// 检查是否包含字母
	hasLetter := false
	for _, b := range data {
		if unicode.IsLetter(rune(b)) {
			hasLetter = true
			break
		}
	}
	return hasLetter && len(data) > 3
}

func (d *CaesarDecoder) Decode(data []byte) ([]byte, error) {
	// 尝试所有可能的移位（1-25）
	for shift := 1; shift <= 25; shift++ {
		var result strings.Builder
		for _, c := range data {
			if unicode.IsLetter(rune(c)) {
				if unicode.IsUpper(rune(c)) {
					result.WriteRune(rune((int(c-'A')+shift)%26 + 'A'))
				} else {
					result.WriteRune(rune((int(c-'a')+shift)%26 + 'a'))
				}
			} else {
				result.WriteByte(c)
			}
		}
		decoded := []byte(result.String())
		if isReadableText(decoded) {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("no readable caesar shift found")
}

// ROT47解码器
type Rot47Decoder struct{}

func (d *Rot47Decoder) Name() string  { return "ROT47" }
func (d *Rot47Decoder) Priority() int { return 7 }

func (d *Rot47Decoder) CanDecode(data []byte) bool {
	// 检查是否包含可打印ASCII字符
	for _, b := range data {
		if b >= 33 && b <= 126 {
			return true
		}
	}
	return false
}

func (d *Rot47Decoder) Decode(data []byte) ([]byte, error) {
	result := make([]byte, len(data))
	for i, b := range data {
		if b >= 33 && b <= 126 {
			result[i] = byte(33 + ((int(b) + 14) % 94))
		} else {
			result[i] = b
		}
	}
	return result, nil
}

// 反转解码器
type ReverseDecoder struct{}

func (d *ReverseDecoder) Name() string  { return "Reverse" }
func (d *ReverseDecoder) Priority() int { return 8 }

func (d *ReverseDecoder) CanDecode(data []byte) bool {
	return len(data) > 3
}

func (d *ReverseDecoder) Decode(data []byte) ([]byte, error) {
	reversed := make([]byte, len(data))
	for i, j := 0, len(data)-1; i < len(data); i, j = i+1, j-1 {
		reversed[i] = data[j]
	}
	return reversed, nil
}

// Base58解码器
var base58Alphabet = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

type Base58Decoder struct{}

func (d *Base58Decoder) Name() string  { return "Base58" }
func (d *Base58Decoder) Priority() int { return 9 }

func (d *Base58Decoder) CanDecode(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	for _, b := range data {
		if !bytes.Contains(base58Alphabet, []byte{b}) {
			return false
		}
	}
	return true
}

func (d *Base58Decoder) Decode(data []byte) ([]byte, error) {
	result := []byte{}
	for _, b := range data {
		if b == ' ' || b == '\n' || b == '\r' {
			continue
		}
		if !bytes.Contains(base58Alphabet, []byte{b}) {
			return nil, fmt.Errorf("invalid base58 char")
		}
	}
	// 参考bitcoin base58解码实现
	zero := base58Alphabet[0]
	b58 := make([]byte, len(data))
	for i := range data {
		b58[i] = byte(bytes.IndexByte(base58Alphabet, data[i]))
	}
	intVal := 0
	for _, c := range b58 {
		intVal = intVal*58 + int(c)
	}
	for intVal > 0 {
		result = append([]byte{byte(intVal % 256)}, result...)
		intVal /= 256
	}
	// 前导0处理
	for _, c := range data {
		if c == zero {
			result = append([]byte{0}, result...)
		} else {
			break
		}
	}
	return result, nil
}

// XOR解码器（单字节爆破）
type XorDecoder struct{}

func (d *XorDecoder) Name() string  { return "XOR" }
func (d *XorDecoder) Priority() int { return 10 }

func (d *XorDecoder) CanDecode(data []byte) bool {
	return len(data) > 2
}

func (d *XorDecoder) Decode(data []byte) ([]byte, error) {
	for key := 1; key < 256; key++ {
		out := make([]byte, len(data))
		for i, b := range data {
			out[i] = b ^ byte(key)
		}
		if isReadableText(out) {
			return out, nil
		}
	}
	return nil, fmt.Errorf("no readable xor key found")
}

// 摩斯码解码器
var morseMap = map[string]string{
	".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9",
}

type MorseDecoder struct{}

func (d *MorseDecoder) Name() string  { return "MorseCode" }
func (d *MorseDecoder) Priority() int { return 11 }

func (d *MorseDecoder) CanDecode(data []byte) bool {
	return bytes.Contains(data, []byte(".")) || bytes.Contains(data, []byte("-"))
}

func (d *MorseDecoder) Decode(data []byte) ([]byte, error) {
	words := strings.Split(string(data), " ")
	var result strings.Builder
	for _, w := range words {
		if v, ok := morseMap[w]; ok {
			result.WriteString(v)
		} else if w == "" {
			result.WriteString(" ")
		} else {
			result.WriteString(".")
		}
	}
	return []byte(result.String()), nil
}

// RailFence解码器
type RailFenceDecoder struct{}

func (d *RailFenceDecoder) Name() string  { return "RailFence" }
func (d *RailFenceDecoder) Priority() int { return 12 }

func (d *RailFenceDecoder) CanDecode(data []byte) bool {
	return len(data) > 4
}

func (d *RailFenceDecoder) Decode(data []byte) ([]byte, error) {
	// 默认尝试2-5轨道
	for rails := 2; rails <= 5; rails++ {
		res := railFenceDecode(string(data), rails)
		if isReadableText([]byte(res)) {
			return []byte(res), nil
		}
	}
	return nil, fmt.Errorf("no readable railfence found")
}

func railFenceDecode(cipher string, rails int) string {
	n := len(cipher)
	rail := make([][]rune, rails)
	for i := range rail {
		rail[i] = make([]rune, n)
	}
	dirDown := false
	row, col := 0, 0
	for i := 0; i < n; i++ {
		if row == 0 || row == rails-1 {
			dirDown = !dirDown
		}
		rail[row][col] = '*'
		col++
		if dirDown {
			row++
		} else {
			row--
		}
	}
	index := 0
	for i := 0; i < rails; i++ {
		for j := 0; j < n; j++ {
			if rail[i][j] == '*' && index < n {
				rail[i][j] = rune(cipher[index])
				index++
			}
		}
	}
	result := make([]rune, 0, n)
	row, col = 0, 0
	dirDown = false
	for i := 0; i < n; i++ {
		if row == 0 || row == rails-1 {
			dirDown = !dirDown
		}
		if rail[row][col] != 0 {
			result = append(result, rail[row][col])
		}
		col++
		if dirDown {
			row++
		} else {
			row--
		}
	}
	return string(result)
}

// Vigenere解码器（需指定key，默认不爆破）
type VigenereDecoder struct{}

func (d *VigenereDecoder) Name() string  { return "Vigenere" }
func (d *VigenereDecoder) Priority() int { return 13 }

func (d *VigenereDecoder) CanDecode(data []byte) bool {
	return false // 需指定key，暂不自动爆破
}

func (d *VigenereDecoder) Decode(data []byte) ([]byte, error) {
	return nil, fmt.Errorf("需要指定key")
}

// Atbash解码器
type AtbashDecoder struct{}

func (d *AtbashDecoder) Name() string  { return "Atbash" }
func (d *AtbashDecoder) Priority() int { return 14 }

func (d *AtbashDecoder) CanDecode(data []byte) bool {
	return len(data) > 2
}

func (d *AtbashDecoder) Decode(data []byte) ([]byte, error) {
	var result strings.Builder
	for _, c := range data {
		if c >= 'A' && c <= 'Z' {
			result.WriteByte('Z' - (c - 'A'))
		} else if c >= 'a' && c <= 'z' {
			result.WriteByte('z' - (c - 'a'))
		} else {
			result.WriteByte(c)
		}
	}
	return []byte(result.String()), nil
}

// Affine解码器（爆破常用a,b）
type AffineDecoder struct{}

func (d *AffineDecoder) Name() string  { return "Affine" }
func (d *AffineDecoder) Priority() int { return 15 }

func (d *AffineDecoder) CanDecode(data []byte) bool {
	return len(data) > 2
}

func (d *AffineDecoder) Decode(data []byte) ([]byte, error) {
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	m := len(alphabet)
	for a := 1; a < m; a++ {
		if gcd(a, m) != 1 {
			continue
		}
		for b := 0; b < m; b++ {
			var result strings.Builder
			for _, c := range data {
				uc := unicode.ToUpper(rune(c))
				if uc >= 'A' && uc <= 'Z' {
					x := int(uc - 'A')
					plain := (modInverse(a, m) * (x - b + m)) % m
					result.WriteByte(alphabet[plain])
				} else {
					result.WriteByte(byte(c))
				}
			}
			decoded := []byte(result.String())
			if isReadableText(decoded) {
				return decoded, nil
			}
		}
	}
	return nil, fmt.Errorf("no readable affine found")
}

func gcd(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

func modInverse(a, m int) int {
	a = a % m
	for x := 1; x < m; x++ {
		if (a*x)%m == 1 {
			return x
		}
	}
	return 1
}

// Polybius解码器
type PolybiusDecoder struct{}

func (d *PolybiusDecoder) Name() string  { return "Polybius" }
func (d *PolybiusDecoder) Priority() int { return 16 }

func (d *PolybiusDecoder) CanDecode(data []byte) bool {
	pattern := regexp.MustCompile(`^[1-5 ]+$`)
	return pattern.Match(data)
}

func (d *PolybiusDecoder) Decode(data []byte) ([]byte, error) {
	alphabet := "ABCDEFGHIKLMNOPQRSTUVWXYZ"
	data = bytes.ReplaceAll(data, []byte(" "), []byte(""))
	if len(data)%2 != 0 {
		return nil, fmt.Errorf("invalid polybius length")
	}
	var result strings.Builder
	for i := 0; i < len(data); i += 2 {
		x := int(data[i] - '1')
		y := int(data[i+1] - '1')
		if x < 0 || x > 4 || y < 0 || y > 4 {
			result.WriteByte('.')
			continue
		}
		result.WriteByte(alphabet[y+x*5])
	}
	return []byte(result.String()), nil
}

// Unhexlify解码器（十六进制字符串转字节）
type UnhexlifyDecoder struct{}

func (d *UnhexlifyDecoder) Name() string  { return "Unhexlify" }
func (d *UnhexlifyDecoder) Priority() int { return 17 }

func (d *UnhexlifyDecoder) CanDecode(data []byte) bool {
	pattern := regexp.MustCompile(`^[0-9a-fA-F]+$`)
	return len(data) > 1 && len(data)%2 == 0 && pattern.Match(data)
}

func (d *UnhexlifyDecoder) Decode(data []byte) ([]byte, error) {
	return hex.DecodeString(string(data))
}

// Undecimal解码器（十进制数字转字节，支持大端/小端）
type UndecimalDecoder struct{}

func (d *UndecimalDecoder) Name() string  { return "Undecimal" }
func (d *UndecimalDecoder) Priority() int { return 18 }

func (d *UndecimalDecoder) CanDecode(data []byte) bool {
	pattern := regexp.MustCompile(`^([0-9]+ ?)+$`)
	return pattern.Match(data)
}

func (d *UndecimalDecoder) Decode(data []byte) ([]byte, error) {
	parts := strings.Fields(string(data))
	var result []byte
	for _, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil {
			return nil, err
		}
		result = append(result, byte(v))
	}
	return result, nil
}

// Unbinary解码器（二进制字符串转字节）
type UnbinaryDecoder struct{}

func (d *UnbinaryDecoder) Name() string  { return "Unbinary" }
func (d *UnbinaryDecoder) Priority() int { return 19 }

func (d *UnbinaryDecoder) CanDecode(data []byte) bool {
	pattern := regexp.MustCompile(`^[01 ]+$`)
	return pattern.Match(data)
}

func (d *UnbinaryDecoder) Decode(data []byte) ([]byte, error) {
	parts := strings.Fields(string(data))
	var result []byte
	for _, p := range parts {
		v, err := strconv.ParseUint(p, 2, 8)
		if err != nil {
			return nil, err
		}
		result = append(result, byte(v))
	}
	return result, nil
}

// Ascii85/Base85解码器
type Ascii85Decoder struct{}

func (d *Ascii85Decoder) Name() string  { return "Ascii85" }
func (d *Ascii85Decoder) Priority() int { return 20 }

func (d *Ascii85Decoder) CanDecode(data []byte) bool {
	return bytes.Contains(data, []byte("~>")) || bytes.Contains(data, []byte("z"))
}

func (d *Ascii85Decoder) Decode(data []byte) ([]byte, error) {
	decoded := make([]byte, len(data)*4/5)
	n, _, err := ascii85.Decode(decoded, data, true)
	if err != nil {
		return nil, err
	}
	return decoded[:n], nil
}

// Phonetic解码器（NATO音标字母表）
var phoneticMap = map[string]string{
	"alpha": "A", "bravo": "B", "charlie": "C", "delta": "D", "echo": "E", "foxtrot": "F", "golf": "G", "hotel": "H", "india": "I", "juliett": "J", "kilo": "K", "lima": "L", "mike": "M", "november": "N", "oscar": "O", "papa": "P", "quebec": "Q", "romeo": "R", "sierra": "S", "tango": "T", "uniform": "U", "victor": "V", "whiskey": "W", "xray": "X", "yankee": "Y", "zulu": "Z",
}

type PhoneticDecoder struct{}

func (d *PhoneticDecoder) Name() string  { return "Phonetic" }
func (d *PhoneticDecoder) Priority() int { return 21 }

func (d *PhoneticDecoder) CanDecode(data []byte) bool {
	for k := range phoneticMap {
		if strings.Contains(strings.ToLower(string(data)), k) {
			return true
		}
	}
	return false
}

func (d *PhoneticDecoder) Decode(data []byte) ([]byte, error) {
	words := strings.Fields(strings.ToLower(string(data)))
	var result strings.Builder
	for _, w := range words {
		if v, ok := phoneticMap[w]; ok {
			result.WriteString(v)
		} else {
			result.WriteString(".")
		}
	}
	return []byte(result.String()), nil
}

// T9解码器（手机九宫格）
var t9Map = map[string]string{
	"2": "A", "22": "B", "222": "C", "3": "D", "33": "E", "333": "F", "4": "G", "44": "H", "444": "I", "5": "J", "55": "K", "555": "L", "6": "M", "66": "N", "666": "O", "7": "P", "77": "Q", "777": "R", "7777": "S", "8": "T", "88": "U", "888": "V", "9": "W", "99": "X", "999": "Y", "9999": "Z",
}

type T9Decoder struct{}

func (d *T9Decoder) Name() string  { return "T9" }
func (d *T9Decoder) Priority() int { return 22 }

func (d *T9Decoder) CanDecode(data []byte) bool {
	pattern := regexp.MustCompile(`^[2-9 ]+$`)
	return pattern.Match(data)
}

func (d *T9Decoder) Decode(data []byte) ([]byte, error) {
	words := strings.Fields(string(data))
	var result strings.Builder
	for _, w := range words {
		if v, ok := t9Map[w]; ok {
			result.WriteString(v)
		} else {
			result.WriteString(".")
		}
	}
	return []byte(result.String()), nil
}

// DNA/Codon解码器
type DnaDecoder struct{}

func (d *DnaDecoder) Name() string  { return "DNA" }
func (d *DnaDecoder) Priority() int { return 23 }

func (d *DnaDecoder) CanDecode(data []byte) bool {
	pattern := regexp.MustCompile(`^[ACGTU\s]+$`)
	return pattern.Match(data) && len(data) >= 6
}

func (d *DnaDecoder) Decode(data []byte) ([]byte, error) {
	// 清理数据
	clean := strings.ReplaceAll(strings.ToUpper(string(data)), "U", "T")
	clean = strings.ReplaceAll(clean, " ", "")
	clean = strings.ReplaceAll(clean, "\n", "")
	clean = strings.ReplaceAll(clean, "\r", "")

	if len(clean)%3 != 0 {
		return nil, fmt.Errorf("DNA length must be multiple of 3")
	}

	// DNA到字符映射
	allChars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 ."
	var result strings.Builder

	for i := 0; i < len(clean); i += 3 {
		codon := clean[i : i+3]
		index := 0

		// 计算索引
		switch codon[2] {
		case 'A':
			index += 0
		case 'C':
			index += 1
		case 'G':
			index += 2
		case 'T':
			index += 3
		}
		switch codon[1] {
		case 'A':
			index += 0
		case 'C':
			index += 4
		case 'G':
			index += 8
		case 'T':
			index += 12
		}
		switch codon[0] {
		case 'A':
			index += 0
		case 'C':
			index += 16
		case 'G':
			index += 32
		case 'T':
			index += 48
		}

		if index < len(allChars) {
			result.WriteByte(allChars[index])
		} else {
			result.WriteByte('.')
		}
	}

	return []byte(result.String()), nil
}

// RSA解码器（简化版，支持基本解密）
type RsaDecoder struct{}

func (d *RsaDecoder) Name() string  { return "RSA" }
func (d *RsaDecoder) Priority() int { return 24 }

func (d *RsaDecoder) CanDecode(data []byte) bool {
	// 检查是否包含RSA相关参数
	return bytes.Contains(data, []byte("n=")) || bytes.Contains(data, []byte("e=")) || bytes.Contains(data, []byte("c="))
}

func (d *RsaDecoder) Decode(data []byte) ([]byte, error) {
	// 简化版RSA解密，实际应用中需要更复杂的实现
	// 这里只是占位符，实际RSA解密需要专门的库
	return nil, fmt.Errorf("RSA解密需要专门的实现")
}

// 隐写术解码器（Whitespace）
type WhitespaceDecoder struct{}

func (d *WhitespaceDecoder) Name() string  { return "Whitespace" }
func (d *WhitespaceDecoder) Priority() int { return 25 }

func (d *WhitespaceDecoder) CanDecode(data []byte) bool {
	return bytes.Contains(data, []byte(" ")) || bytes.Contains(data, []byte("\t"))
}

func (d *WhitespaceDecoder) Decode(data []byte) ([]byte, error) {
	// 将空格和制表符转换为二进制
	var binary strings.Builder
	for _, b := range data {
		switch b {
		case ' ':
			binary.WriteString("0")
		case '\t':
			binary.WriteString("1")
		}
	}

	// 转换为字节
	binaryStr := binary.String()
	if len(binaryStr) == 0 {
		return nil, fmt.Errorf("no whitespace found")
	}

	// 补齐到8的倍数
	for len(binaryStr)%8 != 0 {
		binaryStr += "0"
	}

	var result []byte
	for i := 0; i < len(binaryStr); i += 8 {
		byteStr := binaryStr[i : i+8]
		val, err := strconv.ParseUint(byteStr, 2, 8)
		if err != nil {
			return nil, err
		}
		result = append(result, byte(val))
	}

	return result, nil
}

// 异端编程语言解码器（Brainfuck）
type BrainfuckDecoder struct{}

func (d *BrainfuckDecoder) Name() string  { return "Brainfuck" }
func (d *BrainfuckDecoder) Priority() int { return 26 }

func (d *BrainfuckDecoder) CanDecode(data []byte) bool {
	pattern := regexp.MustCompile(`[><+\-.,\[\]]+`)
	return pattern.Match(data)
}

func (d *BrainfuckDecoder) Decode(data []byte) ([]byte, error) {
	// 简化的Brainfuck解释器
	code := string(data)
	memory := make([]byte, 30000)
	ptr := 0
	var output strings.Builder
	loopStack := make([]int, 0)
	loopMap := make(map[int]int)

	// 预处理循环映射
	for i, char := range code {
		if char == '[' {
			loopStack = append(loopStack, i)
		} else if char == ']' {
			if len(loopStack) > 0 {
				start := loopStack[len(loopStack)-1]
				loopStack = loopStack[:len(loopStack)-1]
				loopMap[start] = i
				loopMap[i] = start
			}
		}
	}

	// 执行代码
	for i := 0; i < len(code); i++ {
		switch code[i] {
		case '>':
			ptr = (ptr + 1) % 30000
		case '<':
			ptr = (ptr - 1 + 30000) % 30000
		case '+':
			memory[ptr]++
		case '-':
			memory[ptr]--
		case '.':
			output.WriteByte(memory[ptr])
		case '[':
			if memory[ptr] == 0 {
				if end, ok := loopMap[i]; ok {
					i = end
				}
			}
		case ']':
			if memory[ptr] != 0 {
				if start, ok := loopMap[i]; ok {
					i = start
				}
			}
		}
	}

	return []byte(output.String()), nil
}

// ZIP文件解码器
type ZipDecoder struct{}

func (d *ZipDecoder) Name() string  { return "ZIP" }
func (d *ZipDecoder) Priority() int { return 27 }

func (d *ZipDecoder) CanDecode(data []byte) bool {
	return len(data) > 4 && bytes.HasPrefix(data, []byte{0x50, 0x4B, 0x03, 0x04})
}

func (d *ZipDecoder) Decode(data []byte) ([]byte, error) {
	// 简化版ZIP解码，实际应用中需要专门的ZIP库
	return nil, fmt.Errorf("ZIP解码需要专门的实现")
}

// TAR文件解码器
type TarDecoder struct{}

func (d *TarDecoder) Name() string  { return "TAR" }
func (d *TarDecoder) Priority() int { return 28 }

func (d *TarDecoder) CanDecode(data []byte) bool {
	return len(data) > 512 && (bytes.HasSuffix(data, []byte("ustar")) || bytes.HasSuffix(data, []byte("tar")))
}

func (d *TarDecoder) Decode(data []byte) ([]byte, error) {
	// 简化版TAR解码，实际应用中需要专门的TAR库
	return nil, fmt.Errorf("TAR解码需要专门的实现")
}

// GZIP解码器
type GzipDecoder struct{}

func (d *GzipDecoder) Name() string  { return "GZIP" }
func (d *GzipDecoder) Priority() int { return 29 }

func (d *GzipDecoder) CanDecode(data []byte) bool {
	return len(data) > 2 && bytes.HasPrefix(data, []byte{0x1f, 0x8b})
}

func (d *GzipDecoder) Decode(data []byte) ([]byte, error) {
	// 简化版GZIP解码，实际应用中需要专门的GZIP库
	return nil, fmt.Errorf("GZIP解码需要专门的实现")
}

// 网络协议解码器（HTTP URL参数）
type HttpParamDecoder struct{}

func (d *HttpParamDecoder) Name() string  { return "HTTP-Param" }
func (d *HttpParamDecoder) Priority() int { return 30 }

func (d *HttpParamDecoder) CanDecode(data []byte) bool {
	return bytes.Contains(data, []byte("=")) && (bytes.Contains(data, []byte("&")) || bytes.Contains(data, []byte("?")))
}

func (d *HttpParamDecoder) Decode(data []byte) ([]byte, error) {
	// 解析HTTP参数
	params := strings.Split(string(data), "&")
	var result strings.Builder
	for _, param := range params {
		if strings.Contains(param, "=") {
			parts := strings.SplitN(param, "=", 2)
			if len(parts) == 2 {
				decoded, err := url.QueryUnescape(parts[1])
				if err == nil {
					result.WriteString(decoded)
					result.WriteString(" ")
				}
			}
		}
	}
	return []byte(strings.TrimSpace(result.String())), nil
}

// Base45解码器
type Base45Decoder struct{}

func (d *Base45Decoder) Name() string  { return "Base45" }
func (d *Base45Decoder) Priority() int { return 31 }

func (d *Base45Decoder) CanDecode(data []byte) bool {
	pattern := regexp.MustCompile(`^[0-9A-Z $%*+\-./:]+$`)
	return pattern.Match(data)
}

func (d *Base45Decoder) Decode(data []byte) ([]byte, error) {
	// Base45解码实现
	base45Chars := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
	var result []byte

	// 每3个字符解码为2个字节
	for i := 0; i < len(data); i += 3 {
		if i+2 >= len(data) {
			break
		}

		val := 0
		for j := 0; j < 3; j++ {
			idx := strings.IndexByte(base45Chars, data[i+j])
			if idx == -1 {
				return nil, fmt.Errorf("invalid base45 character")
			}
			val = val*45 + idx
		}

		result = append(result, byte(val>>8))
		result = append(result, byte(val&0xFF))
	}

	return result, nil
}

// Base62解码器
type Base62Decoder struct{}

func (d *Base62Decoder) Name() string  { return "Base62" }
func (d *Base62Decoder) Priority() int { return 32 }

func (d *Base62Decoder) CanDecode(data []byte) bool {
	pattern := regexp.MustCompile(`^[0-9A-Za-z]+$`)
	return pattern.Match(data)
}

func (d *Base62Decoder) Decode(data []byte) ([]byte, error) {
	// Base62解码实现
	base62Chars := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var result []byte

	// 转换为大整数然后转换为字节
	val := 0
	for _, b := range data {
		idx := strings.IndexByte(base62Chars, b)
		if idx == -1 {
			return nil, fmt.Errorf("invalid base62 character")
		}
		val = val*62 + idx
	}

	// 转换为字节数组
	for val > 0 {
		result = append([]byte{byte(val % 256)}, result...)
		val /= 256
	}

	return result, nil
}

// Base92解码器
type Base92Decoder struct{}

func (d *Base92Decoder) Name() string  { return "Base92" }
func (d *Base92Decoder) Priority() int { return 33 }

func (d *Base92Decoder) CanDecode(data []byte) bool {
	pattern := regexp.MustCompile(`^[!-~]+$`)
	return pattern.Match(data)
}

func (d *Base92Decoder) Decode(data []byte) ([]byte, error) {
	// Base92解码实现
	base92Chars := "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
	var result []byte

	val := 0
	for _, b := range data {
		idx := strings.IndexByte(base92Chars, b)
		if idx == -1 {
			return nil, fmt.Errorf("invalid base92 character")
		}
		val = val*92 + idx
	}

	for val > 0 {
		result = append([]byte{byte(val % 256)}, result...)
		val /= 256
	}

	return result, nil
}

// BCD解码器
type BcdDecoder struct{}

func (d *BcdDecoder) Name() string  { return "BCD" }
func (d *BcdDecoder) Priority() int { return 34 }

func (d *BcdDecoder) CanDecode(data []byte) bool {
	pattern := regexp.MustCompile(`^[0-9]+$`)
	return pattern.Match(data)
}

func (d *BcdDecoder) Decode(data []byte) ([]byte, error) {
	var result []byte
	for i := 0; i < len(data); i += 2 {
		if i+1 >= len(data) {
			break
		}
		high := int(data[i] - '0')
		low := int(data[i+1] - '0')
		if high > 9 || low > 9 {
			return nil, fmt.Errorf("invalid BCD digit")
		}
		result = append(result, byte(high*16+low))
	}
	return result, nil
}

// HTML Entity解码器
type HtmlEntityDecoder struct{}

func (d *HtmlEntityDecoder) Name() string  { return "HTML-Entity" }
func (d *HtmlEntityDecoder) Priority() int { return 35 }

func (d *HtmlEntityDecoder) CanDecode(data []byte) bool {
	return bytes.Contains(data, []byte("&")) && bytes.Contains(data, []byte(";"))
}

func (d *HtmlEntityDecoder) Decode(data []byte) ([]byte, error) {
	// 简化的HTML实体解码
	htmlEntities := map[string]string{
		"&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": "\"", "&#39;": "'",
		"&nbsp;": " ", "&copy;": "©", "&reg;": "®", "&trade;": "™",
	}

	result := string(data)
	for entity, char := range htmlEntities {
		result = strings.ReplaceAll(result, entity, char)
	}

	// 处理数字实体 &#123;
	re := regexp.MustCompile(`&#(\d+);`)
	result = re.ReplaceAllStringFunc(result, func(match string) string {
		parts := re.FindStringSubmatch(match)
		if len(parts) == 2 {
			if num, err := strconv.Atoi(parts[1]); err == nil {
				return string(rune(num))
			}
		}
		return match
	})

	return []byte(result), nil
}

// Quoted Printable解码器
type QuotedPrintableDecoder struct{}

func (d *QuotedPrintableDecoder) Name() string  { return "Quoted-Printable" }
func (d *QuotedPrintableDecoder) Priority() int { return 36 }

func (d *QuotedPrintableDecoder) CanDecode(data []byte) bool {
	return bytes.Contains(data, []byte("="))
}

func (d *QuotedPrintableDecoder) Decode(data []byte) ([]byte, error) {
	var result []byte
	for i := 0; i < len(data); i++ {
		if data[i] == '=' {
			if i+2 < len(data) {
				hexStr := string(data[i+1 : i+3])
				if val, err := hex.DecodeString(hexStr); err == nil {
					result = append(result, val...)
					i += 2
				} else {
					result = append(result, data[i])
				}
			} else {
				result = append(result, data[i])
			}
		} else {
			result = append(result, data[i])
		}
	}
	return result, nil
}

// Punycode解码器
type PunycodeDecoder struct{}

func (d *PunycodeDecoder) Name() string  { return "Punycode" }
func (d *PunycodeDecoder) Priority() int { return 37 }

func (d *PunycodeDecoder) CanDecode(data []byte) bool {
	return bytes.Contains(data, []byte("xn--"))
}

func (d *PunycodeDecoder) Decode(data []byte) ([]byte, error) {
	// 简化的Punycode解码
	str := string(data)
	if strings.HasPrefix(str, "xn--") {
		// 这里需要完整的Punycode实现
		return nil, fmt.Errorf("Punycode解码需要完整实现")
	}
	return data, nil
}

// A1Z26解码器
type A1Z26Decoder struct{}

func (d *A1Z26Decoder) Name() string  { return "A1Z26" }
func (d *A1Z26Decoder) Priority() int { return 38 }

func (d *A1Z26Decoder) CanDecode(data []byte) bool {
	pattern := regexp.MustCompile(`^([1-2]?[0-9] ?)+$`)
	return pattern.Match(data)
}

func (d *A1Z26Decoder) Decode(data []byte) ([]byte, error) {
	parts := strings.Fields(string(data))
	var result strings.Builder
	for _, part := range parts {
		if num, err := strconv.Atoi(part); err == nil && num >= 1 && num <= 26 {
			result.WriteByte(byte('a' + num - 1))
		} else {
			result.WriteByte('.')
		}
	}
	return []byte(result.String()), nil
}

// Bacon Cipher解码器
type BaconCipherDecoder struct{}

func (d *BaconCipherDecoder) Name() string  { return "Bacon-Cipher" }
func (d *BaconCipherDecoder) Priority() int { return 39 }

func (d *BaconCipherDecoder) CanDecode(data []byte) bool {
	pattern := regexp.MustCompile(`^[ABab\s]+$`)
	return pattern.Match(data)
}

func (d *BaconCipherDecoder) Decode(data []byte) ([]byte, error) {
	// Bacon密码解码
	baconMap := map[string]string{
		"AAAAA": "A", "AAAAB": "B", "AAABA": "C", "AAABB": "D", "AABAA": "E",
		"AABAB": "F", "AABBA": "G", "AABBB": "H", "ABAAA": "I", "ABAAB": "J",
		"ABABA": "K", "ABABB": "L", "ABBAA": "M", "ABBAB": "N", "ABBBA": "O",
		"ABBBB": "P", "BAAAA": "Q", "BAAAB": "R", "BAABA": "S", "BAABB": "T",
		"BABAA": "U", "BABAB": "V", "BABBA": "W", "BABBB": "X", "BBAAA": "Y",
		"BBAAB": "Z",
	}

	clean := strings.ReplaceAll(strings.ToUpper(string(data)), " ", "")
	var result strings.Builder

	for i := 0; i < len(clean); i += 5 {
		if i+5 <= len(clean) {
			group := clean[i : i+5]
			if char, ok := baconMap[group]; ok {
				result.WriteString(char)
			} else {
				result.WriteString(".")
			}
		}
	}

	return []byte(result.String()), nil
}

// Cetacean Cipher解码器
type CetaceanCipherDecoder struct{}

func (d *CetaceanCipherDecoder) Name() string  { return "Cetacean-Cipher" }
func (d *CetaceanCipherDecoder) Priority() int { return 40 }

func (d *CetaceanCipherDecoder) CanDecode(data []byte) bool {
	pattern := regexp.MustCompile(`^(?:[eE]{16,})(?: [eE]{16,})*$`)
	return pattern.Match(data)
}

func (d *CetaceanCipherDecoder) Decode(data []byte) ([]byte, error) {
	// 海豚密码解码
	var binaryArray []int
	for _, char := range data {
		if char == ' ' {
			binaryArray = append(binaryArray, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0)
		} else {
			if char == 'e' {
				binaryArray = append(binaryArray, 1)
			} else {
				binaryArray = append(binaryArray, 0)
			}
		}
	}

	var result strings.Builder
	for i := 0; i < len(binaryArray); i += 16 {
		if i+16 <= len(binaryArray) {
			var byteStr strings.Builder
			for j := 0; j < 16; j++ {
				if binaryArray[i+j] == 1 {
					byteStr.WriteString("1")
				} else {
					byteStr.WriteString("0")
				}
			}
			if val, err := strconv.ParseUint(byteStr.String(), 2, 16); err == nil {
				result.WriteByte(byte(val))
			}
		}
	}

	return []byte(result.String()), nil
}

// Caret/M-decode解码器
type CaretMdecodeDecoder struct{}

func (d *CaretMdecodeDecoder) Name() string  { return "Caret-M-decode" }
func (d *CaretMdecodeDecoder) Priority() int { return 41 }

func (d *CaretMdecodeDecoder) CanDecode(data []byte) bool {
	return bytes.Contains(data, []byte("^")) || bytes.Contains(data, []byte("M-"))
}

func (d *CaretMdecodeDecoder) Decode(data []byte) ([]byte, error) {
	// Caret/M-decode实现
	var result []byte
	prev := ""

	for i := 0; i < len(data); i++ {
		charCode := data[i]
		curChar := string(data[i])

		if prev == "M-^" {
			if charCode > 63 && charCode <= 95 {
				result = append(result, charCode+64)
			} else if charCode == 63 {
				result = append(result, 255)
			} else {
				result = append(result, 77, 45, 94, charCode)
			}
			prev = ""
		} else if prev == "M-" {
			if curChar == "^" {
				prev = prev + "^"
			} else if charCode >= 32 && charCode <= 126 {
				result = append(result, charCode+128)
				prev = ""
			} else {
				result = append(result, 77, 45, charCode)
				prev = ""
			}
		} else if prev == "M" {
			if curChar == "-" {
				prev = prev + "-"
			} else {
				result = append(result, 77, charCode)
				prev = ""
			}
		} else if prev == "^" {
			if charCode > 63 && charCode <= 126 {
				result = append(result, charCode-64)
			} else if charCode == 63 {
				result = append(result, 127)
			} else {
				result = append(result, 94, charCode)
			}
			prev = ""
		} else {
			if curChar == "M" {
				prev = "M"
			} else if curChar == "^" {
				prev = "^"
			} else {
				result = append(result, charCode)
			}
		}
	}

	return result, nil
}

// RC4解码器
type Rc4Decoder struct{}

func (d *Rc4Decoder) Name() string  { return "RC4" }
func (d *Rc4Decoder) Priority() int { return 42 }

func (d *Rc4Decoder) CanDecode(data []byte) bool {
	return len(data) > 8
}

func (d *Rc4Decoder) Decode(data []byte) ([]byte, error) {
	// RC4解密（需要密钥，这里尝试常见密钥）
	commonKeys := [][]byte{
		[]byte("key"), []byte("secret"), []byte("password"), []byte("admin"),
		[]byte("123456"), []byte("password123"), []byte("admin123"),
	}

	for _, key := range commonKeys {
		result := rc4Decrypt(data, key)
		if isReadableText(result) {
			return result, nil
		}
	}
	return nil, fmt.Errorf("no readable RC4 key found")
}

func rc4Decrypt(data, key []byte) []byte {
	// RC4算法实现
	S := make([]byte, 256)
	for i := 0; i < 256; i++ {
		S[i] = byte(i)
	}

	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(S[i]) + int(key[i%len(key)])) % 256
		S[i], S[j] = S[j], S[i]
	}

	result := make([]byte, len(data))
	i, j := 0, 0
	for k := 0; k < len(data); k++ {
		i = (i + 1) % 256
		j = (j + int(S[i])) % 256
		S[i], S[j] = S[j], S[i]
		t := (int(S[i]) + int(S[j])) % 256
		result[k] = data[k] ^ S[t]
	}

	return result
}

// ChaCha解码器
type ChaChaDecoder struct{}

func (d *ChaChaDecoder) Name() string  { return "ChaCha" }
func (d *ChaChaDecoder) Priority() int { return 43 }

func (d *ChaChaDecoder) CanDecode(data []byte) bool {
	return len(data) > 16
}

func (d *ChaChaDecoder) Decode(data []byte) ([]byte, error) {
	// ChaCha解密（简化版）
	// 实际应用中需要完整的ChaCha实现
	return nil, fmt.Errorf("ChaCha解密需要完整实现")
}

// Salsa20解码器
type Salsa20Decoder struct{}

func (d *Salsa20Decoder) Name() string  { return "Salsa20" }
func (d *Salsa20Decoder) Priority() int { return 44 }

func (d *Salsa20Decoder) CanDecode(data []byte) bool {
	return len(data) > 16
}

func (d *Salsa20Decoder) Decode(data []byte) ([]byte, error) {
	// Salsa20解密（简化版）
	return nil, fmt.Errorf("Salsa20解密需要完整实现")
}

// XXTEA解码器
type XxteaDecoder struct{}

func (d *XxteaDecoder) Name() string  { return "XXTEA" }
func (d *XxteaDecoder) Priority() int { return 45 }

func (d *XxteaDecoder) CanDecode(data []byte) bool {
	return len(data) > 8 && len(data)%4 == 0
}

func (d *XxteaDecoder) Decode(data []byte) ([]byte, error) {
	// XXTEA解密
	key := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}

	// 转换为uint32数组
	if len(data)%4 != 0 {
		return nil, fmt.Errorf("data length must be multiple of 4")
	}

	v := make([]uint32, len(data)/4)
	for i := 0; i < len(v); i++ {
		v[i] = uint32(data[i*4]) | uint32(data[i*4+1])<<8 | uint32(data[i*4+2])<<16 | uint32(data[i*4+3])<<24
	}

	k := make([]uint32, 4)
	for i := 0; i < 4; i++ {
		k[i] = uint32(key[i*4]) | uint32(key[i*4+1])<<8 | uint32(key[i*4+2])<<16 | uint32(key[i*4+3])<<24
	}

	// XXTEA解密
	n := len(v)
	if n < 2 {
		return nil, fmt.Errorf("data too short")
	}

	delta := uint32(0x9E3779B9)
	q := uint32(6 + 52/n)
	sum := q * delta

	for sum != 0 {
		e := (sum >> 2) & 3
		for p := n - 1; p > 0; p-- {
			v[p] -= ((v[p-1]>>5 ^ v[(p+1)%n]<<2) + (v[(p+1)%n]>>3 ^ v[p-1]<<4)) ^ ((sum ^ v[(p+1)%n]) + (k[(p&3)^int(e)] ^ v[p-1]))
		}
		v[0] -= ((v[n-1]>>5 ^ v[1]<<2) + (v[1]>>3 ^ v[n-1]<<4)) ^ ((sum ^ v[1]) + (k[int(e)] ^ v[n-1]))
		sum -= delta
	}

	// 转换回字节
	result := make([]byte, len(v)*4)
	for i, val := range v {
		result[i*4] = byte(val)
		result[i*4+1] = byte(val >> 8)
		result[i*4+2] = byte(val >> 16)
		result[i*4+3] = byte(val >> 24)
	}

	return result, nil
}

// Bifid Cipher解码器
type BifidCipherDecoder struct{}

func (d *BifidCipherDecoder) Name() string  { return "Bifid-Cipher" }
func (d *BifidCipherDecoder) Priority() int { return 46 }

func (d *BifidCipherDecoder) CanDecode(data []byte) bool {
	pattern := regexp.MustCompile(`^[1-5]+$`)
	return pattern.Match(data)
}

func (d *BifidCipherDecoder) Decode(data []byte) ([]byte, error) {
	// Bifid密码解码
	key := "ABCDEFGHIKLMNOPQRSTUVWXYZ"
	keySquare := make([][]byte, 5)
	for i := 0; i < 5; i++ {
		keySquare[i] = make([]byte, 5)
		for j := 0; j < 5; j++ {
			keySquare[i][j] = key[i*5+j]
		}
	}

	// 将数字对转换为坐标
	var coords []int
	for i := 0; i < len(data); i += 2 {
		if i+1 < len(data) {
			row := int(data[i] - '1')
			col := int(data[i+1] - '1')
			if row >= 0 && row < 5 && col >= 0 && col < 5 {
				coords = append(coords, row, col)
			}
		}
	}

	// 重新排列坐标
	var result strings.Builder
	for i := 0; i < len(coords); i += 2 {
		if i+1 < len(coords) {
			row := coords[i]
			col := coords[i+1]
			if row < 5 && col < 5 {
				result.WriteByte(keySquare[row][col])
			}
		}
	}

	return []byte(result.String()), nil
}

// Caesar Box Cipher解码器
type CaesarBoxCipherDecoder struct{}

func (d *CaesarBoxCipherDecoder) Name() string  { return "Caesar-Box-Cipher" }
func (d *CaesarBoxCipherDecoder) Priority() int { return 47 }

func (d *CaesarBoxCipherDecoder) CanDecode(data []byte) bool {
	return len(data) > 4
}

func (d *CaesarBoxCipherDecoder) Decode(data []byte) ([]byte, error) {
	// Caesar Box密码解码
	n := len(data)
	cols := int(math.Sqrt(float64(n)))
	if cols*cols != n {
		cols++
	}

	// 创建矩阵
	matrix := make([][]byte, cols)
	for i := range matrix {
		matrix[i] = make([]byte, cols)
	}

	// 填充矩阵
	idx := 0
	for i := 0; i < cols; i++ {
		for j := 0; j < cols; j++ {
			if idx < len(data) {
				matrix[i][j] = data[idx]
				idx++
			}
		}
	}

	// 按列读取
	var result strings.Builder
	for j := 0; j < cols; j++ {
		for i := 0; i < cols; i++ {
			if matrix[i][j] != 0 {
				result.WriteByte(matrix[i][j])
			}
		}
	}

	return []byte(result.String()), nil
}

// CipherSaber2解码器
type CipherSaber2Decoder struct{}

func (d *CipherSaber2Decoder) Name() string  { return "CipherSaber2" }
func (d *CipherSaber2Decoder) Priority() int { return 48 }

func (d *CipherSaber2Decoder) CanDecode(data []byte) bool {
	return len(data) > 20
}

func (d *CipherSaber2Decoder) Decode(data []byte) ([]byte, error) {
	// CipherSaber2解密（简化版）
	return nil, fmt.Errorf("CipherSaber2解密需要完整实现")
}

// LS47解码器
type Ls47Decoder struct{}

func (d *Ls47Decoder) Name() string  { return "LS47" }
func (d *Ls47Decoder) Priority() int { return 49 }

func (d *Ls47Decoder) CanDecode(data []byte) bool {
	return len(data) > 4
}

func (d *Ls47Decoder) Decode(data []byte) ([]byte, error) {
	// LS47解密（简化版）
	return nil, fmt.Errorf("LS47解密需要完整实现")
}

// MessagePack解码器
type MessagePackDecoder struct{}

func (d *MessagePackDecoder) Name() string  { return "MessagePack" }
func (d *MessagePackDecoder) Priority() int { return 50 }

func (d *MessagePackDecoder) CanDecode(data []byte) bool {
	return len(data) > 1 && (data[0] >= 0x80 && data[0] <= 0x8f || data[0] >= 0x90 && data[0] <= 0x9f || data[0] >= 0xa0 && data[0] <= 0xbf)
}

func (d *MessagePackDecoder) Decode(data []byte) ([]byte, error) {
	// MessagePack解码（简化版）
	return nil, fmt.Errorf("MessagePack解码需要完整实现")
}

// CBOR解码器
type CborDecoder struct{}

func (d *CborDecoder) Name() string  { return "CBOR" }
func (d *CborDecoder) Priority() int { return 51 }

func (d *CborDecoder) CanDecode(data []byte) bool {
	return len(data) > 1 && (data[0] >= 0x00 && data[0] <= 0x17 || data[0] >= 0x20 && data[0] <= 0x37)
}

func (d *CborDecoder) Decode(data []byte) ([]byte, error) {
	// CBOR解码（简化版）
	return nil, fmt.Errorf("CBOR解码需要完整实现")
}

// YAML解码器
type YamlDecoder struct{}

func (d *YamlDecoder) Name() string  { return "YAML" }
func (d *YamlDecoder) Priority() int { return 52 }

func (d *YamlDecoder) CanDecode(data []byte) bool {
	return bytes.HasPrefix(data, []byte("---")) || bytes.Contains(data, []byte(":")) && bytes.Contains(data, []byte("\n"))
}

func (d *YamlDecoder) Decode(data []byte) ([]byte, error) {
	// YAML解码（简化版）
	return nil, fmt.Errorf("YAML解码需要完整实现")
}

// JSON解码器
type JsonDecoder struct{}

func (d *JsonDecoder) Name() string  { return "JSON" }
func (d *JsonDecoder) Priority() int { return 53 }

func (d *JsonDecoder) CanDecode(data []byte) bool {
	return bytes.HasPrefix(data, []byte("{")) || bytes.HasPrefix(data, []byte("["))
}

func (d *JsonDecoder) Decode(data []byte) ([]byte, error) {
	// JSON解码（简化版）
	return nil, fmt.Errorf("JSON解码需要完整实现")
}

// CSV解码器
type CsvDecoder struct{}

func (d *CsvDecoder) Name() string  { return "CSV" }
func (d *CsvDecoder) Priority() int { return 54 }

func (d *CsvDecoder) CanDecode(data []byte) bool {
	return bytes.Contains(data, []byte(",")) && bytes.Contains(data, []byte("\n"))
}

func (d *CsvDecoder) Decode(data []byte) ([]byte, error) {
	// CSV解码（简化版）
	return nil, fmt.Errorf("CSV解码需要完整实现")
}

// Avro解码器
type AvroDecoder struct{}

func (d *AvroDecoder) Name() string  { return "Avro" }
func (d *AvroDecoder) Priority() int { return 55 }

func (d *AvroDecoder) CanDecode(data []byte) bool {
	return len(data) > 4 && bytes.HasPrefix(data, []byte{0x4F, 0x62, 0x6A, 0x01})
}

func (d *AvroDecoder) Decode(data []byte) ([]byte, error) {
	// Avro解码（简化版）
	return nil, fmt.Errorf("Avro解码需要完整实现")
}

// Rison解码器
type RisonDecoder struct{}

func (d *RisonDecoder) Name() string  { return "Rison" }
func (d *RisonDecoder) Priority() int { return 56 }

func (d *RisonDecoder) CanDecode(data []byte) bool {
	return bytes.Contains(data, []byte("(")) && bytes.Contains(data, []byte(")"))
}

func (d *RisonDecoder) Decode(data []byte) ([]byte, error) {
	// Rison解码（简化版）
	return nil, fmt.Errorf("Rison解码需要完整实现")
}

// Modhex解码器
type ModhexDecoder struct{}

func (d *ModhexDecoder) Name() string  { return "Modhex" }
func (d *ModhexDecoder) Priority() int { return 57 }

func (d *ModhexDecoder) CanDecode(data []byte) bool {
	pattern := regexp.MustCompile(`^[cbdefghijklnrtuv]+$`)
	return pattern.Match(data)
}

func (d *ModhexDecoder) Decode(data []byte) ([]byte, error) {
	// Modhex解码
	modhexMap := map[byte]byte{
		'c': 0x0, 'b': 0x1, 'd': 0x2, 'e': 0x3, 'f': 0x4, 'g': 0x5, 'h': 0x6, 'i': 0x7,
		'j': 0x8, 'k': 0x9, 'l': 0xa, 'n': 0xb, 'r': 0xc, 't': 0xd, 'u': 0xe, 'v': 0xf,
	}

	var result []byte
	for i := 0; i < len(data); i += 2 {
		if i+1 < len(data) {
			high, ok1 := modhexMap[data[i]]
			low, ok2 := modhexMap[data[i+1]]
			if ok1 && ok2 {
				result = append(result, (high<<4)|low)
			}
		}
	}

	return result, nil
}

// MIME解码器
type MimeDecoder struct{}

func (d *MimeDecoder) Name() string  { return "MIME" }
func (d *MimeDecoder) Priority() int { return 58 }

func (d *MimeDecoder) CanDecode(data []byte) bool {
	return bytes.Contains(data, []byte("=?UTF-8?B?")) || bytes.Contains(data, []byte("=?UTF-8?Q?"))
}

func (d *MimeDecoder) Decode(data []byte) ([]byte, error) {
	// MIME解码
	str := string(data)

	// 处理Base64编码的MIME
	re := regexp.MustCompile(`=\?UTF-8\?B\?([A-Za-z0-9+/=]+)\?=`)
	str = re.ReplaceAllStringFunc(str, func(match string) string {
		parts := re.FindStringSubmatch(match)
		if len(parts) == 2 {
			if decoded, err := base64.StdEncoding.DecodeString(parts[1]); err == nil {
				return string(decoded)
			}
		}
		return match
	})

	// 处理Quoted-Printable编码的MIME
	re = regexp.MustCompile(`=\?UTF-8\?Q\?([^?]+)\?=`)
	str = re.ReplaceAllStringFunc(str, func(match string) string {
		parts := re.FindStringSubmatch(match)
		if len(parts) == 2 {
			// 简化的QP解码
			qpStr := strings.ReplaceAll(parts[1], "_", " ")
			var result []byte
			for i := 0; i < len(qpStr); i++ {
				if qpStr[i] == '=' && i+2 < len(qpStr) {
					if val, err := hex.DecodeString(qpStr[i+1 : i+3]); err == nil {
						result = append(result, val...)
						i += 2
					} else {
						result = append(result, qpStr[i])
					}
				} else {
					result = append(result, qpStr[i])
				}
			}
			return string(result)
		}
		return match
	})

	return []byte(str), nil
}

// IPv6解码器
type Ipv6Decoder struct{}

func (d *Ipv6Decoder) Name() string  { return "IPv6" }
func (d *Ipv6Decoder) Priority() int { return 59 }

func (d *Ipv6Decoder) CanDecode(data []byte) bool {
	pattern := regexp.MustCompile(`^[0-9a-fA-F:]+$`)
	return pattern.Match(data) && bytes.Contains(data, []byte(":"))
}

func (d *Ipv6Decoder) Decode(data []byte) ([]byte, error) {
	// IPv6解码（简化版）
	return nil, fmt.Errorf("IPv6解码需要完整实现")
}

// X.509解码器
type X509Decoder struct{}

func (d *X509Decoder) Name() string  { return "X.509" }
func (d *X509Decoder) Priority() int { return 60 }

func (d *X509Decoder) CanDecode(data []byte) bool {
	return bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) || bytes.HasPrefix(data, []byte("-----BEGIN PUBLIC KEY-----"))
}

func (d *X509Decoder) Decode(data []byte) ([]byte, error) {
	// X.509解码（简化版）
	return nil, fmt.Errorf("X.509解码需要完整实现")
}

// ASN.1解码器
type Asn1Decoder struct{}

func (d *Asn1Decoder) Name() string  { return "ASN.1" }
func (d *Asn1Decoder) Priority() int { return 61 }

func (d *Asn1Decoder) CanDecode(data []byte) bool {
	return len(data) > 2 && (data[0] == 0x30 || data[0] == 0x02 || data[0] == 0x03)
}

func (d *Asn1Decoder) Decode(data []byte) ([]byte, error) {
	// ASN.1解码（简化版）
	return nil, fmt.Errorf("ASN.1解码需要完整实现")
}

// TLV解码器
type TlvDecoder struct{}

func (d *TlvDecoder) Name() string  { return "TLV" }
func (d *TlvDecoder) Priority() int { return 62 }

func (d *TlvDecoder) CanDecode(data []byte) bool {
	return len(data) > 3
}

func (d *TlvDecoder) Decode(data []byte) ([]byte, error) {
	// TLV解码（简化版）
	return nil, fmt.Errorf("TLV解码需要完整实现")
}

// HTTP Headers解码器
type HttpHeadersDecoder struct{}

func (d *HttpHeadersDecoder) Name() string  { return "HTTP-Headers" }
func (d *HttpHeadersDecoder) Priority() int { return 63 }

func (d *HttpHeadersDecoder) CanDecode(data []byte) bool {
	return bytes.Contains(data, []byte("HTTP/")) || bytes.Contains(data, []byte("GET ")) || bytes.Contains(data, []byte("POST "))
}

func (d *HttpHeadersDecoder) Decode(data []byte) ([]byte, error) {
	// HTTP Headers解码（简化版）
	return nil, fmt.Errorf("HTTP Headers解码需要完整实现")
}

// DNS解码器
type DnsDecoder struct{}

func (d *DnsDecoder) Name() string  { return "DNS" }
func (d *DnsDecoder) Priority() int { return 64 }

func (d *DnsDecoder) CanDecode(data []byte) bool {
	return len(data) > 12 && (data[2] == 0x01 || data[2] == 0x00)
}

func (d *DnsDecoder) Decode(data []byte) ([]byte, error) {
	// DNS解码（简化版）
	return nil, fmt.Errorf("DNS解码需要完整实现")
}

// MAC Address解码器
type MacAddressDecoder struct{}

func (d *MacAddressDecoder) Name() string  { return "MAC-Address" }
func (d *MacAddressDecoder) Priority() int { return 65 }

func (d *MacAddressDecoder) CanDecode(data []byte) bool {
	pattern := regexp.MustCompile(`^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$`)
	return pattern.Match(data)
}

func (d *MacAddressDecoder) Decode(data []byte) ([]byte, error) {
	// MAC地址解码
	clean := strings.ReplaceAll(strings.ReplaceAll(string(data), ":", ""), "-", "")
	if len(clean) != 12 {
		return nil, fmt.Errorf("invalid MAC address length")
	}

	result, err := hex.DecodeString(clean)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// UUID解码器
type UuidDecoder struct{}

func (d *UuidDecoder) Name() string  { return "UUID" }
func (d *UuidDecoder) Priority() int { return 66 }

func (d *UuidDecoder) CanDecode(data []byte) bool {
	pattern := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	return pattern.Match(data)
}

func (d *UuidDecoder) Decode(data []byte) ([]byte, error) {
	// UUID解码
	clean := strings.ReplaceAll(string(data), "-", "")
	if len(clean) != 32 {
		return nil, fmt.Errorf("invalid UUID length")
	}

	result, err := hex.DecodeString(clean)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// 管理器结构
type Manager struct {
	Config        *Config
	Decoders      []Decoder
	Results       []*DecodeResult
	Flags         []string
	Mutex         sync.Mutex
	FlagRegex     *regexp.Regexp
	Processed     map[string]bool // 用于去重
	ProcessedMux  sync.Mutex
	FailedMethods map[string]int // 记录失败的解码方法及其次数
}

func NewManager(config *Config) *Manager {
	manager := &Manager{
		Config:    config,
		Decoders:  make([]Decoder, 0),
		Results:   make([]*DecodeResult, 0),
		Flags:     make([]string, 0),
		Processed: make(map[string]bool),
	}

	// 注册所有解码器
	manager.Decoders = append(manager.Decoders,
		&Base64Decoder{},
		&Base32Decoder{},
		&HexDecoder{},
		&URLDecoder{},
		&BinaryDecoder{},
		&CaesarDecoder{},
		&Rot47Decoder{},
		&ReverseDecoder{},
		&Base58Decoder{},
		&XorDecoder{},
		&MorseDecoder{},
		&RailFenceDecoder{},
		&VigenereDecoder{},
		&AtbashDecoder{},
		&AffineDecoder{},
		&PolybiusDecoder{},
		&UnhexlifyDecoder{},
		&UndecimalDecoder{},
		&UnbinaryDecoder{},
		&Ascii85Decoder{},
		&PhoneticDecoder{},
		&T9Decoder{},
		&DnaDecoder{},
		&RsaDecoder{},
		&WhitespaceDecoder{},
		&BrainfuckDecoder{},
		&ZipDecoder{},
		&TarDecoder{},
		&GzipDecoder{},
		&HttpParamDecoder{},
		&Base45Decoder{},
		&Base62Decoder{},
		&Base92Decoder{},
		&BcdDecoder{},
		&HtmlEntityDecoder{},
		&QuotedPrintableDecoder{},
		&PunycodeDecoder{},
		&A1Z26Decoder{},
		&BaconCipherDecoder{},
		&CetaceanCipherDecoder{},
		&CaretMdecodeDecoder{},
		&Rc4Decoder{},
		&ChaChaDecoder{},
		&Salsa20Decoder{},
		&XxteaDecoder{},
		&BifidCipherDecoder{},
		&CaesarBoxCipherDecoder{},
		&CipherSaber2Decoder{},
		&Ls47Decoder{},
		&MessagePackDecoder{},
		&CborDecoder{},
		&YamlDecoder{},
		&JsonDecoder{},
		&CsvDecoder{},
		&AvroDecoder{},
		&RisonDecoder{},
		&ModhexDecoder{},
		&MimeDecoder{},
		&Ipv6Decoder{},
		&X509Decoder{},
		&Asn1Decoder{},
		&TlvDecoder{},
		&HttpHeadersDecoder{},
		&DnsDecoder{},
		&MacAddressDecoder{},
		&UuidDecoder{},
	)

	// 编译标志正则
	if config.FlagFormat != "" {
		manager.FlagRegex = regexp.MustCompile(config.FlagFormat)
	}

	return manager
}

// 计算数据的哈希值用于去重
func calculateHash(data []byte) string {
	hash := md5.Sum(data)
	return hex.EncodeToString(hash[:])
}

// 过滤字符，只保留字母数字，乱码用点号显示，优化子串显示
// 使用正则表达式过滤字符，只保留字母数字，其他字符用点号显示
func filterAlphanumeric(data []byte) string {
	// 使用正则表达式匹配字母和数字
	alphanumericRegex := regexp.MustCompile(`[a-zA-Z0-9]`)

	// 将字节数组转换为字符串
	strData := string(data)

	// 使用正则表达式替换非字母数字字符为点号
	// 先找到所有字母数字字符的位置
	matches := alphanumericRegex.FindAllStringIndex(strData, -1)

	var result strings.Builder
	lastEnd := 0

	for _, match := range matches {
		start, end := match[0], match[1]

		// 添加字母数字字符
		result.WriteString(strData[start:end])

		// 在字母数字字符之间添加点号（如果有间隔）
		if start > lastEnd {
			result.WriteByte('.')
		}

		lastEnd = end
	}

	// 如果最后一个字母数字字符后面还有内容，添加点号
	if lastEnd < len(strData) {
		result.WriteByte('.')
	}

	// 清理结果，移除开头和结尾的点号
	filtered := strings.Trim(result.String(), ".")

	// 如果结果为空，返回原始数据的十六进制表示
	if filtered == "" {
		// 显示前20个字符的十六进制
		if len(data) > 20 {
			return fmt.Sprintf("hex:%x...", data[:20])
		} else {
			return fmt.Sprintf("hex:%x", data)
		}
	}

	return filtered
}

// 检查是否为可读文本
func isReadableText(data []byte) bool {
	if len(data) < 3 {
		return false
	}

	// 检查是否包含常见英文单词
	text := strings.ToLower(string(data))
	commonWords := []string{"the", "and", "or", "but", "in", "on", "at", "to", "for", "of", "with", "by", "flag", "ctf"}

	wordCount := 0
	for _, word := range commonWords {
		if strings.Contains(text, word) {
			wordCount++
		}
	}

	return wordCount > 0
}

// 自动提取文本字符串
func extractStrings(data []byte) []string {
	var strings []string

	// 提取可打印字符串
	pattern := regexp.MustCompile(`[ -~]{4,}`)
	matches := pattern.FindAll(data, -1)
	for _, match := range matches {
		strings = append(strings, string(match))
	}

	// 提取Base64字符串
	base64Pattern := regexp.MustCompile(`[A-Za-z0-9+/]{8,}={0,2}`)
	base64Matches := base64Pattern.FindAll(data, -1)
	for _, match := range base64Matches {
		strings = append(strings, string(match))
	}

	// 提取十六进制字符串
	hexPattern := regexp.MustCompile(`[0-9a-fA-F]{8,}`)
	hexMatches := hexPattern.FindAll(data, -1)
	for _, match := range hexMatches {
		strings = append(strings, string(match))
	}

	return strings
}

// 创建CTF字典
func createCTFDictionaries() []*Dictionary {
	dicts := []*Dictionary{
		// CTF标志字典
		{
			Name: "CTF_Flags",
			Patterns: []string{
				`FLAG\{[^}]+\}`,
				`flag\{[^}]+\}`,
				`CTF\{[^}]+\}`,
				`ctf\{[^}]+\}`,
				`KEY\{[^}]+\}`,
				`key\{[^}]+\}`,
				`SECRET\{[^}]+\}`,
				`secret\{[^}]+\}`,
			},
			Words: []string{"flag", "ctf", "key", "secret", "password"},
		},

		// 常见英文词汇
		{
			Name:     "Common_Words",
			Patterns: []string{},
			Words: []string{
				"the", "and", "or", "but", "in", "on", "at", "to", "for", "of", "with", "by",
				"hello", "world", "test", "admin", "user", "password", "login", "secret",
				"key", "encrypt", "decrypt", "cipher", "code", "message", "data", "file",
				"system", "network", "security", "hack", "crack", "solve", "find", "get",
				"cyber", "chef", "decode", "encode", "base64", "hex", "binary", "ascii",
				"working", "success", "found", "correct", "right", "true", "false",
			},
		},

		// 编程相关词汇
		{
			Name:     "Programming",
			Patterns: []string{},
			Words: []string{
				"function", "class", "method", "variable", "string", "integer", "boolean",
				"array", "object", "null", "undefined", "true", "false", "if", "else",
				"for", "while", "return", "import", "export", "public", "private",
				"python", "javascript", "java", "c++", "go", "rust", "php", "ruby",
				"html", "css", "sql", "json", "xml", "yaml", "markdown",
			},
		},

		// 网络协议词汇
		{
			Name:     "Network",
			Patterns: []string{},
			Words: []string{
				"http", "https", "ftp", "ssh", "telnet", "dns", "tcp", "udp", "ip",
				"port", "host", "server", "client", "request", "response", "header",
				"cookie", "session", "token", "auth", "login", "logout", "register",
			},
		},

		// 加密相关词汇
		{
			Name:     "Crypto",
			Patterns: []string{},
			Words: []string{
				"aes", "des", "rsa", "md5", "sha1", "sha256", "sha512", "hmac",
				"caesar", "vigenere", "atbash", "affine", "railfence", "polybius",
				"base64", "base32", "base58", "hex", "binary", "xor", "rot13", "rot47",
				"morse", "bacon", "bifid", "xxtea", "rc4", "chacha", "salsa20",
			},
		},

		// 文件格式词汇
		{
			Name:     "FileFormats",
			Patterns: []string{},
			Words: []string{
				"zip", "tar", "gz", "rar", "7z", "pdf", "doc", "docx", "xls", "xlsx",
				"png", "jpg", "jpeg", "gif", "bmp", "svg", "mp3", "mp4", "avi", "mov",
				"txt", "log", "csv", "json", "xml", "yaml", "ini", "cfg", "conf",
			},
		},

		// 系统命令词汇
		{
			Name:     "Commands",
			Patterns: []string{},
			Words: []string{
				"ls", "dir", "cd", "pwd", "cat", "type", "echo", "print", "grep",
				"find", "search", "sort", "uniq", "wc", "head", "tail", "cut",
				"sed", "awk", "tr", "rev", "base64", "hexdump", "xxd", "strings",
			},
		},

		// 特殊模式
		{
			Name: "Special_Patterns",
			Patterns: []string{
				`[A-Z]{2,}`,              // 大写字母序列
				`[a-z]{2,}`,              // 小写字母序列
				`[0-9]{3,}`,              // 数字序列
				`[A-Za-z0-9]{8,}`,        // 字母数字混合
				`[!@#$%^&*()]{3,}`,       // 特殊字符序列
				`[A-Z][a-z]+[A-Z][a-z]+`, // 驼峰命名
				`[a-z]+_[a-z]+`,          // 下划线命名
				`[a-z]+-[a-z]+`,          // 连字符命名
			},
			Words: []string{},
		},
	}

	// 编译正则表达式
	for _, dict := range dicts {
		if len(dict.Patterns) > 0 {
			dict.Regex = regexp.MustCompile(strings.Join(dict.Patterns, "|"))
		}
	}

	return dicts
}

// 字典匹配函数
func matchDictionary(data []byte, dicts []*Dictionary) []DictMatch {
	var matches []DictMatch
	text := strings.ToLower(string(data))

	for _, dict := range dicts {
		// 检查正则模式
		if dict.Regex != nil {
			patternMatches := dict.Regex.FindAllString(string(data), -1)
			for _, match := range patternMatches {
				matches = append(matches, DictMatch{
					Dictionary: dict.Name,
					Pattern:    match,
					Score:      10,
					Type:       "regex",
				})
			}
		}

		// 检查词汇匹配
		for _, word := range dict.Words {
			wordLower := strings.ToLower(word)
			if strings.Contains(text, wordLower) {
				score := 5
				// 检查原始文本中是否有精确匹配（保持大小写）
				if strings.Contains(string(data), word) { // 精确匹配
					score = 8
				}
				matches = append(matches, DictMatch{
					Dictionary: dict.Name,
					Pattern:    word,
					Score:      score,
					Type:       "word",
				})
			}
		}
	}

	return matches
}

// 计算置信度
func calculateConfidence(matches []DictMatch, data []byte) float64 {
	if len(matches) == 0 {
		return 0.0
	}

	// 计算匹配质量
	totalScore := 0
	exactMatches := 0
	regexMatches := 0

	for _, match := range matches {
		totalScore += match.Score
		if match.Type == "word" && match.Score == 8 {
			exactMatches++
		} else if match.Type == "regex" {
			regexMatches++
		}
	}

	// 基础置信度：基于匹配质量而不是数据长度
	baseConfidence := 0.0

	// 如果有精确匹配，给予高置信度
	if exactMatches > 0 {
		baseConfidence = 0.8 + float64(exactMatches)*0.1
	} else if regexMatches > 0 {
		baseConfidence = 0.6 + float64(regexMatches)*0.1
	} else {
		// 基于总分数计算，但不再除以数据长度
		baseConfidence = float64(totalScore) * 0.1
	}

	if baseConfidence > 1.0 {
		baseConfidence = 1.0
	}

	// 检查过滤后的结果是否包含点号
	filtered := filterAlphanumeric(data)
	dotCount := strings.Count(filtered, ".")

	// 如果没有点号（纯字母数字），给予额外奖励
	if dotCount == 0 && len(filtered) > 0 {
		// 给纯字母数字结果额外20%的置信度奖励
		baseConfidence += 0.2
		if baseConfidence > 1.0 {
			baseConfidence = 1.0
		}
	} else if dotCount > 0 {
		// 有点号的结果，根据点号比例降低置信度
		dotRatio := float64(dotCount) / float64(len(filtered))
		baseConfidence *= (1.0 - dotRatio*0.2) // 最多降低20%
	}

	// 特殊处理：明显的明文应该给100%置信度
	text := strings.ToLower(string(data))
	if strings.Contains(text, "hello") && strings.Contains(text, "world") {
		baseConfidence = 1.0
	}
	if strings.Contains(text, "flag{") || strings.Contains(text, "flag}") {
		baseConfidence = 1.0
	}
	if strings.Contains(text, "test") && strings.Contains(text, "message") {
		baseConfidence = 1.0
	}

	return baseConfidence
}

// 新增：全局answer数组
var answerList []DecodeResult
var answerMux sync.Mutex

// 修改处理目标函数
// 根据失败方法调整解码器优先级
func (m *Manager) adjustDecoderPriority() {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()

	// 如果某些方法失败次数过多，降低其优先级
	for methodName, failCount := range m.FailedMethods {
		if failCount > 5 { // 失败超过5次
			// 找到对应的解码器并降低优先级
			for i, decoder := range m.Decoders {
				if decoder.Name() == methodName {
					// 将失败次数多的解码器移到后面
					if i < len(m.Decoders)-1 {
						m.Decoders[i], m.Decoders[i+1] = m.Decoders[i+1], m.Decoders[i]
					}
					break
				}
			}
		}
	}
}

func (m *Manager) ProcessTarget(target *Target, round int) {
	// 检查递归深度
	if round > m.Config.MaxRounds || target.Depth > m.Config.MaxDepth {
		return
	}

	// 检查是否已处理过
	m.ProcessedMux.Lock()
	if m.Processed[target.Hash] {
		m.ProcessedMux.Unlock()
		return
	}
	m.Processed[target.Hash] = true
	m.ProcessedMux.Unlock()

	// 自动提取字符串
	if m.Config.AutoExtract {
		strings := extractStrings(target.Data)
		for _, str := range strings {
			if len(str) >= m.Config.MinData {
				newTarget := &Target{
					Data:    []byte(str),
					Parent:  target,
					Depth:   target.Depth + 1,
					Config:  m.Config,
					Manager: m,
					Hash:    calculateHash([]byte(str)),
				}
				m.ProcessTarget(newTarget, round)
			}
		}
	}

	// 尝试所有解码器
	for _, decoder := range m.Decoders {
		if decoder.CanDecode(target.Data) {
			decoded, err := decoder.Decode(target.Data)
			if err != nil {
				continue
			}

			// 检查解码后长度是否合理
			originalLen := len(target.Data)
			decodedLen := len(decoded)

			// 如果解码后变长，果断抛弃这个结果，但继续尝试其他解码方法
			if decodedLen > originalLen {
				// 记录这个解码方法失败次数
				m.Mutex.Lock()
				if m.FailedMethods == nil {
					m.FailedMethods = make(map[string]int)
				}
				m.FailedMethods[decoder.Name()]++
				m.Mutex.Unlock()
				continue // 跳过这个结果，继续尝试下一个解码器
			}

			// 处理解码后长度合理的结果
			if decodedLen >= m.Config.MinData {
				// 字典匹配
				dicts := createCTFDictionaries()
				dictMatches := matchDictionary(decoded, dicts)
				confidence := calculateConfidence(dictMatches, decoded)

				// 创建解码结果
				result := &DecodeResult{
					Method:      decoder.Name(),
					Original:    target.Data,
					Decoded:     decoded,
					Filtered:    filterAlphanumeric(decoded),
					Round:       round,
					Parent:      target,
					DictMatches: dictMatches,
					Confidence:  confidence,
				}

				m.Mutex.Lock()
				m.Results = append(m.Results, result)
				resultIndex := len(m.Results)
				m.Mutex.Unlock()

				// 新增：只要有字典匹配且置信度>0.1，加入answerList（降低阈值）
				if confidence > 0.1 && len(dictMatches) > 0 {
					answerMux.Lock()
					answerList = append(answerList, *result)
					currentAnswerCount := len(answerList)
					answerMux.Unlock()

					// 实时显示answer收集状态
					confidencePercent := int(confidence * 100)
					fmt.Printf("    📥 Collected answers: %d (Confidence: %d%%, Dictionary: %s)\n",
						currentAnswerCount, confidencePercent, dictMatches[0].Dictionary)
				}

				// 检查过滤后的结果是否包含点号
				dotCount := strings.Count(result.Filtered, ".")

				// 只显示没有点号的结果
				if dotCount == 0 && len(result.Filtered) > 0 {
					fmt.Printf("[%d] 🔓 [%s] %s", resultIndex, decoder.Name(), result.Filtered)

					// 显示置信度和字典匹配
					if confidence > 0.1 {
						confidencePercent := int(confidence * 100)
						fmt.Printf(" (Confidence: %d%%)", confidencePercent)
					}
					if len(dictMatches) > 0 {
						fmt.Printf(" [Dictionary: %s]", dictMatches[0].Dictionary)
					}
					fmt.Println()

					// 检查是否包含标志
					if m.FlagRegex != nil {
						matches := m.FlagRegex.FindAll(decoded, -1)
						for _, match := range matches {
							flag := string(match)
							if !contains(m.Flags, flag) {
								m.Flags = append(m.Flags, flag)
								fmt.Printf("🎌 发现标志: %s\n", flag)
							}
						}
					}

					// 检查是否为可读文本
					if isReadableText(decoded) {
						fmt.Printf("✅ 发现明文: %s\n", result.Filtered)
					} else {
						// 只递归置信度大于0.7的结果
						if confidence > 0.7 {
							newTarget := &Target{
								Data:    decoded,
								Parent:  target,
								Depth:   target.Depth + 1,
								Config:  m.Config,
								Manager: m,
								Hash:    calculateHash(decoded),
							}
							m.ProcessTarget(newTarget, round+1)
						}
					}
				} else {
					// 有点号的结果，仍然进行字典匹配和收集，但不显示，也不继续递归
					if confidence > 0.1 && len(dictMatches) > 0 {
						answerMux.Lock()
						answerList = append(answerList, *result)
						answerMux.Unlock()
					}

					// 检查是否包含标志
					if m.FlagRegex != nil {
						matches := m.FlagRegex.FindAll(decoded, -1)
						for _, match := range matches {
							flag := string(match)
							if !contains(m.Flags, flag) {
								m.Flags = append(m.Flags, flag)
								fmt.Printf("🎌 发现标志: %s\n", flag)
							}
						}
					}
				}
			}
		}
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func main() {
	args := os.Args[1:]
	if len(args) < 1 {
		fmt.Println("🔪 SUMURAI - CTF Automated Solver")
		fmt.Println("Usage: sumurai.exe <target_file> [rounds]")
		fmt.Println("Example: sumurai.exe test.txt 3")
		return
	}

	// 解析参数
	targetFile := args[0]
	maxRounds := 3 // 默认3轮
	if len(args) > 1 {
		if rounds, err := strconv.Atoi(args[1]); err == nil {
			maxRounds = rounds
		}
	}

	// 创建配置
	config := &Config{
		MaxRounds:   maxRounds,
		Threads:     runtime.NumCPU(),
		OutDir:      "./results",
		MinData:     4,
		FlagFormat:  `FLAG\{.*?\}`,
		AutoExtract: true,
		MaxDepth:    10, // 限制递归深度
	}

	// 创建管理器
	manager := NewManager(config)

	// 读取目标文件
	data, err := os.ReadFile(targetFile)
	if err != nil {
		fmt.Printf("❌ Failed to read file: %v\n", err)
		return
	}

	fmt.Printf("🎯 Target: %s (Max rounds: %d)\n", targetFile, maxRounds)
	fmt.Printf("🚀 Start cross decoding...\n")

	// 每轮结束后显示失败方法统计
	defer func() {
		if len(manager.FailedMethods) > 0 {
			fmt.Printf("\n📊 Failed Method Statistics:\n")
			for method, count := range manager.FailedMethods {
				fmt.Printf("   ❌ %s: %d times (decoded result longer)\n", method, count)
			}
		}
	}()

	// 创建根目标
	rootTarget := &Target{
		Data:    data,
		Parent:  nil,
		Depth:   0,
		Config:  config,
		Manager: manager,
		Hash:    calculateHash(data),
	}

	// 开始处理
	manager.ProcessTarget(rootTarget, 1)

	// 显示结果摘要
	fmt.Printf("\n📊 Result Summary:\n")
	fmt.Printf("   Decoding Results: %d\n", len(manager.Results))
	fmt.Printf("   Flags Found: %d\n", len(manager.Flags))

	if len(manager.Flags) > 0 {
		fmt.Printf("\n🎌 Flags Found:\n")
		for i, flag := range manager.Flags {
			fmt.Printf("   [%d] %s\n", i+1, flag)
		}
	}

	// 新增：输出answerList - 堆叠式显示
	fmt.Printf("\n💡 High Confidence Dictionary Decoding Answers (Stacked):\n")
	if len(answerList) == 0 {
		fmt.Println("   No high confidence dictionary match result")
	} else {
		// 按置信度排序
		type AnswerWithConfidence struct {
			Answer     DecodeResult
			Confidence float64
		}
		var sortedAnswers []AnswerWithConfidence
		for _, ans := range answerList {
			sortedAnswers = append(sortedAnswers, AnswerWithConfidence{
				Answer:     ans,
				Confidence: ans.Confidence,
			})
		}

		// 按置信度降序排序
		for i := 0; i < len(sortedAnswers)-1; i++ {
			for j := i + 1; j < len(sortedAnswers); j++ {
				if sortedAnswers[i].Confidence < sortedAnswers[j].Confidence {
					sortedAnswers[i], sortedAnswers[j] = sortedAnswers[j], sortedAnswers[i]
				}
			}
		}

		for i, item := range sortedAnswers {
			ans := item.Answer
			confidencePercent := int(ans.Confidence * 100)
			fmt.Printf("   [%d] [%s] %s (Confidence: %d%%)\n", i+1, ans.Method, ans.Filtered, confidencePercent)
			if len(ans.DictMatches) > 0 {
				fmt.Printf("        📚 Dictionary: ")
				dictMap := make(map[string][]string)
				for _, match := range ans.DictMatches {
					dictMap[match.Dictionary] = append(dictMap[match.Dictionary], match.Pattern)
				}
				for dict, patterns := range dictMap {
					fmt.Printf("%s(%s) ", dict, strings.Join(patterns, ","))
				}
				fmt.Println()
			}
			fmt.Printf("        Plaintext: %s\n", ans.Filtered)
		}
	}

	// 字典分析
	fmt.Printf("\n🔍 Dictionary Analysis Result:\n")

	// 按置信度排序结果
	type ResultWithConfidence struct {
		Result     *DecodeResult
		Confidence float64
	}

	var sortedResults []ResultWithConfidence
	for _, result := range manager.Results {
		sortedResults = append(sortedResults, ResultWithConfidence{
			Result:     result,
			Confidence: result.Confidence,
		})
	}

	// 按置信度降序排序
	for i := 0; i < len(sortedResults)-1; i++ {
		for j := i + 1; j < len(sortedResults); j++ {
			if sortedResults[i].Confidence < sortedResults[j].Confidence {
				sortedResults[i], sortedResults[j] = sortedResults[j], sortedResults[i]
			}
		}
	}

	// 显示高置信度结果
	fmt.Printf("\n🏆 High Confidence Decoding Results (Confidence > 0.3):\n")
	highConfidenceCount := 0
	for _, item := range sortedResults {
		if item.Confidence > 0.3 {
			highConfidenceCount++
			confidencePercent := int(item.Confidence * 100)
			fmt.Printf("   [%d%%] %s -> %s\n",
				confidencePercent,
				item.Result.Method,
				item.Result.Filtered)

			// 显示字典匹配详情
			if len(item.Result.DictMatches) > 0 {
				fmt.Printf("        📚 Dictionary Match: ")
				dicts := make(map[string][]string)
				for _, match := range item.Result.DictMatches {
					dicts[match.Dictionary] = append(dicts[match.Dictionary], match.Pattern)
				}
				for dict, patterns := range dicts {
					fmt.Printf("%s(%s) ", dict, strings.Join(patterns, ","))
				}
				fmt.Println()
			}
		}
	}

	if highConfidenceCount == 0 {
		fmt.Printf("   No high confidence result\n")
	}

	// 显示解码方法统计
	fmt.Printf("\n📈 Decoder Usage Statistics:\n")
	methodStats := make(map[string]int)
	for _, result := range manager.Results {
		methodStats[result.Method]++
	}

	// 按使用次数排序
	type MethodStat struct {
		Name  string
		Count int
	}
	var methodList []MethodStat
	for method, count := range methodStats {
		methodList = append(methodList, MethodStat{method, count})
	}

	for i := 0; i < len(methodList)-1; i++ {
		for j := i + 1; j < len(methodList); j++ {
			if methodList[i].Count < methodList[j].Count {
				methodList[i], methodList[j] = methodList[j], methodList[i]
			}
		}
	}

	for _, stat := range methodList {
		fmt.Printf("   %s: %d times\n", stat.Name, stat.Count)
	}

	// 显示字典匹配统计
	fmt.Printf("\n📚 Dictionary Match Statistics:\n")
	dictStats := make(map[string]int)
	for _, result := range manager.Results {
		for _, match := range result.DictMatches {
			dictStats[match.Dictionary]++
		}
	}

	if len(dictStats) > 0 {
		for dict, count := range dictStats {
			fmt.Printf("   %s: %d matches\n", dict, count)
		}
	} else {
		fmt.Printf("   No dictionary match\n")
	}

	fmt.Printf("\n🔄 Decode Chain:\n")
	for i, result := range manager.Results {
		fmt.Printf("   [%d] %s -> %s", i+1, result.Method, result.Filtered)
		if result.Confidence > 0.1 {
			confidencePercent := int(result.Confidence * 100)
			fmt.Printf(" (%d%%)", confidencePercent)
		}
		fmt.Println()
	}

	fmt.Println("✅ Done!")

	// 最终答案总结
	fmt.Printf("\n🎯 Final Answer Summary:\n")
	if len(answerList) == 0 {
		fmt.Println("   No valid answer found")
	} else {
		fmt.Printf("   %d high confidence answers found:\n", len(answerList))

		// 按置信度排序
		type FinalAnswer struct {
			Method      string
			Plaintext   string
			Confidence  float64
			DictTypes   []string
			Round       int
			DecodeChain []string // 新增：解码链
		}

		var finalAnswers []FinalAnswer
		for _, ans := range answerList {
			dictTypes := make([]string, 0)
			for _, match := range ans.DictMatches {
				dictTypes = append(dictTypes, match.Dictionary)
			}

			// 构建解码链（简化版本，只显示当前解码方法）
			decodeChain := []string{ans.Method}

			finalAnswers = append(finalAnswers, FinalAnswer{
				Method:      ans.Method,
				Plaintext:   ans.Filtered,
				Confidence:  ans.Confidence,
				DictTypes:   dictTypes,
				Round:       ans.Round,
				DecodeChain: decodeChain,
			})
		}

		// 过滤掉有点号的结果，只保留纯字母数字的结果
		var cleanAnswers []FinalAnswer
		for _, ans := range finalAnswers {
			if strings.Count(ans.Plaintext, ".") == 0 && len(ans.Plaintext) > 0 {
				cleanAnswers = append(cleanAnswers, ans)
			}
		}

		// 按置信度降序排序
		for i := 0; i < len(cleanAnswers)-1; i++ {
			for j := i + 1; j < len(cleanAnswers); j++ {
				if cleanAnswers[i].Confidence < cleanAnswers[j].Confidence {
					cleanAnswers[i], cleanAnswers[j] = cleanAnswers[j], cleanAnswers[i]
				}
			}
		}

		// 显示最终答案（只显示没有点号的结果）
		if len(cleanAnswers) > 0 {
			fmt.Printf("   %d pure alphanumeric results found:\n", len(cleanAnswers))
			for i, ans := range cleanAnswers {
				confidencePercent := int(ans.Confidence * 100)
				fmt.Printf("   [%d] %s (Confidence: %d%%)\n", i+1, ans.Method, confidencePercent)
				fmt.Printf("       Plaintext: %s\n", ans.Plaintext)
				fmt.Printf("       Dictionary: %s\n", strings.Join(ans.DictTypes, ", "))
				fmt.Printf("       Round: %d\n", ans.Round)
				fmt.Println()
			}
		} else {
			fmt.Printf("   No pure alphanumeric result found\n")
		}

		// 推荐多个最佳答案（不再只显示没有点号的结果，去除重复明文）
		if len(finalAnswers) > 0 {
			// 新增：优先可读性高的明文，再按置信度排序
			type RankedAnswer struct {
				FinalAnswer
				Readability int
			}
			var rankedAnswers []RankedAnswer
			for _, ans := range finalAnswers {
				readScore := plaintextReadabilityScore(ans.Plaintext)
				rankedAnswers = append(rankedAnswers, RankedAnswer{ans, readScore})
			}
			// 排序：先按Readability降序，再按置信度降序
			for i := 0; i < len(rankedAnswers)-1; i++ {
				for j := i + 1; j < len(rankedAnswers); j++ {
					if rankedAnswers[i].Readability < rankedAnswers[j].Readability ||
						(rankedAnswers[i].Readability == rankedAnswers[j].Readability && rankedAnswers[i].Confidence < rankedAnswers[j].Confidence) {
						rankedAnswers[i], rankedAnswers[j] = rankedAnswers[j], rankedAnswers[i]
					}
				}
			}
			fmt.Printf("\n🏆 Top Recommendations (Top 5):\n")
			seenPlaintext := make(map[string]bool)
			topCount := 0
			maxTopCount := 5
			for _, ans := range rankedAnswers {
				if topCount >= maxTopCount {
					break
				}
				if !seenPlaintext[ans.Plaintext] && len(ans.Plaintext) > 0 && ans.Plaintext != strings.Repeat(".", len(ans.Plaintext)) {
					seenPlaintext[ans.Plaintext] = true
					topCount++
					confidencePercent := int(ans.Confidence * 100)
					fmt.Printf("   [%d] %s (Confidence: %d%%)\n", topCount, ans.Method, confidencePercent)
					fmt.Printf("       Plaintext: %s\n", ans.Plaintext)
					fmt.Printf("       Decode Chain: %s\n", strings.Join(ans.DecodeChain, " -> "))
					// 限制字典显示长度，最多显示前5个
					dictDisplay := ans.DictTypes
					if len(dictDisplay) > 5 {
						dictDisplay = dictDisplay[:5]
						dictDisplay = append(dictDisplay, "...")
					}
					fmt.Printf("       Dictionary: %s\n", strings.Join(dictDisplay, ", "))
					fmt.Printf("       Round: %d\n", ans.Round)
					fmt.Println()
				}
			}

			// 显示所有90%以上置信度的结果（去除重复明文）
			fmt.Printf("🥇 Best Recommendations (Confidence >= 90%%):\n")
			seenPlaintext2 := make(map[string]bool)
			var highConfidenceResults []FinalAnswer

			// 先收集所有90%以上的结果
			for _, ans := range finalAnswers {
				confidencePercent := int(ans.Confidence * 100)
				if confidencePercent >= 90 {
					highConfidenceResults = append(highConfidenceResults, ans)
				}
			}

			// 去重并显示
			for i, ans := range highConfidenceResults {
				if !seenPlaintext2[ans.Plaintext] {
					seenPlaintext2[ans.Plaintext] = true
					confidencePercent := int(ans.Confidence * 100)
					fmt.Printf("   [%d] %s (Confidence: %d%%)\n", i+1, ans.Method, confidencePercent)
					fmt.Printf("       Plaintext: %s\n", ans.Plaintext)
					fmt.Printf("       Decode Chain: %s\n", strings.Join(ans.DecodeChain, " -> "))
					// 限制字典显示长度，最多显示前5个
					dictDisplay := ans.DictTypes
					if len(dictDisplay) > 5 {
						dictDisplay = dictDisplay[:5]
						dictDisplay = append(dictDisplay, "...")
					}
					fmt.Printf("       Dictionary: %s\n", strings.Join(dictDisplay, ", "))
					fmt.Printf("       Round: %d\n", ans.Round)
					fmt.Println()
				}
			}

			uniqueCount := len(seenPlaintext2)
			if uniqueCount == 0 {
				fmt.Printf("   No result with confidence >= 90%% found\n")
			} else {
				fmt.Printf("   %d unique results with confidence >= 90%% found\n", uniqueCount)
			}
		} else {
			fmt.Printf("\n🏆 Top Recommendations:\n")
			fmt.Printf("   No pure alphanumeric result found\n")
		}
	}
}

// 判断明文可读性分数（使用正则表达式进行字典比对，不区分大小写）
func plaintextReadabilityScore(s string) int {
	// 长度优先，长度越长分数越高
	lengthScore := len(s) * 50

	// 使用正则表达式进行字典比对，不区分大小写

	// Compile regex (case-insensitive)
	flagRegex := regexp.MustCompile(`(?i)flag\{.*?\}`)
	helloWorldRegex := regexp.MustCompile(`(?i)hello.*world|world.*hello`)
	testMessageRegex := regexp.MustCompile(`(?i)test.*message|message.*test`)

	// Special patterns
	if flagRegex.MatchString(s) {
		return lengthScore + 1000 // flag highest priority
	}
	if helloWorldRegex.MatchString(s) {
		return lengthScore + 900
	}
	if testMessageRegex.MatchString(s) {
		return lengthScore + 800
	}

	// Base64 plaintext special symbols (regex)
	base64SpecialRegex := regexp.MustCompile(`(?i)[ =+/\-_!@#$%^&*()]`)
	if base64SpecialRegex.MatchString(s) {
		return lengthScore + 700
	}

	// Count English words (regex)
	words := []string{"the", "and", "for", "you", "that", "with", "have", "this", "from", "are", "not", "but", "all", "any", "can", "had", "her", "was", "one", "our", "out", "day", "get", "has", "him", "his", "how", "man", "new", "now", "old", "see", "two", "way", "who", "boy", "did", "its", "let", "put", "say", "she", "too", "use"}
	count := 0
	for _, word := range words {
		wordRegex := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(word) + `\b`)
		if wordRegex.MatchString(s) {
			count++
		}
	}
	return lengthScore + count*10
}
