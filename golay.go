package golay

/* This is reimplementation of wireshark's extended Golay (24,12,8) encoder/decoder.
 * For more information, see https://github.com/boundary/wireshark/blob/master/epan/golay.c
 */

import "errors"

var (
	encodeMatrix = [12]uint16{
		0xC75,
		0x49F,
		0xD4B,
		0x6E3,
		0x9B3,
		0xB66,
		0xECC,
		0x1ED,
		0x3DA,
		0x7B4,
		0xB1D,
		0xE3A,
	}

	decodeMatrix = [12]uint16{
		0x49F,
		0x93E,
		0x6E3,
		0xDC6,
		0xF13,
		0xAB9,
		0x1ED,
		0x3DA,
		0x7B4,
		0xF68,
		0xA4F,
		0xC75,
	}
)

/* weight12 compute the Hamming weight of a 12-bit integer */
func weight12(vector uint16) (w uint) {
	for i := 0; i < 12; i++ {
		if (vector & (1 << i)) > 0 {
			w++
		}
	}
	return
}

func golayCoding(w uint16) (out uint16) {
	for i := 0; i < 12; i++ {
		if (w & (1 << i)) > 0 {
			out ^= encodeMatrix[i]
		}
	}
	return
}

func EncodeWord(payload uint16) uint32 {
	return uint32(payload) | (uint32(golayCoding(payload)) << 12)
}

func golayDecoding(w uint16) (out uint16) {
	for i := 0; i < 12; i++ {
		if (w & (1 << i)) > 0 {
			out ^= decodeMatrix[i]
		}
	}
	return
}

func golayErrors(codeword uint32) int32 {
	receivedparity := uint16(codeword >> 12)
	receiveddata := uint16(codeword & 0xfff)
	syndrome := receivedparity ^ golayCoding(receiveddata)
	w := weight12(syndrome)

	if w <= 3 {
		return int32(syndrome) << 12
	}

	for i := 0; i < 12; i++ {
		errorbit := uint32(1 << i)
		codingerror := encodeMatrix[i]
		if weight12(syndrome^codingerror) <= 2 {
			return int32((uint32(syndrome^codingerror) << 12) | errorbit)
		}
	}

	invsyndrome := golayDecoding(syndrome)
	w = weight12(invsyndrome)
	if w <= 3 {
		return int32(invsyndrome)
	}

	for i := 0; i < 12; i++ {
		errorbit := uint32(1 << i)
		codingerror := decodeMatrix[i]
		if weight12(invsyndrome^codingerror) <= 2 {
			errorword := uint32(invsyndrome^codingerror) | (uint32(errorbit) << 12)
			return int32(errorword)
		}
	}

	return -1
}

func DecodeWord(word uint32) (uint16, error) {
	data := uint16(word & 0xfff)
	errorbits := golayErrors(word)

	if errorbits == -1 {
		return 0, errors.New("4 errors are detected as uncorrectable")
	}
	dataerrors := uint16(errorbits & 0xfff)
	return data ^ dataerrors, nil
}
