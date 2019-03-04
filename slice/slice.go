package slice

func SafeStringCut(s string, length int) string {
	if len(s) < length {
		return s
	}
	return s[:length]
}
