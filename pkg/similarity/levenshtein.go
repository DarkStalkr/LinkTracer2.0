package similarity

func LevenshteinDistance(s1, s2 string) float64 {
    // Implementation of Levenshtein distance algorithm
    // Returns a normalized similarity score between 0 and 1
    // where 1 means identical strings
    d := make([][]int, len(s1)+1)
    for i := range d {
        d[i] = make([]int, len(s2)+1)
    }

    for i := range d {
        d[i][0] = i
    }
    for j := range d[0] {
        d[0][j] = j
    }

    for j := 1; j <= len(s2); j++ {
        for i := 1; i <= len(s1); i++ {
            if s1[i-1] == s2[j-1] {
                d[i][j] = d[i-1][j-1]
            } else {
                min := d[i-1][j]
                if d[i][j-1] < min {
                    min = d[i][j-1]
                }
                if d[i-1][j-1] < min {
                    min = d[i-1][j-1]
                }
                d[i][j] = min + 1
            }
        }
    }

    maxLen := float64(len(s1))
    if len(s2) > len(s1) {
        maxLen = float64(len(s2))
    }

    return 1 - float64(d[len(s1)][len(s2)])/maxLen
}
